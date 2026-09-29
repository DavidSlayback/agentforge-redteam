"""The seed-case runner: the live execute -> judge -> record loop (S3).

For each case it resolves the target in the registry, plays the turns through the Executor
(so the authorization gate applies), builds a deterministic Observation from the final
response, asks the Judge for a Verdict, and records the Attempt, Verdict, and an ordered
agent-action into the store. It never reaches a target itself — only through the Executor.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit

from redteam import findings, regression
from redteam.agents.judge.judge import Judge, Verdict, VerdictOutcome
from redteam.errors import AuthorizationDenied, TargetUnreachable
from redteam.evals.case import OracleConfig, SeedCase
from redteam.executor.executor import Executor
from redteam.executor.authorization import AuthorizationRegistry
from redteam.oracles.base import Observation


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


_BODY_CAP = 8000   # per-field character cap; synthetic data, but keep the store from bloating


def _cap(text: str | None, limit: int = _BODY_CAP) -> str | None:
    if text is None or len(text) <= limit:
        return text
    return text[:limit] + f"...[+{len(text) - limit} chars]"


def _redact_request(body: object) -> object:
    """A request body, made safe to store: a base64 upload becomes a size marker (not the
    payload bytes) and long string fields are capped. Synthetic data only, so this is about
    store size and readability, not PHI."""
    if not isinstance(body, dict):
        return body
    out: dict = {}
    for key, value in body.items():
        if key == "content_base64" and isinstance(value, str):
            out[key] = f"<base64 {len(value)} chars>"
        elif isinstance(value, str):
            out[key] = _cap(value, 2000)
        else:
            out[key] = value
    return out


def record_exchange(ordinal: int, route: str, method: str, request_body: object, record) -> dict:
    """Build one rich exchange row (request + response) for the evidence store. Callers append
    these; `finalize` persists the full list to `evidence` and a lean projection to attempts."""
    return {
        "ordinal": ordinal,
        "route": route,
        "method": method,
        "request": _redact_request(request_body),
        "status_code": record.status_code,
        "response": _cap(record.text),
        "latency_ms": record.latency_ms,
    }


def build_observation(record, oracle: OracleConfig, provider_events: tuple[str, ...] = ()) -> Observation:
    return Observation(
        response_text=record.text,
        status_code=record.status_code,
        latency_ms=record.latency_ms,
        latency_budget_ms=oracle.latency_budget_ms,
        injection_marker=oracle.marker,
        foreign_canaries=frozenset(oracle.foreign_canaries),
        provider_events=provider_events,
    )


@dataclass
class RunResult:
    attempt_id: str
    verdict: Verdict


def run_case(
    case: SeedCase,
    registry: AuthorizationRegistry,
    executor: Executor,
    judge: Judge,
    store,
    minter=None,
    target_sha: str | None = None,
) -> RunResult:
    target = registry.by_id(case.target_id)
    if target is None:
        raise AuthorizationDenied(case.target_id)

    exchanges: list[dict] = []
    record = None
    unreachable: str | None = None
    try:
        # When the case runs as a synthetic patient and a minter is available, obtain the
        # session token once and inject it into each turn so the request is authorized.
        auth_fields: dict = {}
        if case.auth is not None and minter is not None:
            auth_fields = minter.auth_fields(case.auth.patient_uuid)
        for turn in sorted(case.turns, key=lambda t: t.ordinal):
            body = {**(turn.body or {}), **auth_fields}
            url = target.origin + target.base_path + turn.route
            record = executor.request(url, method=turn.method, json=body)
            exchanges.append(record_exchange(turn.ordinal, turn.route, turn.method, body, record))
    except TargetUnreachable as exc:
        # A transport failure or a failed mint is not a defense holding — it is INCONCLUSIVE.
        unreachable = str(exc)

    if unreachable is not None:
        verdict = Verdict(VerdictOutcome.INCONCLUSIVE, (), f"target unreachable: {unreachable}")
        provider_events = ["target_unreachable"]
    else:
        observation = build_observation(record, case.oracle)
        verdict = judge.judge(observation)
        provider_events = list(observation.provider_events)

    return finalize(store, case, target, exchanges, verdict, provider_events, target_sha=target_sha)


def finalize(store, case: SeedCase, target, exchanges: list[dict], verdict: Verdict,
             provider_events: list[str], target_sha: str | None = None) -> RunResult:
    """Persist a judged attempt (spec, attempt, verdict, action) and promote/freeze on a
    confirmed exploit. Shared by run_case and the document-attack flow so lineage, dedup,
    finding promotion, and regression freezing are identical."""
    first_route = sorted(case.turns, key=lambda t: t.ordinal)[0].route if case.turns else None
    store.insert("attack_specs", {
        "schema_version": 1,
        "spec_id": case.case_id,
        "parent_spec_id": case.parent_id,
        "mutation_op": case.mutation_op,
        "category": case.category,
        "owasp": json.dumps(case.owasp),
        "target_route": first_route,
        "turns": json.dumps([t.model_dump() for t in case.turns]),
        "expected_safe_ref": case.expected_safe,
        "created_at": _now(),
    })

    attempt_id = _new_id("att")
    evidence_id = _new_id("ev")
    is_local = (urlsplit(target.origin).hostname or "") in {"localhost", "127.0.0.1", "::1"}
    # A lean projection stays on the attempt for compact queries; the full request/response
    # bodies go to the evidence table, so a verdict can always be audited against what the
    # target actually returned. exchanges may be rich (with request/response) or already lean.
    lean = [{"route": e.get("route"), "status_code": e.get("status_code"),
             "latency_ms": e.get("latency_ms")} for e in exchanges]
    store.insert("attempts", {
        "schema_version": 1,
        "attempt_id": attempt_id,
        "spec_id": case.case_id,
        "target_id": target.id,
        "target_sha": target_sha,   # the build under test; enables resilience-by-version trends
        "target_env": "local" if is_local else "deployed",
        "exchanges": json.dumps(lean),
        "provider_events": json.dumps(provider_events),
        "evidence_ref": evidence_id,
        "started_at": _now(),
    })
    store.insert("evidence", {
        "evidence_id": evidence_id,
        "attempt_id": attempt_id,
        "exchanges": json.dumps(exchanges),   # full request+response bodies (synthetic)
        "created_at": _now(),
    })
    verdict_id = _new_id("ver")
    store.insert("verdicts", {
        "schema_version": 1,
        "verdict_id": verdict_id,
        "attempt_id": attempt_id,
        "outcome": str(verdict.outcome),
        "oracle_results": json.dumps([{"oracle": r.oracle, "tier": r.tier, "outcome": str(r.outcome), "detail": r.detail} for r in verdict.oracle_results]),
        "evidence_ref": evidence_id,
        "judged_at": _now(),
    })
    store.insert("agent_actions", {
        "ts": _now(),
        "agent": "judge",
        "action": "verdict",
        "refs": json.dumps({"case": case.case_id, "attempt": attempt_id, "verdict": verdict_id}),
        "reason": verdict.reason,
    })

    # A confirmed exploit graduates into a deduplicated Finding, and a new Finding is
    # frozen into the regression suite so future builds are checked against it.
    if verdict.outcome is VerdictOutcome.SUCCESS:
        finding_id, is_new = findings.promote(store, case, verdict, verdict_id)
        store.insert("agent_actions", {
            "ts": _now(), "agent": "runner", "action": "finding" if is_new else "finding_dedup",
            "refs": json.dumps({"finding": finding_id, "verdict": verdict_id}),
            "reason": f"{'new' if is_new else 'duplicate'} finding {finding_id}",
        })
        if is_new:
            regression.freeze(store, finding_id, case)
    return RunResult(attempt_id=attempt_id, verdict=verdict)
