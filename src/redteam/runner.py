"""The seed-case runner: the live execute -> judge -> record loop (S3).

For each case it resolves the target in the registry, plays the turns through the Executor
(so the authorization gate applies), builds a deterministic Observation from the final
response, asks the Judge for a Verdict, and records the Attempt, Verdict, and an ordered
agent-action into the store. It never reaches a target itself — only through the Executor.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit

from redteam import findings, regression
from typing import TYPE_CHECKING

from redteam.agents.judge.judge import Judge, VerdictOutcome, no_evidence
from redteam.errors import AuthorizationDenied, TargetUnreachable
from redteam.evals.case import OracleConfig, SeedCase
from redteam.executor.executor import Executor
from redteam.executor.authorization import AuthorizationRegistry
from redteam.oracles.base import Observation
from redteam.oracles.decode import decoded_values, normalize

if TYPE_CHECKING:   # annotations only: verdicts are built by the judge package (tests/test_verdict_path.py)
    from redteam.agents.judge.judge import Verdict


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


def _assert_rooted_route(route: str) -> None:
    """A (possibly model-supplied) route must be a rooted path on the authorized origin, not a
    way to relocate it. Reject a scheme, an authority (`//`), an `@`, or a backslash before the
    URL is assembled — defense-in-depth ahead of the final-URL authorization gate (T2.1)."""
    from redteam.errors import AuthorizationDenied

    if not route.startswith("/") or route.startswith("//") or "://" in route or "@" in route or "\\" in route:
        raise AuthorizationDenied(route)


def send_turns(target, executor: Executor, turns, exchanges: list[dict], *,
               auth_fields: dict | None = None, body_wins: bool = False):
    """Play a case's ordered turns through the Executor, appending one rich exchange per turn
    to ``exchanges``; return the last response record. May raise ``TargetUnreachable``.

    Args:
        auth_fields: session fields (token, patient, clinician) to merge into each body.
        body_wins: the auth/body merge precedence. ``False`` (default) lets ``auth_fields``
            override same-named body keys — a self-consistent authenticated request.
            ``True`` lets the turn body win, so a token-vs-patient mismatch survives to the
            wire — the inversion the cross-patient (BOLA) probe depends on.
    """
    auth_fields = auth_fields or {}
    record = None
    for turn in sorted(turns, key=lambda t: t.ordinal):
        _assert_rooted_route(turn.route)
        base = turn.body or {}
        body = {**auth_fields, **base} if body_wins else {**base, **auth_fields}
        url = target.origin + target.base_path + turn.route
        record = executor.request(url, method=turn.method, json=body)
        exchanges.append(record_exchange(turn.ordinal, turn.route, turn.method, body, record))
    return record


_ECHO_MIN_LEN = 12   # a payload this long is a meaningful echo, not a coincidental substring


def echoes_to_strip(payloads: Iterable[str], tokens: Iterable[str | None]) -> tuple[str, ...]:
    """The sent payload strings whose verbatim echo is removed before judging. A payload is
    stripped when it either (a) contains a token we judge on (marker/canary), or (b) is long enough
    (>= _ECHO_MIN_LEN) to be a real echo rather than a coincidental substring. Either way an echo
    of the attacker's OWN input is never evidence the assistant GENERATED that content
    (role-review T1.2/T3.1) — a real leak is the victim's data, which is not in the attacker's
    payload. Short payloads are left alone so they can't corrupt unrelated response text.

    Tokens are found in a payload under the same normalization the marker is matched with (owner
    decision 3), so a payload carrying a re-cased marker is still stripped."""
    toks = [normalize(t) for t in tokens if t]
    return tuple(dict.fromkeys(
        p for p in payloads if p and (len(p) >= _ECHO_MIN_LEN or any(tok in normalize(p) for tok in toks))))


def case_echoes(case: SeedCase) -> tuple[str, ...]:
    """The echoes to strip for a turn-based case: the string values of its turn bodies. A target
    that reflects the request must not let the model's own marker/canary (which it put in the
    payload) count as one the assistant generated (T1.2). Auth fields are merged in send_turns,
    not in the turn body, so only the case's own payload strings are stripped."""
    payloads = [v for turn in case.turns for v in (turn.body or {}).values() if isinstance(v, str)]
    return echoes_to_strip(payloads, [case.oracle.marker, *case.oracle.foreign_canaries])


def strip_echo(text: str, echoes: Iterable[str]) -> str:
    """``text`` with every verbatim occurrence of each echo replaced by a space."""
    for echo in echoes:
        if echo:
            text = text.replace(echo, " ")
    return text


def raw_echo_forms(echoes: Iterable[str]) -> tuple[str, ...]:
    """Each echo as it can appear in a raw JSON body: JSON-escaped (with and without non-ASCII
    escaping) as well as verbatim, so the raw view drops the same echo the decoded views drop."""
    forms: dict[str, None] = {}
    for echo in echoes:
        if echo:
            forms.update(dict.fromkeys((json.dumps(echo, ensure_ascii=False)[1:-1], json.dumps(echo)[1:-1], echo)))
    return tuple(forms)


def strip_normalized_echo(value: str, echoes: Iterable[str]) -> str:
    """A decoded value in normalized form (decode.normalize) with each echo removed in that same
    form (owner decision 3), so a re-cased or width-shifted echo of the payload cannot survive the
    strip and then match the case-insensitive marker check."""
    return strip_echo(normalize(value), dict.fromkeys(normalize(e) for e in echoes if e))


def build_observation(record, oracle: OracleConfig, provider_events: tuple[str, ...] = (), *,
                      echoes: Iterable[str] = ()) -> Observation:
    """The one way an Observation is built from a response record.

    Echoes of the sent payload are removed from every view, so none counts the attacker's own input
    as something the assistant generated: from the raw body (`response_text`) verbatim and in
    JSON-escaped form, verbatim from each decoded value (`decoded`, what the rubric model reads),
    and in normalized form from each normalized value (`normalized`, what the matching checks
    read), one value at a time before they are joined. The decoded values come from the UNSTRIPPED
    body, because stripping raw text can break the JSON before it is parsed; the payloads are
    decoded strings, so they match their decoded echoes even when the serializer escaped them
    (refactor #2)."""
    echoes = tuple(echoes)
    raw = record.text
    values = None if raw is None else decoded_values(raw)
    return Observation(
        response_text=None if raw is None else strip_echo(raw, raw_echo_forms(echoes)),
        decoded=None if values is None else tuple((p, strip_echo(v, echoes)) for p, v in values),
        normalized=None if values is None else tuple((p, strip_normalized_echo(v, echoes)) for p, v in values),
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
    campaign_id: str | None = None,
) -> RunResult:
    def produce(target, exchanges):
        # When the case runs as a synthetic patient and a minter is available, obtain the
        # session token once and inject it into each turn so the request is authorized.
        auth_fields: dict = {}
        if case.auth is not None and minter is not None:
            auth_fields = minter.auth_fields(case.auth.patient_uuid)
        record = send_turns(target, executor, case.turns, exchanges, auth_fields=auth_fields, body_wins=False)
        observation = build_observation(record, case.oracle, echoes=case_echoes(case))
        return judge.judge(observation), list(observation.provider_events)

    return drive(store, case, registry, target_sha=target_sha, produce=produce, campaign_id=campaign_id)


def finalize(store, case: SeedCase, target, exchanges: list[dict], verdict: Verdict,
             provider_events: list[str], target_sha: str | None = None,
             campaign_id: str | None = None) -> RunResult:
    """Persist a judged attempt (spec, attempt, verdict, action) and promote/freeze on a
    confirmed exploit. Shared by run_case and the document-attack flow so lineage, dedup,
    finding promotion, and regression freezing are identical."""
    # One unit of work: the spec, attempt, evidence, verdict and actions — and, on a confirmed
    # exploit, the finding and its frozen regression case — commit together or not at all, so a
    # crash or lock mid-way never leaves an attempt without its verdict or an unfrozen finding.
    with store.transaction():
        first_route = sorted(case.turns, key=lambda t: t.ordinal)[0].route if case.turns else None
        store.insert("attack_specs", {
            "schema_version": 1,
            "spec_id": case.case_id,
            "campaign_id": campaign_id,   # the scheduled brief this spec belongs to (GitLab #4)
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
            "campaign_id": campaign_id,
            "refs": json.dumps({"case": case.case_id, "attempt": attempt_id, "verdict": verdict_id}),
            "reason": verdict.reason,
        })

        # A confirmed exploit graduates into a deduplicated Finding, and a new Finding is
        # frozen into the regression suite so future builds are checked against it.
        if verdict.outcome is VerdictOutcome.SUCCESS:
            finding_id, is_new = findings.promote(store, case, verdict, verdict_id)
            store.insert("agent_actions", {
                "ts": _now(), "agent": "runner", "action": "finding" if is_new else "finding_dedup",
                "campaign_id": campaign_id,
                "refs": json.dumps({"finding": finding_id, "verdict": verdict_id}),
                "reason": f"{'new' if is_new else 'duplicate'} finding {finding_id}",
            })
            if is_new:
                regression.freeze(store, finding_id, case)
    return RunResult(attempt_id=attempt_id, verdict=verdict)


def drive(store, case: SeedCase, registry: AuthorizationRegistry, *, target_sha: str | None = None,
          produce, campaign_id: str | None = None) -> RunResult:
    """The shared execution driver: resolve the target, run ``produce``, and persist.

    ``produce(target, exchanges) -> (Verdict, list[str])`` runs the path-specific execution,
    appending rich exchanges to ``exchanges`` as it goes, and returns the verdict plus its
    provider events. It may return a terminal verdict directly (e.g. a document short-circuit)
    or raise ``TargetUnreachable`` — which the driver converts to an INCONCLUSIVE verdict,
    preserving whatever exchanges were captured (a transport failure is not a defense holding).
    Every attack path funnels through here so target resolution, the unreachable handling, and
    ``finalize`` live in exactly one place.
    """
    target = registry.by_id(case.target_id)
    if target is None:
        raise AuthorizationDenied(case.target_id)
    exchanges: list[dict] = []
    try:
        verdict, provider_events = produce(target, exchanges)
    except TargetUnreachable as exc:
        verdict = no_evidence(f"target unreachable: {exc}")
        provider_events = ["target_unreachable"]
    return finalize(store, case, target, exchanges, verdict, provider_events, target_sha=target_sha,
                    campaign_id=campaign_id)
