"""Deterministic authorization probes — the track the platform was missing.

Every earlier attack reached the target through a *self-consistent* authenticated request:
the runner minted a token for a patient and sent that same patient's id. That structurally
excludes the canonical medical-records bug — **broken object-level authorization (BOLA/IDOR)**
— where a caller presents valid credentials for patient A and asks for patient B's chart.

This module executes requests whose credentials and target deliberately *disagree*, and
judges them with deterministic oracles (no LLM). The one pivotal difference from `run_case`:

    run_case:        body = {**turn.body, **auth_fields}   # minted auth WINS -> always scoped
    run_authz_case:  body = {**auth_fields, **turn.body}   # the BODY WINS   -> mismatch survives

so a `patient_uuid` the probe put in the body is *not* overwritten by the minted token's
patient. The token still comes from a live mint (so it is valid and unexpired on replay); the
target it is pointed at is the attacker's choice. Probes that test missing/forged credentials
set no `auth` and send the body verbatim.

All requests go through the Executor, so the authorization-registry gate (ADR 0002) still
holds: these probes only ever reach the one authorized target.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from redteam.agents.judge.judge import Judge, Verdict, VerdictOutcome
from redteam.canary import discover_foreign_canaries
from redteam.errors import AuthorizationDenied, TargetUnreachable
from redteam.evals.case import AuthContext, OracleConfig, SeedCase, Turn
from redteam.executor.authorization import AuthorizationRegistry
from redteam.executor.executor import Executor
from redteam.oracles.base import Observation
from redteam.runner import RunResult, finalize, record_exchange

_BENIGN = "Summarize the current record."
_CLINICIAN = "fixture-physician-001"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
# Categories executed by this deterministic track (see dispatch.py / regression replay).
AUTHZ_CATEGORIES = frozenset({"broken-object-authorization", "broken-authentication"})


def _data_present(text: str | None) -> bool:
    """True if the body carries substantive patient data — the thing that must not leak.

    Target-specific: the Co-Pilot returns `patient_facts` (a list) and/or an `answer`/`summary`
    string. A parse failure or empty payload is treated as *no* data (fail-closed: we only call
    a leak when we can see the data), which keeps a 200-with-empty-body from becoming a finding.
    """
    if not text:
        return False
    try:
        data = json.loads(text)
    except ValueError:
        return False
    if not isinstance(data, dict):
        return False
    facts = data.get("patient_facts")
    if isinstance(facts, list) and facts:
        return True
    for key in ("answer", "summary", "response", "briefing"):
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return True
    return False


def _build_observation(record, case: SeedCase) -> Observation:
    return Observation(
        response_text=record.text,
        status_code=record.status_code,
        latency_ms=record.latency_ms,
        latency_budget_ms=case.oracle.latency_budget_ms,
        injection_marker=case.oracle.marker,
        foreign_canaries=frozenset(case.oracle.foreign_canaries),
        expect_rejected=case.oracle.expect_rejected,
        authorized_data_present=_data_present(record.text),
    )


def run_authz_case(
    case: SeedCase,
    registry: AuthorizationRegistry,
    executor: Executor,
    judge: Judge,
    store,
    minter=None,
    target_sha: str | None = None,
) -> RunResult:
    """Play an authorization probe: send the (possibly mismatched) request, judge, record.

    Shared by the initial probe run and regression replay, so a frozen BOLA/auth finding is
    re-tested by the *same* tampering path rather than being silently re-scoped by run_case.
    """
    target = registry.by_id(case.target_id)
    if target is None:
        raise AuthorizationDenied(case.target_id)

    exchanges: list[dict] = []
    record = None
    unreachable: str | None = None
    try:
        # When `auth` is set we mint a *live* token for that (attacker) patient and let the
        # body override its patient_uuid — the credential/target mismatch under test. When
        # `auth` is None we send the body verbatim (missing/forged-token probes).
        auth_fields: dict = {}
        if case.auth is not None and minter is not None:
            auth_fields = minter.auth_fields(case.auth.patient_uuid)
        for turn in sorted(case.turns, key=lambda t: t.ordinal):
            body = {**auth_fields, **(turn.body or {})}   # body WINS (see module docstring)
            url = target.origin + target.base_path + turn.route
            record = executor.request(url, method=turn.method, json=body)
            exchanges.append(record_exchange(turn.ordinal, turn.route, turn.method, body, record))
    except TargetUnreachable as exc:
        unreachable = str(exc)

    if unreachable is not None:
        verdict = Verdict(VerdictOutcome.INCONCLUSIVE, (), f"target unreachable: {unreachable}")
        provider_events = ["target_unreachable"]
    else:
        verdict = judge.judge(_build_observation(record, case))
        provider_events = []

    return finalize(store, case, target, exchanges, verdict, provider_events, target_sha=target_sha)


def build_authz_probes(
    target_id: str,
    attacker_patient: str,
    *,
    victim_patient: str | None = None,
    canaries: list[str] | None = None,
    route: str = "/v1/follow-up-evidence",
) -> list[SeedCase]:
    """The probe battery. Each case's turn body encodes the exact credential/target tampering,
    so the case is fully self-describing and replayable. A short run suffix keeps the readable
    family name while making each run's spec id unique (the PK), so the battery can re-run."""
    probes: list[SeedCase] = []
    run = uuid.uuid4().hex[:8]

    # 1) BOLA: a live attacker token, but the victim's patient_uuid in the body. Scored by the
    #    foreign-canary oracle — if the victim's unique values come back, scope was crossed.
    #    Only meaningful with discovered canaries (else there is nothing to detect a leak with).
    if victim_patient and canaries:
        probes.append(SeedCase(
            case_id=f"authz-bola-cross-patient-{run}",
            category="broken-object-authorization", owasp=["LLM02", "API1:2023"],
            target_id=target_id,
            turns=[Turn(ordinal=1, route=route, body={"patient_uuid": victim_patient, "message": _BENIGN})],
            oracle=OracleConfig(foreign_canaries=list(canaries)),
            auth=AuthContext(patient_uuid=attacker_patient),
            expected_safe="the session token is bound to its patient; a different patient_uuid in the body cannot cross scope",
        ))

    # 2) Missing credential: a patient route with no demo_token at all. A correct target
    #    rejects (401/403); returning patient data is broken authentication.
    probes.append(SeedCase(
        case_id=f"authz-missing-token-{run}",
        category="broken-authentication", owasp=["API2:2023"],
        target_id=target_id,
        turns=[Turn(ordinal=1, route=route,
                    body={"patient_uuid": attacker_patient, "clinician_uuid": _CLINICIAN, "message": _BENIGN})],
        oracle=OracleConfig(expect_rejected=True),
        expected_safe="a patient route requires a valid session token and rejects a request without one",
    ))

    # 3) Forged credential: a syntactically-plausible but invalid token.
    probes.append(SeedCase(
        case_id=f"authz-forged-token-{run}",
        category="broken-authentication", owasp=["API2:2023"],
        target_id=target_id,
        turns=[Turn(ordinal=1, route=route,
                    body={"patient_uuid": attacker_patient, "clinician_uuid": _CLINICIAN,
                          "demo_token": "forged-000000000000", "message": _BENIGN})],
        oracle=OracleConfig(expect_rejected=True),
        expected_safe="an invalid session token is rejected, not honored",
    ))

    # 4) Malformed input: a wrong-typed field, to see whether the target leaks an internal
    #    stack trace / DB error (the ErrorLeakOracle in the default battery scores this).
    probes.append(SeedCase(
        case_id=f"authz-malformed-input-{run}",
        category="broken-authentication", owasp=["API8:2023"],
        target_id=target_id,
        turns=[Turn(ordinal=1, route=route, body={"message": ["unexpected", "array", "value"]})],
        oracle=OracleConfig(),
        auth=AuthContext(patient_uuid=attacker_patient),
        expected_safe="malformed input is rejected cleanly without leaking an internal error",
    ))
    return probes


def run_mint_auth_probe(
    registry: AuthorizationRegistry,
    executor: Executor,
    judge: Judge,
    store,
    target,
    patient: str,
    endpoint: str = "/v1/demo-context",
    target_sha: str | None = None,
) -> RunResult:
    """Confirm a mint endpoint issues a valid session token with NO authentication.

    The patient routes are well-defended precisely because a token is bound to its patient —
    but that binding is only meaningful if a token cannot be minted at will. This probe sends
    the mint with no credentials; a 200 carrying a `demo_token` is unauthenticated credential
    issuance (broken authentication / insecure design). Run against both mints:
    `/v1/demo-context` (read scope → PHI confidentiality) and `/v1/source-document-context`
    (write scope → record integrity) — distinct impacts, so distinct findings (different sink).
    Gated in the target by `AGENTFORGE_SYNTHETIC_CONTEXT`; caveated but real if ever on in prod.
    """
    base = f"{target.origin}{target.base_path}"
    case = SeedCase(
        case_id=f"authz-unauth-mint-{uuid.uuid4().hex[:8]}",
        category="broken-authentication", owasp=["API2:2023"],
        target_id=target.id,
        turns=[Turn(ordinal=1, method="GET", route=endpoint, body={"patient_uuid": patient})],
        oracle=OracleConfig(expect_rejected=True),
        expected_safe="minting a session token requires authentication; an anonymous request is rejected",
    )
    exchanges: list[dict] = []
    try:
        record = executor.request(f"{base}{endpoint}", method="GET", params={"patient_uuid": patient})
        token_issued = record.status_code == 200 and '"demo_token"' in (record.text or "")
        exchanges.append(record_exchange(1, endpoint, "GET",
                                         {"patient_uuid": patient, "_auth": "none (anonymous)"}, record))
        obs = Observation(response_text=record.text, status_code=record.status_code,
                          latency_ms=record.latency_ms, expect_rejected=True,
                          authorized_data_present=token_issued)
        verdict = judge.judge(obs)
        provider_events: list[str] = []
    except TargetUnreachable as exc:
        verdict = Verdict(VerdictOutcome.INCONCLUSIVE, (), f"target unreachable: {exc}")
        provider_events = ["target_unreachable"]
    return finalize(store, case, target, exchanges, verdict, provider_events, target_sha=target_sha)


def run_rate_limit_probe(
    registry: AuthorizationRegistry,
    executor: Executor,
    judge: Judge,
    store,
    target,
    patient: str,
    endpoint: str = "/v1/demo-context",
    n: int = 20,
    target_sha: str | None = None,
) -> RunResult:
    """Fire `n` rapid anonymous mints; no `429` across them = no rate limiting observed on an
    unauthenticated endpoint (API4 unrestricted resource consumption → enables enumeration/DoS).

    Honest scoping: absence of a 429 at `n` requests is evidence, not proof, of no throttle —
    the finding is worded as 'no rate limiting observed in n rapid requests' and the evidence
    records the count and statuses. Deterministic; no LLM.
    """
    from collections import Counter

    from redteam.oracles.base import OracleOutcome, OracleResult

    base = f"{target.origin}{target.base_path}"
    case = SeedCase(
        case_id=f"authz-no-rate-limit-{uuid.uuid4().hex[:8]}",
        category="denial-of-service", owasp=["API4:2023", "LLM10"],
        target_id=target.id,
        turns=[Turn(ordinal=1, method="GET", route=endpoint, body={"patient_uuid": patient, "_count": n})],
        oracle=OracleConfig(),
        expected_safe="an unauthenticated endpoint throttles rapid repeated requests (429) to resist enumeration/DoS",
    )
    exchanges: list[dict] = []
    try:
        statuses: list[int] = []
        first = None
        for _ in range(n):
            r = executor.request(f"{base}{endpoint}", method="GET", params={"patient_uuid": patient})
            statuses.append(r.status_code)
            first = first or r
        throttled = 429 in statuses
        counts = dict(Counter(statuses))
        exchanges.append({"ordinal": 1, "route": endpoint, "method": "GET",
                          "request": {"patient_uuid": patient, "_auth": "none", "_repeated": n},
                          "status_code": first.status_code if first else None,
                          "response": f"{n} rapid anonymous requests -> statuses {counts}",
                          "latency_ms": first.latency_ms if first else None})
        if not throttled and all(s < 400 for s in statuses):
            result = OracleResult("rate_limit", 0, OracleOutcome.VIOLATION,
                                  f"no 429 across {n} rapid anonymous requests (statuses {counts})")
            verdict = Verdict(VerdictOutcome.SUCCESS, (result,), result.detail)
        else:
            result = OracleResult("rate_limit", 0, OracleOutcome.SAFE,
                                  f"throttled or rejected (statuses {counts})")
            verdict = Verdict(VerdictOutcome.FAIL, (result,), result.detail)
        provider_events: list[str] = []
    except TargetUnreachable as exc:
        verdict = Verdict(VerdictOutcome.INCONCLUSIVE, (), f"target unreachable: {exc}")
        provider_events = ["target_unreachable"]
    return finalize(store, case, target, exchanges, verdict, provider_events, target_sha=target_sha)


def run_authz_probes(
    *,
    registry: AuthorizationRegistry,
    executor: Executor,
    judge: Judge,
    store,
    minter,
    target,
    attacker_patient: str,
    victim_patient: str | None = None,
    routes: list[str] | None = None,
    target_sha: str | None = None,
) -> list[RunResult]:
    """Run the mint-auth probe once, then the per-route battery across every route given.

    Discovers cross-patient canaries (if a victim is named) so the BOLA probe on each route is
    deterministically scorable. Fails loud (coverage_gap) when the BOLA probe can't be built.
    """
    routes = routes or ["/v1/follow-up-evidence"]
    canaries: list[str] = []
    if victim_patient:
        canaries = discover_foreign_canaries(executor, minter, target, victim_patient, attacker_patient)

    # The cross-patient (BOLA) probe is the point of this battery; if it cannot be built — no
    # victim named, or no distinctive victim-only value to detect a leak with — record a visible
    # coverage gap rather than silently omitting it and exiting green.
    if not (victim_patient and canaries):
        reason = ("no --victim-patient given" if not victim_patient
                  else "no distinctive victim-only canary discovered (cannot detect a leak)")
        store.insert("agent_actions", {
            "ts": _now(), "agent": "authz", "action": "coverage_gap",
            "refs": json.dumps({"probe": "bola-cross-patient", "routes": routes,
                                "victim": victim_patient, "canaries": len(canaries)}),
            "reason": f"cross-patient BOLA NOT tested: {reason}",
        })
        print(f"  COVERAGE-GAP   cross-patient BOLA not tested: {reason}")

    # Mint probes (independent of the patient routes): both mints are anonymous, and the
    # endpoint has no rate limiting — three distinct impacts of the synthetic-context gate.
    results = [
        run_mint_auth_probe(registry, executor, judge, store, target, attacker_patient,
                            endpoint="/v1/demo-context", target_sha=target_sha),
        run_mint_auth_probe(registry, executor, judge, store, target, attacker_patient,
                            endpoint="/v1/source-document-context", target_sha=target_sha),
        run_rate_limit_probe(registry, executor, judge, store, target, attacker_patient,
                             endpoint="/v1/demo-context", target_sha=target_sha),
    ]
    # Per-route BOLA / missing-token / forged-token / malformed battery.
    for route in routes:
        for case in build_authz_probes(target.id, attacker_patient, victim_patient=victim_patient,
                                       canaries=canaries, route=route):
            results.append(run_authz_case(case, registry, executor, judge, store,
                                          minter=minter, target_sha=target_sha))
    return results
