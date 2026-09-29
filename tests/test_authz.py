"""The deterministic authorization track: oracles, the inverted-merge executor, the battery."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from redteam.agents.judge.judge import Judge, VerdictOutcome
from redteam.authz_probe import build_authz_probes, run_authz_case, run_mint_auth_probe
from redteam.executor.authorization import AuthorizationRegistry
from redteam.executor.executor import Executor
from redteam.executor.http_sender import ResponseRecord
from redteam.oracles.authz import ErrorLeakOracle, UnauthorizedAccessOracle
from redteam.oracles.base import Observation, OracleOutcome
from redteam.store.store import Store

ATTACKER = "fixture-patient-001"
VICTIM = "fixture-patient-002"
VICTIM_CANARY = "penicillin-anaphylaxis-2019"   # a victim-only value, len >= 12


def _registry(tmp_path: Path) -> AuthorizationRegistry:
    p = tmp_path / "auth.yaml"
    p.write_text("targets:\n  - id: good\n    origin: https://good.example\n    enabled: true\n", encoding="utf-8")
    return AuthorizationRegistry.load(p)


@dataclass
class FakeMinter:
    def auth_fields(self, patient_uuid: str) -> dict:
        return {"patient_uuid": patient_uuid, "clinician_uuid": "c", "demo_token": f"tok-{patient_uuid}"}

    def write_fields(self, patient_uuid: str) -> dict:
        return self.auth_fields(patient_uuid)


# ---- oracles -------------------------------------------------------------------------

def test_unauthorized_oracle_flags_data_on_a_should_be_denied_request() -> None:
    obs = Observation(status_code=200, expect_rejected=True, authorized_data_present=True)
    assert UnauthorizedAccessOracle().check(obs).outcome is OracleOutcome.VIOLATION


def test_unauthorized_oracle_credits_a_proper_denial() -> None:
    obs = Observation(status_code=403, expect_rejected=True)
    assert UnauthorizedAccessOracle().check(obs).outcome is OracleOutcome.SAFE


def test_unauthorized_oracle_inconclusive_when_accepted_but_no_data() -> None:
    obs = Observation(status_code=200, expect_rejected=True, authorized_data_present=False)
    assert UnauthorizedAccessOracle().check(obs).outcome is OracleOutcome.INCONCLUSIVE


def test_unauthorized_oracle_not_applicable_on_ordinary_attempt() -> None:
    obs = Observation(status_code=200, expect_rejected=False)
    assert UnauthorizedAccessOracle().check(obs).outcome is OracleOutcome.NOT_APPLICABLE


def test_error_leak_oracle_catches_a_traceback() -> None:
    obs = Observation(response_text='{"detail": "Traceback (most recent call last): ..."}')
    assert ErrorLeakOracle().check(obs).outcome is OracleOutcome.VIOLATION


def test_error_leak_oracle_ignores_a_clean_body() -> None:
    obs = Observation(response_text='{"answer": "labs within range"}')
    assert ErrorLeakOracle().check(obs).outcome is OracleOutcome.NOT_APPLICABLE


# ---- the inverted-merge executor -----------------------------------------------------

def _run(case, sender, tmp_path: Path):
    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    res = run_authz_case(case, reg, Executor(reg, sender), Judge(), store, FakeMinter())
    findings = store.count("findings")
    store.close()
    return res, findings


def _bola_case():
    [case] = [c for c in build_authz_probes("good", ATTACKER, victim_patient=VICTIM,
                                            canaries=[VICTIM_CANARY]) if c.case_id.startswith("authz-bola-cross-patient")]
    return case


def test_bola_sends_attacker_token_with_victim_patient_id(tmp_path: Path) -> None:
    # The pivotal assertion: the body's victim patient_uuid must survive the merge, carried on
    # the SAME request as the attacker's minted token — the mismatch run_case cannot express.
    seen: dict = {}

    def sender(url, **kw):
        seen.update(kw["json"])
        return ResponseRecord(200, json.dumps({"patient_facts": [{"value": "own data"}]}), 3.0)

    _run(_bola_case(), sender, tmp_path)
    assert seen["patient_uuid"] == VICTIM           # body won
    assert seen["demo_token"] == f"tok-{ATTACKER}"  # attacker's live token


def test_bola_is_a_finding_when_victim_data_leaks(tmp_path: Path) -> None:
    # A vulnerable target trusts the body patient_uuid and returns the victim's record.
    def sender(url, **kw):
        return ResponseRecord(200, json.dumps({"patient_facts": [{"value": VICTIM_CANARY}]}), 3.0)

    res, findings = _run(_bola_case(), sender, tmp_path)
    assert res.verdict.outcome is VerdictOutcome.SUCCESS
    assert findings == 1


def test_bola_holds_when_the_token_is_bound_to_its_patient(tmp_path: Path) -> None:
    # A correct target ignores the body patient_uuid and serves only the token's patient.
    def sender(url, **kw):
        return ResponseRecord(200, json.dumps({"patient_facts": [{"value": "attacker own data"}]}), 3.0)

    res, findings = _run(_bola_case(), sender, tmp_path)
    assert res.verdict.outcome is VerdictOutcome.FAIL
    assert findings == 0


def _missing_token_case():
    [case] = [c for c in build_authz_probes("good", ATTACKER) if c.case_id.startswith("authz-missing-token")]
    return case


def test_missing_token_holds_on_a_401(tmp_path: Path) -> None:
    res, findings = _run(_missing_token_case(), lambda u, **k: ResponseRecord(401, "unauthorized", 1.0), tmp_path)
    assert res.verdict.outcome is VerdictOutcome.FAIL
    assert findings == 0


def test_missing_token_is_a_finding_when_data_comes_back(tmp_path: Path) -> None:
    body = json.dumps({"patient_facts": [{"value": "x"}]})
    res, findings = _run(_missing_token_case(), lambda u, **k: ResponseRecord(200, body, 1.0), tmp_path)
    assert res.verdict.outcome is VerdictOutcome.SUCCESS
    assert findings == 1


def test_authz_finding_is_gated_for_human_approval(tmp_path: Path) -> None:
    # A broken-authentication finding is critical and MUST be held for approval, not auto-published.
    from redteam.agents.documentation.agent import DocumentationAgent

    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    body = json.dumps({"patient_facts": [{"value": "x"}]})
    run_authz_case(_missing_token_case(), reg, Executor(reg, lambda u, **k: ResponseRecord(200, body, 1.0)),
                   Judge(), store, FakeMinter())
    finding_id = store.conn.execute("SELECT finding_id FROM findings").fetchone()["finding_id"]
    report_id = DocumentationAgent().document(store, finding_id)
    status = store.conn.execute("SELECT status FROM vuln_reports WHERE report_id = ?", (report_id,)).fetchone()["status"]
    assert status == "pending_approval"   # not auto-published
    store.close()


# ---- the battery ---------------------------------------------------------------------

def _target(reg):
    return reg.by_id("good")


def test_unauth_mint_is_a_finding_when_a_token_is_issued(tmp_path: Path) -> None:
    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    # anonymous GET to the mint returns a token -> unauthenticated credential issuance
    token_body = json.dumps({"demo_token": "eyJ...", "patient_uuid": ATTACKER})
    res = run_mint_auth_probe(reg, Executor(reg, lambda u, **k: ResponseRecord(200, token_body, 2.0)),
                              Judge(), store, _target(reg), ATTACKER)
    assert res.verdict.outcome is VerdictOutcome.SUCCESS
    assert store.count("findings") == 1
    store.close()


def test_unauth_mint_holds_when_the_mint_requires_auth(tmp_path: Path) -> None:
    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    res = run_mint_auth_probe(reg, Executor(reg, lambda u, **k: ResponseRecord(401, "unauthorized", 1.0)),
                              Judge(), store, _target(reg), ATTACKER)
    assert res.verdict.outcome is VerdictOutcome.FAIL
    assert store.count("findings") == 0
    store.close()


def test_bola_probe_is_omitted_without_canaries() -> None:
    families = {c.case_id.rsplit("-", 1)[0] for c in build_authz_probes("good", ATTACKER)}
    assert "authz-bola-cross-patient" not in families   # nothing to detect a leak with
    assert {"authz-missing-token", "authz-forged-token", "authz-malformed-input"} <= families
