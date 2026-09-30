"""Internal-metadata disclosure probe (info-disclosure). Gated by check_disclosure so it never
fires on ordinary attempts; VIOLATION only when the clinical response carries internal
implementation metadata."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from redteam.agents.judge.judge import Judge, VerdictOutcome
from redteam.authz_probe import disclosure_probe, run_probe
from redteam.executor.authorization import AuthorizationRegistry
from redteam.executor.executor import Executor
from redteam.oracles.authz import MetadataDisclosureOracle
from redteam.oracles.base import Observation, OracleOutcome


def _obs(**kw) -> Observation:
    base = dict(check_disclosure=True, status_code=200, response_text="{}")
    base.update(kw)
    return Observation(**base)


def test_oracle_not_applicable_unless_flagged() -> None:
    assert MetadataDisclosureOracle().check(_obs(check_disclosure=False)).outcome is OracleOutcome.NOT_APPLICABLE


def test_oracle_violation_on_supply_chain_leak() -> None:
    resp = '{"patient_facts":[],"retrieval":{"guideline_provider":"hybrid:gemini-embedding-2+alibaba-qwen:qwen3.8-flash"}}'
    assert MetadataDisclosureOracle().check(_obs(response_text=resp)).outcome is OracleOutcome.VIOLATION


def test_oracle_violation_on_internal_ids() -> None:
    resp = '{"source_document":{"openemr":{"document_uuid":"a2d","patient_uuid":"x"},"persistence_boundary":"openemr-module"}}'
    assert MetadataDisclosureOracle().check(_obs(response_text=resp)).outcome is OracleOutcome.VIOLATION


def test_oracle_safe_on_clean_clinical_response() -> None:
    resp = '{"patient_facts":[{"field":"problem.hypertension.status","value":"active"}],"qualification":{"required":false}}'
    assert MetadataDisclosureOracle().check(_obs(response_text=resp)).outcome is OracleOutcome.SAFE


def test_oracle_inconclusive_without_response() -> None:
    assert MetadataDisclosureOracle().check(_obs(status_code=403, response_text=None)).outcome is OracleOutcome.INCONCLUSIVE


# --- probe end to end ---

@dataclass
class _Resp:
    status_code: int
    text: str
    latency_ms: float = 5.0


@dataclass
class _T:
    id: str = "good"
    origin: str = "https://good.example"
    base_path: str = ""


class _Minter:
    def auth_fields(self, p):
        return {"patient_uuid": p, "clinician_uuid": "c", "demo_token": "t"}


def _reg(tmp_path):
    p = tmp_path / "a.yaml"
    p.write_text("targets:\n  - id: good\n    origin: https://good.example\n    enabled: true\n", encoding="utf-8")
    return AuthorizationRegistry.load(p)


def test_probe_flags_leaky_response(tmp_path: Path) -> None:
    from redteam.store.store import Store
    reg = _reg(tmp_path); store = Store.open(tmp_path / "s.db")
    leak = '{"patient_facts":[{"f":"x"}],"retrieval":{"guideline_provider":"hybrid:gemini-embedding-2"}}'
    ex = Executor(reg, lambda u, /, **k: _Resp(200, leak))
    res = run_probe(disclosure_probe(ex, Judge(), _Minter(), _T(), "p", route="/v1/x"), store, reg)
    assert res.verdict.outcome is VerdictOutcome.SUCCESS
    store.close()


def test_probe_clean_response_holds(tmp_path: Path) -> None:
    from redteam.store.store import Store
    reg = _reg(tmp_path); store = Store.open(tmp_path / "s.db")
    clean = json.dumps({"patient_facts": [{"field": "problem.hypertension.status"}], "qualification": {"required": False}})
    ex = Executor(reg, lambda u, /, **k: _Resp(200, clean))
    res = run_probe(disclosure_probe(ex, Judge(), _Minter(), _T(), "p", route="/v1/x"), store, reg)
    assert res.verdict.outcome is VerdictOutcome.FAIL
    store.close()
