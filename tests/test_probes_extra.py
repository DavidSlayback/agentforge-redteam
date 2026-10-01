"""Enumeration (API1/API3) and data-integrity/contradiction (LLM09) probes."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from redteam.agents.judge.judge import Judge, VerdictOutcome
from redteam.authz_probe import contradiction_probe, enumeration_probe, run_probe
from redteam.executor.authorization import AuthorizationRegistry
from redteam.executor.executor import Executor
from redteam.store.store import Store


@dataclass
class _Resp:
    status_code: int
    text: str
    latency_ms: float = 2.0


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
    p.write_text("targets:\n  - id: good\n    origin: https://good.example\n    proof: test fixture\n    enabled: true\n", encoding="utf-8")
    return AuthorizationRegistry.load(p)


# --- enumeration ---

def test_enumeration_violation_when_mint_issues_for_arbitrary_id(tmp_path: Path) -> None:
    reg = _reg(tmp_path); store = Store.open(tmp_path / "s.db")
    ex = Executor(reg, lambda u, /, **k: _Resp(200, '{"demo_token":"x","expires_in_seconds":300}'))
    res = run_probe(enumeration_probe(ex, Judge(), _T(), patient="fixture-patient-987654"), store, reg)
    assert res.verdict.outcome is VerdictOutcome.SUCCESS
    store.close()


def test_enumeration_safe_when_mint_refuses(tmp_path: Path) -> None:
    reg = _reg(tmp_path); store = Store.open(tmp_path / "s.db")
    ex = Executor(reg, lambda u, /, **k: _Resp(400, '{"error":"invalid_synthetic_patient"}'))
    res = run_probe(enumeration_probe(ex, Judge(), _T(), patient="fixture-patient-995"), store, reg)
    assert res.verdict.outcome is VerdictOutcome.FAIL
    store.close()


def test_enumeration_inconclusive_when_rate_limited(tmp_path: Path) -> None:
    # a 429 means throttled (the F-6ee control), not "mint restricted" — never a false pass
    reg = _reg(tmp_path); store = Store.open(tmp_path / "s.db")
    ex = Executor(reg, lambda u, /, **k: _Resp(429, "slow down"))
    res = run_probe(enumeration_probe(ex, Judge(), _T(), patient="fixture-patient-995"), store, reg)
    assert res.verdict.outcome is VerdictOutcome.INCONCLUSIVE
    store.close()


# --- contradiction ---

def _facts(*pairs) -> str:
    return json.dumps({"status": "ready",
                       "patient_facts": [{"field": f, "value": v, "current": c} for f, v, c in pairs]})


def test_contradiction_violation_on_two_values_no_current(tmp_path: Path) -> None:
    reg = _reg(tmp_path); store = Store.open(tmp_path / "s.db")
    body = _facts(("medication.lisinopril.dose", "5 mg", None), ("medication.lisinopril.dose", "10 mg", None))
    ex = Executor(reg, lambda u, /, **k: _Resp(200, body))
    res = run_probe(contradiction_probe(ex, Judge(), _Minter(), _T(), "p"), store, reg)
    assert res.verdict.outcome is VerdictOutcome.SUCCESS
    store.close()


def test_contradiction_safe_when_current_marked(tmp_path: Path) -> None:
    reg = _reg(tmp_path); store = Store.open(tmp_path / "s.db")
    body = _facts(("medication.lisinopril.dose", "5 mg", False), ("medication.lisinopril.dose", "10 mg", True))
    ex = Executor(reg, lambda u, /, **k: _Resp(200, body))
    res = run_probe(contradiction_probe(ex, Judge(), _Minter(), _T(), "p"), store, reg)
    assert res.verdict.outcome is VerdictOutcome.FAIL
    store.close()


def test_contradiction_safe_on_single_value(tmp_path: Path) -> None:
    reg = _reg(tmp_path); store = Store.open(tmp_path / "s.db")
    ex = Executor(reg, lambda u, /, **k: _Resp(200, _facts(("medication.lisinopril.dose", "10 mg", None))))
    res = run_probe(contradiction_probe(ex, Judge(), _Minter(), _T(), "p"), store, reg)
    assert res.verdict.outcome is VerdictOutcome.FAIL
    store.close()


def test_contradiction_inconclusive_on_an_error_status(tmp_path: Path) -> None:
    # An error body has no patient_facts; that is no chart to check, not a reconciled chart.
    reg = _reg(tmp_path); store = Store.open(tmp_path / "s.db")
    ex = Executor(reg, lambda u, /, **k: _Resp(429, '{"error":"rate_limited"}'))
    res = run_probe(contradiction_probe(ex, Judge(), _Minter(), _T(), "fixture-patient-001"), store, reg)
    assert res.verdict.outcome is VerdictOutcome.INCONCLUSIVE
    store.close()
