"""The Orchestrator prioritizes from state, selects, records decisions, and halts."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from redteam.agents.orchestrator.budget import Budget, Governor
from redteam.agents.orchestrator.candidates import build_candidates
from redteam.agents.orchestrator.orchestrator import Orchestrator
from redteam.agents.orchestrator.selector import DeterministicSelector
from redteam.agents.redteam.agent import RedTeamAgent
from redteam.agents.judge.judge import Judge
from redteam.executor.authorization import AuthorizationRegistry
from redteam.executor.executor import Executor
from redteam.executor.http_sender import ResponseRecord
from redteam.store.store import Store

CANNED = (
    '{"case_id":"x","category":"prompt-injection","owasp":["LLM01"],"target_id":"good",'
    '"turns":[{"ordinal":1,"method":"POST","route":"/v1/x","body":{}}],'
    '"oracle":{"marker":"ZZ","foreign_canaries":[],"latency_budget_ms":null},'
    '"expected_safe":"refuses"}'
)


@dataclass
class FakeModel:
    def complete(self, system: str, user: str, **kw: object) -> str:
        return CANNED


def _registry(tmp_path: Path) -> AuthorizationRegistry:
    p = tmp_path / "auth.yaml"
    p.write_text("targets:\n  - id: good\n    origin: https://good.example\n    proof: test fixture\n    enabled: true\n", encoding="utf-8")
    return AuthorizationRegistry.load(p)


def test_governor_halts_on_each_limit() -> None:
    g = Governor(Budget(max_campaigns=2, max_model_calls=999, max_no_signal=99))
    g.record(produced_finding=False, model_calls=0)
    assert not g.should_halt()
    g.record(produced_finding=False, model_calls=0)
    assert g.should_halt() and "campaign budget" in g.halt_reason()

    g2 = Governor(Budget(max_campaigns=99, max_model_calls=999, max_no_signal=2))
    g2.record(produced_finding=False, model_calls=0)
    g2.record(produced_finding=True, model_calls=0)   # a finding resets the streak
    assert not g2.should_halt()


def test_candidates_favor_untested_categories(tmp_path: Path) -> None:
    store = Store.open(tmp_path / "s.db")
    cats = [("prompt-injection", ["LLM01"]), ("denial-of-service", ["LLM10"])]
    cands = build_candidates(store, "good", ["/v1/x"], cats)
    # both untested -> equal score; the list is well-formed and sorted
    assert cands[0].score >= cands[-1].score
    assert {c.brief["category"] for c in cands} == {"prompt-injection", "denial-of-service"}
    store.close()


def test_candidates_favor_categories_with_open_findings(tmp_path: Path) -> None:
    store = Store.open(tmp_path / "s.db")
    with store.transaction():
        store.insert("findings", {
            "finding_id": "F-1", "title": "t", "primary_category": "denial-of-service",
            "status": "new", "dedup_key": "k1", "updated_at": "2026-09-28",
        })
    cats = [("prompt-injection", ["LLM01"]), ("denial-of-service", ["LLM10"])]
    cands = build_candidates(store, "good", ["/v1/x"], cats)
    assert cands[0].brief["category"] == "denial-of-service"   # exploit weight ranks it first
    assert cands[0].inputs["open_findings"] == 1
    store.close()


def test_governor_model_call_halt() -> None:
    g = Governor(Budget(max_campaigns=99, max_model_calls=5, max_no_signal=99))
    g.record(produced_finding=False, model_calls=6)
    assert g.should_halt() and "model-call budget" in g.halt_reason()


def test_jev_selector_requires_configuration(monkeypatch) -> None:
    import pytest
    from redteam.agents.orchestrator.candidates import Candidate
    from redteam.agents.orchestrator.selector import JevSelector

    monkeypatch.delenv("AGENTFORGE_REDTEAM_JEV_KEY", raising=False)
    with pytest.raises(RuntimeError):
        JevSelector().select([Candidate(brief={}, score=1.0)])


def test_jev_falls_back_on_vendor_outage(monkeypatch) -> None:
    # T3.7: a vendor/network outage must degrade to the deterministic top-1, not kill the run.
    import sys
    import types

    from redteam.agents.orchestrator.candidates import Candidate
    from redteam.agents.orchestrator.selector import JevSelector

    monkeypatch.setenv("AGENTFORGE_REDTEAM_JEV_KEY", "k")
    fake = types.ModuleType("typesafe_sdk")

    class _Client:
        def __init__(self, **kw): ...
        def system_one(self, *a, **k):
            raise RuntimeError("vendor down")
        def close(self): ...

    fake.TypeSafeClient = _Client
    fake.Choice = lambda **kw: None
    monkeypatch.setitem(sys.modules, "typesafe_sdk", fake)

    top1 = Candidate(brief={"category": "prompt-injection"}, score=1.0, inputs={"tried": 0, "open_findings": 0})
    chosen, meta = JevSelector().select([top1, Candidate(brief={"category": "x"}, score=0.5)])
    assert chosen is top1                      # deterministic fallback, not a crash
    assert meta["fell_back"] is True and "error" in meta


def test_jev_confidence_bands() -> None:
    from redteam.agents.orchestrator.candidates import Candidate
    from redteam.agents.orchestrator.selector import _apply_bands

    top = [Candidate(brief={"category": "a"}, score=2.0), Candidate(brief={"category": "b"}, score=1.0)]
    # confident: take Jev's pick (index 1)
    chosen, fell_back = _apply_bands(top, jev_index=1, confidence=0.9, threshold=0.5)
    assert chosen is top[1] and not fell_back
    # low confidence: fall back to the deterministic top-1
    chosen, fell_back = _apply_bands(top, jev_index=1, confidence=0.3, threshold=0.5)
    assert chosen is top[0] and fell_back
    # out-of-range index: fall back, never crash
    chosen, fell_back = _apply_bands(top, jev_index=9, confidence=0.9, threshold=0.5)
    assert chosen is top[0] and fell_back


def test_orchestrator_runs_and_halts_on_no_signal(tmp_path: Path) -> None:
    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    clean = Executor(reg, lambda u, **k: ResponseRecord(200, "no marker here", 5.0))  # always FAIL
    orch = Orchestrator(
        registry=reg, executor=clean, judge=Judge(), store=store,
        agent=RedTeamAgent(), model=FakeModel(), selector=DeterministicSelector(),
    )
    run = orch.run(
        target_id="good", surfaces=["/v1/x"],
        categories=[("prompt-injection", ["LLM01"])],
        budget=Budget(max_campaigns=99, max_model_calls=999, max_no_signal=3),
    )
    assert run.campaigns == 3                 # halted after 3 no-signal campaigns
    assert run.findings_opened == 0
    assert "no signal" in run.halt_reason
    # a select action per campaign + a halt action recorded
    selects = store.conn.execute("SELECT COUNT(*) AS c FROM agent_actions WHERE agent='orchestrator' AND action='select'").fetchone()["c"]
    assert selects == 3
    store.close()
