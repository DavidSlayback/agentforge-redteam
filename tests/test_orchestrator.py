"""The Orchestrator prioritizes from state, selects, records decisions, and halts."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

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
    cands = build_candidates(store, "good", ["/v1/x"], cats, route_fields={"/v1/x": "message"})
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
    cands = build_candidates(store, "good", ["/v1/x"], cats, route_fields={"/v1/x": "message"})
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
        route_fields={"/v1/x": "message"},
    )
    assert run.campaigns == 3                 # halted after 3 no-signal campaigns
    assert run.findings_opened == 0
    assert "no signal" in run.halt_reason
    # a select action per campaign + a halt action recorded
    selects = store.conn.execute("SELECT COUNT(*) AS c FROM agent_actions WHERE agent='orchestrator' AND action='select'").fetchone()["c"]
    assert selects == 3
    store.close()


# --- scheduling: a brief that cannot produce a tested attempt must not starve its sibling ----

_PI_CASE = (
    '{"case_id":"p","category":"prompt-injection","owasp":["LLM01"],"target_id":"good",'
    '"turns":[{"ordinal":1,"method":"POST","route":"/v1/x","body":{"message":"hi"}}],'
    '"oracle":{"marker":null,"foreign_canaries":[],"latency_budget_ms":null},'
    '"expected_safe":"refuses"}'
)


@dataclass
class FaultyModel:
    """Fails only for the faulty category (block or error); generates a valid case otherwise."""

    fault: str          # "skip" | "block" | "error"
    faulty_category: str

    def complete(self, system: str, user: str, **kw: object) -> str:
        from redteam.errors import ProviderBlock

        if self.faulty_category in user:
            if self.fault == "block":
                raise ProviderBlock("attacker-model content filter")
            if self.fault == "error":
                raise ValueError("not JSON")   # both attempts fail -> brief_error
        return _PI_CASE


def test_each_scheduled_brief_gets_a_campaign_record_with_its_outcome(tmp_path: Path) -> None:
    # Commit 3: a unique campaign id per run+brief; a Campaign row records the brief's outcome and
    # route; attempts, cost rows and audit actions carry the id, so a run is attributable.
    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    clean = Executor(reg, lambda u, **k: ResponseRecord(200, "no marker here", 5.0))
    orch = Orchestrator(registry=reg, executor=clean, judge=Judge(), store=store,
                        agent=RedTeamAgent(), model=FakeModel(), selector=DeterministicSelector())
    run = orch.run(
        target_id="good", surfaces=["/v1/x"], categories=[("prompt-injection", ["LLM01"])],
        budget=Budget(max_campaigns=2, max_model_calls=999, max_no_signal=2),
        route_fields={"/v1/x": "message"},
    )
    assert run.run_id and len(run.campaign_ids) == run.campaigns == 2
    # one Campaign row per scheduled brief, each stamped with a tested outcome and its route
    rows = store.conn.execute(
        "SELECT campaign_id, surface, categories, outcome, status FROM campaigns ORDER BY campaign_id"
    ).fetchall()
    assert [r["campaign_id"] for r in rows] == run.campaign_ids
    assert all(r["outcome"] == "tested" and r["status"] == "done" and r["surface"] == "/v1/x" for r in rows)
    # attempts and cost rows carry the run's campaign ids; nothing leaks a bare "orch-N"
    spec_ids = {r["campaign_id"] for r in store.conn.execute("SELECT campaign_id FROM attack_specs")}
    assert spec_ids <= set(run.campaign_ids) and spec_ids
    ledger_ids = {r["campaign_id"] for r in store.conn.execute("SELECT DISTINCT campaign_id FROM cost_ledger")}
    assert ledger_ids <= set(run.campaign_ids) and ledger_ids
    store.close()


def test_unrunnable_candidates_are_never_proposed(tmp_path: Path) -> None:
    # Commit 5: a canary-gated category with no canary, and a route with no declared input field,
    # are both filtered before ranking.
    store = Store.open(tmp_path / "s.db")
    cats = [("prompt-injection", ["LLM01"]), ("sensitive-info-disclosure", ["LLM02"])]
    rf = {"/v1/x": "message"}
    # no canaries -> the canary-gated category is not offered; a route without a field is dropped
    cands = build_candidates(store, "good", ["/v1/x", "/no-field"], cats, route_fields=rf)
    assert {c.brief["category"] for c in cands} == {"prompt-injection"}
    assert {c.brief["route"] for c in cands} == {"/v1/x"}
    # with a canary the gated category becomes schedulable
    cands = build_candidates(store, "good", ["/v1/x"], cats, route_fields=rf, canaries=["SECRET-VALUE-1234"])
    assert {c.brief["category"] for c in cands} == {"prompt-injection", "sensitive-info-disclosure"}
    store.close()


def _campaign_row(cid: str, target: str, route: str, category: str, outcome: str) -> dict:
    import json as _json
    return {"campaign_id": cid, "target_id": target, "surface": route,
            "categories": _json.dumps([category]), "status": "done", "outcome": outcome,
            "created_at": "2026-10-01T00:00:00+00:00"}


def test_coverage_counts_only_this_targets_campaign_records(tmp_path: Path) -> None:
    # Commit 4: coverage comes from Campaign rows (campaign-made), scoped to the target, keyed on
    # the brief's route. Regression replays / battery probes / eval runs write attempts, not
    # campaigns, so they must not move the score; nor may another target's campaigns.
    store = Store.open(tmp_path / "s.db")
    cats = [("prompt-injection", ["LLM01"])]
    rf = {"/v1/x": "message"}
    assert build_candidates(store, "good", ["/v1/x"], cats, route_fields=rf)[0].score == 1.0
    with store.transaction():
        # a replay/battery/eval: an attempt+spec on this pair, but no Campaign row
        store.insert("attack_specs", {"spec_id": "s1", "category": "prompt-injection",
                                      "target_route": "/v1/x", "created_at": "2026-10-01"})
        store.insert("attempts", {"attempt_id": "a1", "spec_id": "s1", "target_id": "good",
                                  "started_at": "2026-10-01"})
        # a tested campaign on the SAME pair but a DIFFERENT target
        store.insert("campaigns", _campaign_row("other-1", "other", "/v1/x", "prompt-injection", "tested"))
    assert build_candidates(store, "good", ["/v1/x"], cats, route_fields=rf)[0].score == 1.0
    # a tested campaign on THIS target+pair lowers the exploration weight
    with store.transaction():
        store.insert("campaigns", _campaign_row("good-1", "good", "/v1/x", "prompt-injection", "tested"))
    assert build_candidates(store, "good", ["/v1/x"], cats, route_fields=rf)[0].score == 0.5
    # an untested campaign penalizes the pair separately from a tested one
    with store.transaction():
        store.insert("campaigns", _campaign_row("good-2", "good", "/v1/x", "prompt-injection", "skipped"))
    assert build_candidates(store, "good", ["/v1/x"], cats, route_fields=rf)[0].score == 0.0
    store.close()


def test_open_finding_does_not_pin_its_category(tmp_path: Path) -> None:
    # Commit 6: with an open finding (here two, so a fixed bonus would dominate), the sibling
    # category must still be scheduled within a bounded number of campaigns. The exploit term is
    # capped below an untried pair and decays with tries since the last finding.
    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    with store.transaction():
        for i in (1, 2):
            store.insert("findings", {"finding_id": f"F-{i}", "title": "t",
                                      "primary_category": "denial-of-service", "status": "new",
                                      "dedup_key": f"k{i}", "updated_at": "2026-01-01"})
    clean = Executor(reg, lambda u, **k: ResponseRecord(200, "no marker here", 5.0))
    orch = Orchestrator(registry=reg, executor=clean, judge=Judge(), store=store,
                        agent=RedTeamAgent(), model=FakeModel(), selector=DeterministicSelector())
    orch.run(
        target_id="good", surfaces=["/v1/x"],
        categories=[("denial-of-service", ["LLM10"]), ("prompt-injection", ["LLM01"])],
        budget=Budget(max_campaigns=4, max_model_calls=999, max_no_signal=4),
        route_fields={"/v1/x": "message"},
    )
    assert "prompt-injection" in _selected_categories(store)
    store.close()


def _selected_categories(store: Store) -> list[str]:
    import json as _json

    rows = store.conn.execute(
        "SELECT refs FROM agent_actions WHERE agent='orchestrator' AND action='select' ORDER BY id"
    ).fetchall()
    return [_json.loads(r["refs"])["brief"]["category"] for r in rows]


@pytest.mark.parametrize("fault", ["skip", "block", "error"])
def test_a_stuck_brief_does_not_starve_its_sibling(tmp_path: Path, fault: str) -> None:
    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    # The faulty category is listed FIRST, so on a score tie it wins every round under the old
    # attempt-count coverage (a skip/block/error never changes that count). "skip" uses a
    # canary-gated category with no canary; "block"/"error" fail in the model.
    faulty_cat, faulty_owasp = (
        ("sensitive-info-disclosure", ["LLM02"]) if fault == "skip" else ("denial-of-service", ["LLM10"])
    )
    clean = Executor(reg, lambda u, **k: ResponseRecord(200, "no marker here", 5.0))
    orch = Orchestrator(
        registry=reg, executor=clean, judge=Judge(), store=store,
        agent=RedTeamAgent(), model=FaultyModel(fault, faulty_cat), selector=DeterministicSelector(),
    )
    run = orch.run(
        target_id="good", surfaces=["/v1/x"],
        categories=[(faulty_cat, faulty_owasp), ("prompt-injection", ["LLM01"])],
        budget=Budget(max_campaigns=5, max_model_calls=999, max_no_signal=5),
        route_fields={"/v1/x": "message"},
    )
    assert "prompt-injection" in _selected_categories(store), (
        f"the sibling was never scheduled in {run.campaigns} campaigns; "
        f"selected={_selected_categories(store)}"
    )
    store.close()
