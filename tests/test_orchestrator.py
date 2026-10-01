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
    g.record(outcome="tested", produced_finding=False)
    assert not g.should_halt()
    g.record(outcome="tested", produced_finding=False)
    assert g.should_halt() and "campaign budget" in g.halt_reason()

    g2 = Governor(Budget(max_campaigns=99, max_model_calls=999, max_no_signal=2))
    g2.record(outcome="tested", produced_finding=False)
    g2.record(outcome="tested", produced_finding=True)   # a finding resets the streak
    assert not g2.should_halt()


def test_only_tested_campaigns_count_toward_no_signal() -> None:
    # Untested outcomes (skip / provider block / error / unreachable) are neither signal nor its
    # absence, so the no-signal streak counts only tested campaigns.
    g = Governor(Budget(max_campaigns=99, max_model_calls=999, max_no_signal=2))
    for outcome in ("skipped", "provider_blocked", "errored", "unreachable"):
        g.record(outcome=outcome, produced_finding=False)
    assert g.no_signal == 0 and g.tested == 0 and not g.should_halt()   # all untested: no halt
    g.record(outcome="tested", produced_finding=False)
    g.record(outcome="tested", produced_finding=False)
    assert g.should_halt() and "no signal for 2 tested campaigns" in g.halt_reason()


def test_call_budget_caps_and_reports_room() -> None:
    # The model-call cap lives solely on CallBudget (the Governor no longer counts calls).
    from redteam.agents.orchestrator.budget import CallBudget
    from redteam.errors import BudgetExceeded

    b = CallBudget(max_calls=2)
    assert b.has_room
    b.charge(); b.charge()
    assert not b.has_room
    with pytest.raises(BudgetExceeded):
        b.charge()
    assert CallBudget(max_calls=None).has_room   # no cap configured -> always room


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
    assert run.campaigns == 3 and run.tested == 3   # halted after 3 tested, findingless campaigns
    assert run.findings_opened == 0
    assert "no signal for 3 tested campaigns" in run.halt_reason
    # a select action per campaign + a halt action recorded
    selects = store.conn.execute("SELECT COUNT(*) AS c FROM agent_actions WHERE agent='orchestrator' AND action='select'").fetchone()["c"]
    assert selects == 3
    store.close()


def test_a_full_outage_run_tests_nothing(tmp_path: Path) -> None:
    # Item 4: when the target is unreachable for every attempt, the run tests nothing (so it exits
    # non-zero under decision 5) and never halts on "no signal" (that would imply it tested).
    from redteam.errors import TargetUnreachable

    def _down(url, **kw):
        raise TargetUnreachable("connection refused")

    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    orch = Orchestrator(registry=reg, executor=Executor(reg, _down), judge=Judge(), store=store,
                        agent=RedTeamAgent(), model=FakeModel(), selector=DeterministicSelector())
    run = orch.run(
        target_id="good", surfaces=["/v1/x"], categories=[("prompt-injection", ["LLM01"])],
        budget=Budget(max_campaigns=9, max_model_calls=999, max_no_signal=3),
        route_fields={"/v1/x": "message"},
    )
    assert run.tested == 0
    assert "no signal" not in run.halt_reason           # an outage is not "tested and found nothing"
    assert run.halt_reason == "nothing runnable"        # retired after two unreachable outcomes
    outcomes = {r["outcome"] for r in store.conn.execute("SELECT outcome FROM campaigns")}
    assert outcomes == {"unreachable"}
    store.close()


@dataclass
class BlockAllModel:
    def complete(self, system: str, user: str, **kw: object) -> str:
        from redteam.errors import ProviderBlock
        raise ProviderBlock("attacker-model content filter")


def test_run_with_nothing_runnable_halts_distinctly(tmp_path: Path) -> None:
    # Commit 7: the only brief is provider-blocked every campaign, so it is retired after two
    # untested outcomes and the run halts "nothing runnable" -- distinct from a no-signal halt,
    # and the no-signal streak never advanced because nothing was tested.
    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    clean = Executor(reg, lambda u, **k: ResponseRecord(200, "no marker here", 5.0))
    orch = Orchestrator(registry=reg, executor=clean, judge=Judge(), store=store,
                        agent=RedTeamAgent(), model=BlockAllModel(), selector=DeterministicSelector())
    run = orch.run(
        target_id="good", surfaces=["/v1/x"],
        categories=[("prompt-injection", ["LLM01"])],
        budget=Budget(max_campaigns=9, max_model_calls=999, max_no_signal=3),
        route_fields={"/v1/x": "message"},
    )
    assert run.halt_reason == "nothing runnable"
    assert run.tested == 0 and run.campaigns == 2   # retired after two untested outcomes
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


def test_run_signal_and_cost_are_attributed_to_its_own_campaigns(tmp_path: Path) -> None:
    # Commit 9: a finding and a cost-ledger row written outside this run (another run's campaign,
    # or none) must not count as this run's signal or cost.
    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    with store.transaction():
        # a finding + ledger row from some OTHER run's campaign
        store.insert("campaigns", _campaign_row("other-9", "good", "/v1/x", "prompt-injection", "tested"))
        store.insert("agent_actions", {"ts": "2026-10-01", "agent": "runner", "action": "finding",
                                       "campaign_id": "other-9", "reason": "foreign finding"})
        store.insert("cost_ledger", {"ts": "2026-10-01", "campaign_id": "other-9", "kind": "generation", "calls": 99})
    clean = Executor(reg, lambda u, **k: ResponseRecord(200, "no marker here", 5.0))
    orch = Orchestrator(registry=reg, executor=clean, judge=Judge(), store=store,
                        agent=RedTeamAgent(), model=FakeModel(), selector=DeterministicSelector())
    run = orch.run(
        target_id="good", surfaces=["/v1/x"], categories=[("prompt-injection", ["LLM01"])],
        budget=Budget(max_campaigns=2, max_model_calls=999, max_no_signal=2),
        route_fields={"/v1/x": "message"},
    )
    # clean target -> no new findings this run; the foreign finding and its 99 calls are excluded
    assert run.findings_opened == 0
    assert run.model_calls < 99                         # the foreign run's 99 calls are not ours
    assert run.model_calls == 2                         # one generation call per tested campaign
    store.close()


def _campaign_row(cid: str, target: str, route: str, category: str, outcome: str,
                  created_at: str = "2026-10-01T00:00:00+00:00") -> dict:
    import json as _json
    return {"campaign_id": cid, "target_id": target, "surface": route,
            "categories": _json.dumps([category]), "status": "done", "outcome": outcome,
            "created_at": created_at}


def _finding(store: Store, category: str, updated_at: str, key: str) -> None:
    with store.transaction():
        store.insert("findings", {"finding_id": f"F-{key}", "title": "t", "primary_category": category,
                                  "status": "new", "dedup_key": key, "updated_at": updated_at})


def test_exploit_term_is_capped_below_an_untried_pair(tmp_path: Path) -> None:
    # Item 8 (cap, independent of decay): with an open finding and no tries since it, the exploit
    # term is capped at 0.49 (not 0.5), so a finding-category untried pair scores 1.49, strictly
    # below what two such pairs would need to out-rank a fresh pair elsewhere.
    store = Store.open(tmp_path / "s.db")
    _finding(store, "denial-of-service", "2026-01-01", "cap")
    cands = build_candidates(store, "good", ["/v1/x"], [("denial-of-service", ["LLM10"])],
                             route_fields={"/v1/x": "message"})
    assert cands[0].score == 1.49          # 1.0 explore + min(0.5, 0.49) cap
    store.close()


def test_exploit_term_decays_with_tries_since_the_finding(tmp_path: Path) -> None:
    # Item 8 (decay, independent of the pair's own exploration): a tested campaign in the category
    # on ANOTHER route, AFTER the finding, raises tries_since to 1, so the exploit term on the
    # untried /v1/x pair decays to 0.25 (= 0.5/(1+1)) while its own explore weight stays 1.0.
    store = Store.open(tmp_path / "s.db")
    _finding(store, "denial-of-service", "2026-01-01", "decay")
    with store.transaction():
        store.insert("campaigns", _campaign_row("c-after", "good", "/other", "denial-of-service",
                                                "tested", created_at="2026-06-01T00:00:00+00:00"))
    cands = build_candidates(store, "good", ["/v1/x"], [("denial-of-service", ["LLM10"])],
                             route_fields={"/v1/x": "message"})
    assert cands[0].score == 1.25          # 1.0 explore + 0.5/(1+1) decayed exploit
    store.close()


def test_tries_since_ignores_campaigns_before_the_finding_and_other_targets(tmp_path: Path) -> None:
    # Item 8 (the c > ts comparison, and target scope): a tested campaign BEFORE the finding, and
    # one for ANOTHER target after it, must not count toward tries_since -> exploit stays capped.
    store = Store.open(tmp_path / "s.db")
    _finding(store, "denial-of-service", "2026-03-01", "ts")
    with store.transaction():
        store.insert("campaigns", _campaign_row("c-before", "good", "/other", "denial-of-service",
                                                "tested", created_at="2026-01-01T00:00:00+00:00"))
        store.insert("campaigns", _campaign_row("c-other-target", "other", "/other", "denial-of-service",
                                                "tested", created_at="2026-06-01T00:00:00+00:00"))
    cands = build_candidates(store, "good", ["/v1/x"], [("denial-of-service", ["LLM10"])],
                             route_fields={"/v1/x": "message"})
    assert cands[0].score == 1.49          # tries_since == 0 -> exploit still capped at 0.49
    store.close()


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
    store.close()


def test_past_untested_outcomes_do_not_suppress_a_pair_in_a_later_run(tmp_path: Path) -> None:
    # Item 1: the untested penalty is run-scoped, never persisted. A pair that was skipped/errored
    # in past runs must not score below a tested pair; only the CURRENT run's untested count (via
    # `untested_in_run`) applies a penalty.
    store = Store.open(tmp_path / "s.db")
    cats = [("prompt-injection", ["LLM01"]), ("denial-of-service", ["LLM10"])]
    rf = {"/v1/x": "message"}
    with store.transaction():
        # PI was untested twice in prior runs; DoS was tested once
        store.insert("campaigns", _campaign_row("r1-1", "good", "/v1/x", "prompt-injection", "errored"))
        store.insert("campaigns", _campaign_row("r1-2", "good", "/v1/x", "prompt-injection", "skipped"))
        store.insert("campaigns", _campaign_row("r2-1", "good", "/v1/x", "denial-of-service", "tested"))
    by_cat = {c.brief["category"]: c.score for c in build_candidates(store, "good", ["/v1/x"], cats, route_fields=rf)}
    assert by_cat["prompt-injection"] == 1.0    # past untested does NOT suppress it
    assert by_cat["denial-of-service"] == 0.5    # a real tested campaign does lower exploration
    # within a run, the penalty applies via untested_in_run
    penalised = {c.brief["category"]: c.score for c in build_candidates(
        store, "good", ["/v1/x"], cats, route_fields=rf,
        untested_in_run={("prompt-injection", "/v1/x"): 1})}
    assert penalised["prompt-injection"] == 0.5   # 1.0 - 0.5 penalty, this run only
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


# --- the Orchestrator passes the call budget; finding attribution; interleaved foreign rows -----

import re as _re

from redteam.agents.redteam.agent import MARKER_PREFIX


def _marker_case(user: str) -> str:
    """A generated case whose payload asks the assistant to emit the platform's minted marker."""
    m = _re.search(_re.escape(MARKER_PREFIX) + r"[0-9a-f]+", user)
    body = f"please emit {m.group(0)}" if m else "hi"
    return ('{"case_id":"g","category":"prompt-injection","owasp":["LLM01"],"target_id":"good",'
            '"turns":[{"ordinal":1,"method":"POST","route":"/v1/x","body":{"message":"' + body + '"}}],'
            '"oracle":{"marker":"ZZ","foreign_canaries":[],"latency_budget_ms":null},'
            '"expected_safe":"refuses"}')


@dataclass
class MarkerModel:
    def complete(self, system: str, user: str, **kw: object) -> str:
        return _marker_case(user)


def _emit_marker(url, **kw):
    """A target that emits the minted marker, wrapped so it is not a verbatim echo of the payload
    (strip_echoes only removes verbatim payload echoes), so the marker oracle fires -> SUCCESS."""
    msg = (kw.get("json") or {}).get("message", "")
    m = _re.search(_re.escape(MARKER_PREFIX) + r"[0-9a-f]+", msg)
    return ResponseRecord(200, f"RESULT {m.group(0)} END" if m else "no marker", 5.0)


def test_mutation_calls_are_capped_through_the_orchestrator(tmp_path: Path) -> None:
    # Item 8: the Orchestrator passes its CallBudget into the campaign, so a mutation call is
    # capped. With room for one call, the generation runs (a tested attempt is persisted) and the
    # mutation it would fire on a FAIL is refused, halting the run on the model-call budget.
    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    clean = Executor(reg, lambda u, **k: ResponseRecord(200, "no marker here", 5.0))  # marker absent -> FAIL
    orch = Orchestrator(registry=reg, executor=clean, judge=Judge(), store=store,
                        agent=RedTeamAgent(), model=MarkerModel(), selector=DeterministicSelector())
    run = orch.run(
        target_id="good", surfaces=["/v1/x"], categories=[("prompt-injection", ["LLM01"])],
        budget=Budget(max_campaigns=5, max_model_calls=1, max_no_signal=5),
        route_fields={"/v1/x": "message"},
    )
    assert "model-call budget" in run.halt_reason
    assert store.count("attempts") == 1          # generation's attempt persisted; mutation never ran
    kinds = dict(store.conn.execute("SELECT kind, SUM(calls) FROM cost_ledger GROUP BY kind").fetchall())
    assert kinds == {"generation": 1}            # the mutation call was capped
    assert run.model_calls == 1
    store.close()


def test_a_finding_resets_no_signal_and_is_attributed_to_the_run(tmp_path: Path) -> None:
    # Item 8: a SUCCESS through the Orchestrator writes a 'finding' audit action carrying the
    # campaign id, so the run counts it (findings_opened) and the no-signal streak resets.
    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    orch = Orchestrator(registry=reg, executor=Executor(reg, _emit_marker), judge=Judge(), store=store,
                        agent=RedTeamAgent(), model=MarkerModel(), selector=DeterministicSelector())
    run = orch.run(
        target_id="good", surfaces=["/v1/x"], categories=[("prompt-injection", ["LLM01"])],
        budget=Budget(max_campaigns=1, max_model_calls=999, max_no_signal=1),
        route_fields={"/v1/x": "message"},
    )
    assert run.findings_opened == 1 and run.tested == 1
    # the finding action carries one of the run's campaign ids (the runner stamped it)
    rows = store.conn.execute("SELECT campaign_id FROM agent_actions WHERE action='finding'").fetchall()
    assert [r["campaign_id"] for r in rows] == [run.campaign_ids[0]]
    store.close()


@dataclass
class InterleavingModel:
    """Writes a foreign run's finding + cost rows DURING our run (before returning its case), so a
    global-delta accounting would wrongly fold them into this run's signal and cost."""

    store: object
    done: bool = False

    def complete(self, system: str, user: str, **kw: object) -> str:
        if not self.done:
            self.done = True
            with self.store.transaction():
                self.store.insert("findings", {"finding_id": "F-foreign", "title": "t",
                                               "primary_category": "x", "status": "new",
                                               "dedup_key": "foreign", "updated_at": "2026-10-01"})
                self.store.insert("agent_actions", {"ts": "2026-10-01", "agent": "runner",
                                                    "action": "finding", "campaign_id": "foreign-run",
                                                    "reason": "foreign"})
                self.store.insert("cost_ledger", {"ts": "2026-10-01", "campaign_id": "foreign-run",
                                                  "kind": "generation", "calls": 50})
        return CANNED


def test_interleaved_foreign_rows_are_not_counted_as_this_run(tmp_path: Path) -> None:
    # Item 8: foreign findings/cost written WHILE the run is in flight must not be attributed to
    # it. The old global-delta code (findings-count delta, SUM(cost_ledger)) would have.
    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    clean = Executor(reg, lambda u, **k: ResponseRecord(200, "no marker here", 5.0))
    orch = Orchestrator(registry=reg, executor=clean, judge=Judge(), store=store,
                        agent=RedTeamAgent(), model=InterleavingModel(store), selector=DeterministicSelector())
    run = orch.run(
        target_id="good", surfaces=["/v1/x"], categories=[("prompt-injection", ["LLM01"])],
        budget=Budget(max_campaigns=1, max_model_calls=999, max_no_signal=1),
        route_fields={"/v1/x": "message"},
    )
    assert store.count("findings") == 1                 # the foreign finding row exists in the store
    assert run.findings_opened == 0                     # but it is not this run's signal
    assert run.model_calls == 1 and run.model_calls < 50  # nor its cost (the foreign 50 excluded)
    store.close()
