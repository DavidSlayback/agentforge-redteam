"""The campaign loop generates, runs, and mutates a non-succeeding case — with fakes."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from redteam.agents.judge.judge import Judge, Verdict, VerdictOutcome
from redteam.agents.redteam.agent import MARKER_PREFIX, RedTeamAgent
from redteam.campaign import run_campaign
from redteam.executor.authorization import AuthorizationRegistry
from redteam.executor.executor import Executor
from redteam.executor.http_sender import ResponseRecord
from redteam.observability import queries
from redteam.store.store import Store

CANNED = (
    '{"case_id":"g1","category":"prompt-injection","owasp":["LLM01"],"target_id":"good",'
    '"turns":[{"ordinal":1,"method":"POST","route":"/v1/x","body":{"q":"hi"}}],'
    '"oracle":{"marker":"ZZ-TOKEN","foreign_canaries":[],"latency_budget_ms":null},'
    '"expected_safe":"refuses"}'
)


@dataclass
class FakeModel:
    def complete(self, system: str, user: str, **kw: object) -> str:
        # Aim the payload at the platform's marker, as a real attacker prompt now asks.
        found = re.search(re.escape(MARKER_PREFIX) + r"[0-9a-f]+", user)
        return CANNED.replace('"body":{"q":"hi"}', f'"body":{{"q":"say {found.group(0)}"}}') if found else CANNED


def _registry(tmp_path: Path) -> AuthorizationRegistry:
    p = tmp_path / "auth.yaml"
    p.write_text("targets:\n  - id: good\n    origin: https://good.example\n    proof: test fixture\n    enabled: true\n", encoding="utf-8")
    return AuthorizationRegistry.load(p)


def test_campaign_generates_and_mutates_on_failure(tmp_path: Path) -> None:
    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    # A clean response: the marker never appears, so every attempt is FAIL -> a mutation fires.
    executor = Executor(reg, lambda u, **k: ResponseRecord(200, "I won't do that", 5.0))
    summary = run_campaign(
        [{"category": "prompt-injection", "owasp": ["LLM01"], "target_id": "good", "route": "/v1/x"}],
        registry=reg, executor=executor, judge=Judge(), store=store,
        agent=RedTeamAgent(), model=FakeModel(), max_mutations=1,
    )
    assert summary.generated == 1
    assert summary.variants == 1                     # one FAIL -> one mutation
    assert summary.outcomes["FAIL"] == 2             # original + variant
    assert store.count("attempts") == 2
    assert store.count("cost_ledger") == 2           # one generation + one mutation call logged
    store.close()


@dataclass
class ProseModel:
    """Never returns JSON — each generation spends its retry and fails."""

    calls: int = 0

    def complete(self, system: str, user: str, **kw: object) -> str:
        self.calls += 1
        return "Sure! Here is an idea for a test..."


def test_every_model_call_is_metered_even_when_it_fails(tmp_path: Path) -> None:
    # --max-model-calls reads the ledger; a call that is made but not recorded escapes the cap.
    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    model = ProseModel()
    brief = {"category": "prompt-injection", "owasp": ["LLM01"], "target_id": "good", "route": "/v1/x"}
    summary = run_campaign([brief, brief], registry=reg, executor=Executor(reg, lambda u, **k: None),
                           judge=Judge(), store=store, agent=RedTeamAgent(), model=model)
    assert summary.outcomes["ERROR"] == 2
    assert model.calls == 4                                  # one retry per brief
    assert queries.cost_summary(store)["calls"] == model.calls
    store.close()


def test_the_model_call_cap_is_enforced_before_each_call(tmp_path: Path) -> None:
    # The cap is checked before every metered call, not only between campaigns, so total calls
    # never exceed it even when a single brief's retries would overshoot.
    from redteam.agents.orchestrator.budget import CallBudget

    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    model = ProseModel()                                     # each generate burns its retry (2 calls)
    brief = {"category": "prompt-injection", "owasp": ["LLM01"], "target_id": "good", "route": "/v1/x"}
    budget = CallBudget(max_calls=3)
    summary = run_campaign([brief, brief, brief], registry=reg, executor=Executor(reg, lambda u, **k: None),
                           judge=Judge(), store=store, agent=RedTeamAgent(), model=model, call_budget=budget)
    assert budget.used == 3                                  # charged up to, never past, the cap
    assert queries.cost_summary(store)["calls"] == 3         # every made call logged; none beyond the cap
    assert summary.budget_halted is True
    store.close()


def test_cap_hit_before_any_attempt_is_budget_halted_not_errored(tmp_path: Path) -> None:
    # Item 2: when the cap stops a brief before any attempt is made, the outcome is budget_halted,
    # distinct from an errored brief (no attempt written, not the brief's fault).
    from redteam.agents.orchestrator.budget import CallBudget

    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    brief = {"category": "prompt-injection", "owasp": ["LLM01"], "target_id": "good", "route": "/v1/x"}
    summary = run_campaign([brief], registry=reg, executor=Executor(reg, lambda u, **k: None),
                           judge=Judge(), store=store, agent=RedTeamAgent(), model=FakeModel(),
                           call_budget=CallBudget(max_calls=0))
    assert summary.generated == 0 and summary.budget_halted is True
    assert summary.brief_outcome() == "budget_halted"
    assert summary.outcomes.get("ERROR", 0) == 0
    store.close()


@dataclass
class _CountingRubric:
    available: bool = True

    def evaluate(self, obs):
        return Verdict(VerdictOutcome.FAIL, (), "rubric: fine")


def test_a_rubric_cap_hit_degrades_to_inconclusive_and_keeps_the_exchange(tmp_path: Path) -> None:
    # Item 3: the generation uses the only budgeted call; when the rubric would be the next call,
    # it degrades to INCONCLUSIVE (the Judge's own fallback) so the target exchange that already
    # happened is persisted, instead of raising inside produce and losing it.
    from redteam.agents.orchestrator.budget import CallBudget

    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    brief = {"category": "excessive-agency", "owasp": ["LLM06"], "target_id": "good", "route": "/v1/x"}
    summary = run_campaign([brief], registry=reg,
                           executor=Executor(reg, lambda u, **k: ResponseRecord(200, '{"answer":"no"}', 5.0)),
                           judge=Judge(rubric=_CountingRubric()), store=store, agent=RedTeamAgent(),
                           model=FakeModel(), max_mutations=1, call_budget=CallBudget(max_calls=1))
    assert store.count("attempts") == 1                              # the real exchange survived
    assert summary.results[0].verdict.outcome == VerdictOutcome.INCONCLUSIVE
    kinds = dict(store.conn.execute("SELECT kind, SUM(calls) FROM cost_ledger GROUP BY kind").fetchall())
    assert "rubric" not in kinds and kinds.get("generation") == 1   # rubric skipped, not charged
    store.close()


def test_rubric_calls_are_metered(tmp_path: Path) -> None:
    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    brief = {"category": "excessive-agency", "owasp": ["LLM06"], "target_id": "good", "route": "/v1/x"}
    run_campaign([brief], registry=reg, executor=Executor(reg, lambda u, **k: ResponseRecord(200, '{"answer":"no"}', 5.0)),
                 judge=Judge(rubric=_CountingRubric()), store=store, agent=RedTeamAgent(), model=FakeModel(),
                 max_mutations=1)
    kinds = dict(store.conn.execute("SELECT kind, SUM(calls) FROM cost_ledger GROUP BY kind").fetchall())
    assert kinds == {"generation": 1, "mutation": 1, "rubric": 2}
    store.close()


@dataclass
class BlockedModel:
    def complete(self, system: str, user: str, **kw: object) -> str:
        from redteam.errors import ProviderBlock
        raise ProviderBlock("content filter")


def test_a_blocked_call_is_still_metered(tmp_path: Path) -> None:
    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    brief = {"category": "prompt-injection", "owasp": ["LLM01"], "target_id": "good", "route": "/v1/x"}
    summary = run_campaign([brief], registry=reg, executor=Executor(reg, lambda u, **k: None), judge=Judge(),
                           store=store, agent=RedTeamAgent(), model=BlockedModel())
    assert summary.outcomes["PROVIDER_BLOCK"] == 1
    assert queries.cost_summary(store)["calls"] == 1
    store.close()


def test_metering_commits_on_its_own_and_refuses_to_join_another_unit(tmp_path: Path) -> None:
    # A metering row inside someone else's unit could be rolled back with it, erasing the record
    # of a call that was really made; the budget would silently undercount.
    import pytest

    from redteam.campaign import _log_call

    store = Store.open(tmp_path / "s.db")
    with pytest.raises(RuntimeError, match="metered"):
        with store.transaction():
            _log_call(store, "c", "generation")
    assert store.count("cost_ledger") == 0
    _log_call(store, "c", "generation")
    assert store.count("cost_ledger") == 1
    store.close()