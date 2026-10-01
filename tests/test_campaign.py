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


@dataclass
class _CountingRubric:
    available: bool = True

    def evaluate(self, obs):
        return Verdict(VerdictOutcome.FAIL, (), "rubric: fine")


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
