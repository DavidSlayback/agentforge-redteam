"""Observability queries aggregate the store into the six PRD answers."""

from __future__ import annotations

from pathlib import Path

from redteam.agents.judge.judge import Judge
from redteam.evals.case import OracleConfig, SeedCase, Turn
from redteam.executor.authorization import AuthorizationRegistry
from redteam.executor.executor import Executor
from redteam.executor.http_sender import ResponseRecord
from redteam.observability import queries, report
from redteam.runner import run_case
from redteam.store.store import Store


def _registry(tmp_path: Path) -> AuthorizationRegistry:
    p = tmp_path / "auth.yaml"
    p.write_text("targets:\n  - id: good\n    origin: https://good.example\n    proof: test fixture\n    enabled: true\n", encoding="utf-8")
    return AuthorizationRegistry.load(p)


def _case(cid: str) -> SeedCase:
    return SeedCase(
        case_id=cid, category="prompt-injection", owasp=["LLM01"], target_id="good",
        turns=[Turn(ordinal=1, route="/v1/x", body={})], oracle=OracleConfig(marker="ZZ-MARK"),
        expected_safe="refuses",
    )


def test_queries_aggregate_a_run(tmp_path: Path) -> None:
    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    # one clean response (FAIL) and one that emits the marker (SUCCESS)
    clean = Executor(reg, lambda u, **k: ResponseRecord(200, "no", 5.0))
    leaked = Executor(reg, lambda u, **k: ResponseRecord(200, "here is ZZ-MARK", 5.0))
    run_case(_case("c1"), reg, clean, Judge(), store)
    run_case(_case("c2"), reg, leaked, Judge(), store)

    assert queries.cases_per_category(store) == {"prompt-injection": 2}
    pf = queries.pass_fail_by_category(store)["prompt-injection"]
    assert pf == {"FAIL": 1, "SUCCESS": 1}
    # two verdict actions + one finding action (the SUCCESS promoted to a Finding)
    actions = queries.agent_trace(store)
    assert len(actions) == 3
    assert any(a["action"] == "finding" for a in actions)
    assert store.count("findings") == 1

    # the SUCCESS produced one new finding; run_case logs no cost (the campaign does)
    assert queries.findings_by_status(store) == {"new": 1}
    assert queries.cost_summary(store)["usd"] == 0.0
    md = report.render_markdown(store)
    assert "Pass/fail by category" in md and "SUCCESS=1" in md
    store.close()
