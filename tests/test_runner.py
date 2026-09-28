"""The runner plays turns through the Executor, judges, and records — with a fake sender."""

from __future__ import annotations

from pathlib import Path

import pytest

from redteam.agents.judge.judge import Judge, VerdictOutcome
from redteam.errors import AuthorizationDenied
from redteam.evals.case import OracleConfig, SeedCase, Turn
from redteam.executor.authorization import AuthorizationRegistry
from redteam.executor.executor import Executor
from redteam.executor.http_sender import ResponseRecord
from redteam.runner import run_case
from redteam.store.store import Store


def _registry(tmp_path: Path) -> AuthorizationRegistry:
    p = tmp_path / "auth.yaml"
    p.write_text("targets:\n  - id: good\n    origin: https://good.example\n    enabled: true\n", encoding="utf-8")
    return AuthorizationRegistry.load(p)


def test_run_case_records_attempt_and_verdict(tmp_path: Path) -> None:
    calls: list[str] = []

    def fake(url: str, **kw: object) -> ResponseRecord:
        calls.append(url)
        return ResponseRecord(200, "I can't share another patient's data", 12.0)

    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    case = SeedCase(
        case_id="c1", category="prompt-injection", owasp=["LLM01"], target_id="good",
        turns=[Turn(ordinal=1, method="POST", route="/v1/x", body={"q": "..."})],
        oracle=OracleConfig(marker="ZZ-MARKER"), expected_safe="refuses",
    )
    result = run_case(case, reg, Executor(reg, fake), Judge(), store)

    assert result.verdict.outcome is VerdictOutcome.FAIL  # marker absent -> attack failed
    assert store.count("attempts") == 1
    assert store.count("verdicts") == 1
    assert store.count("agent_actions") == 1
    assert calls == ["https://good.example/v1/x"]
    store.close()


def test_run_case_denies_unknown_target(tmp_path: Path) -> None:
    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    case = SeedCase(
        case_id="c2", category="x", owasp=["LLM01"], target_id="not-registered",
        turns=[Turn(ordinal=1, route="/x")], expected_safe="",
    )
    with pytest.raises(AuthorizationDenied):
        run_case(case, reg, Executor(reg, lambda u, **k: None), Judge(), store)
    assert store.count("attempts") == 0
    store.close()
