"""The runner plays turns through the Executor, judges, and records — with a fake sender."""

from __future__ import annotations

from pathlib import Path

import pytest

from redteam.agents.judge.judge import Judge, VerdictOutcome
from redteam.errors import AuthorizationDenied, TargetUnreachable
from redteam.evals.case import OracleConfig, SeedCase, Turn
from redteam.executor.authorization import AuthorizationRegistry
from redteam.executor.executor import Executor
from redteam.executor.http_sender import ResponseRecord
from redteam.runner import drive, run_case, send_turns
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


def test_send_turns_merge_precedence(tmp_path: Path) -> None:
    # The auth/body merge precedence is the BOLA-enabling inversion; pin both directions.
    reg = _registry(tmp_path)
    target = reg.by_id("good")
    seen: dict = {}

    def sender(url: str, **kw: object) -> ResponseRecord:
        seen.clear()
        seen.update(kw["json"])
        return ResponseRecord(200, "ok", 1.0)

    ex = Executor(reg, sender)
    turns = [Turn(ordinal=1, method="POST", route="/v1/x", body={"patient_uuid": "victim", "message": "hi"})]
    auth = {"patient_uuid": "attacker", "demo_token": "tok"}

    # body_wins=False: minted auth overrides the body's patient_uuid (self-consistent request)
    exchanges: list[dict] = []
    send_turns(target, ex, turns, exchanges, auth_fields=auth, body_wins=False)
    assert seen["patient_uuid"] == "attacker"
    assert len(exchanges) == 1

    # body_wins=True: the body's patient_uuid survives alongside the attacker's token (BOLA)
    send_turns(target, ex, turns, [], auth_fields=auth, body_wins=True)
    assert seen["patient_uuid"] == "victim"
    assert seen["demo_token"] == "tok"


def test_drive_maps_unreachable_to_inconclusive_and_persists(tmp_path: Path) -> None:
    # Closes a coverage gap: a transport failure is INCONCLUSIVE (never a defense holding), and
    # the attempt is still persisted with whatever exchanges were captured before the failure.
    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    case = SeedCase(
        case_id="c-unreach", category="prompt-injection", owasp=["LLM01"], target_id="good",
        turns=[Turn(ordinal=1, route="/v1/x")], expected_safe="",
    )

    def produce(target, exchanges):
        exchanges.append({"ordinal": 1, "route": "/v1/x", "status_code": None, "latency_ms": None})
        raise TargetUnreachable("connection reset")

    result = drive(store, case, reg, produce=produce)
    assert result.verdict.outcome is VerdictOutcome.INCONCLUSIVE
    assert store.count("attempts") == 1          # persisted despite the failure
    assert store.count("findings") == 0          # INCONCLUSIVE never promotes
    store.close()


def test_drive_denies_unknown_target(tmp_path: Path) -> None:
    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    case = SeedCase(case_id="c-unknown", category="x", owasp=["LLM01"], target_id="nope",
                    turns=[Turn(ordinal=1, route="/x")], expected_safe="")
    with pytest.raises(AuthorizationDenied):
        drive(store, case, reg, produce=lambda t, e: None)
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
