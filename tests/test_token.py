"""Token minting caches, mints through the Executor, and the runner injects the token."""

from __future__ import annotations

import json
from pathlib import Path

from redteam.agents.judge.judge import Judge
from redteam.evals.case import AuthContext, OracleConfig, SeedCase, Turn
from redteam.executor.authorization import AuthorizationRegistry
from redteam.executor.executor import Executor
from redteam.executor.http_sender import ResponseRecord
from redteam.errors import TargetUnreachable
from redteam.executor.token import TokenMinter
from redteam.runner import run_case
from redteam.store.store import Store

TOKEN_JSON = json.dumps({
    "demo_token": "TOK-123", "clinician_uuid": "fixture-physician-001",
    "patient_uuid": "fixture-patient-001", "expires_in_seconds": 300,
})


def _registry(tmp_path: Path) -> AuthorizationRegistry:
    p = tmp_path / "auth.yaml"
    p.write_text(
        "targets:\n  - id: good\n    origin: https://good.example\n"
        "    base_path: /app\n    proof: test fixture\n    enabled: true\n",
        encoding="utf-8",
    )
    return AuthorizationRegistry.load(p)


def test_minter_caches_and_uses_the_executor(tmp_path: Path) -> None:
    reg = _registry(tmp_path)
    calls: list[str] = []

    def sender(url: str, **kw: object) -> ResponseRecord:
        calls.append(url)
        return ResponseRecord(200, TOKEN_JSON, 3.0)

    minter = TokenMinter(Executor(reg, sender), reg.by_id("good"))
    t1 = minter.mint("fixture-patient-001")
    t2 = minter.mint("fixture-patient-001")
    assert t1.demo_token == "TOK-123"
    assert t2 is t1                       # cached: second mint makes no new call
    assert calls == ["https://good.example/app/v1/demo-context"]  # base_path applied


def test_runner_injects_token_into_turn_body(tmp_path: Path) -> None:
    reg = _registry(tmp_path)
    bodies: list[dict] = []

    def sender(url: str, **kw: object) -> ResponseRecord:
        if url.endswith("/v1/demo-context"):
            return ResponseRecord(200, TOKEN_JSON, 3.0)
        bodies.append(kw.get("json", {}))
        return ResponseRecord(200, "clean", 5.0)

    executor = Executor(reg, sender)
    minter = TokenMinter(executor, reg.by_id("good"))
    case = SeedCase(
        case_id="c1", category="prompt-injection", owasp=["LLM01"], target_id="good",
        turns=[Turn(ordinal=1, method="POST", route="/v1/briefings", body={"x": 1})],
        oracle=OracleConfig(marker="ZZ"), expected_safe="refuses",
        auth=AuthContext(patient_uuid="fixture-patient-001"),
    )
    run_case(case, reg, executor, Judge(), Store.open(tmp_path / "s.db"), minter=minter)

    assert bodies and bodies[0]["demo_token"] == "TOK-123"
    assert bodies[0]["patient_uuid"] == "fixture-patient-001"
    assert bodies[0]["x"] == 1            # original body preserved


def _minter_with(tmp_path: Path, records: list[ResponseRecord]) -> tuple[TokenMinter, list[float], list[str]]:
    reg = _registry(tmp_path)
    queue, calls, slept = list(records), [], []

    def sender(url: str, **kw: object) -> ResponseRecord:
        calls.append(url)
        return queue.pop(0)

    minter = TokenMinter(Executor(reg, sender), reg.by_id("good"), sleep=slept.append)
    return minter, slept, calls


def test_minter_waits_retry_after_on_429_then_mints(tmp_path: Path) -> None:
    minter, slept, calls = _minter_with(tmp_path, [
        ResponseRecord(429, '{"error":"mint_rate_limited"}', 1.0, retry_after=7.0),
        ResponseRecord(200, TOKEN_JSON, 3.0),
    ])
    assert minter.mint("fixture-patient-001").demo_token == "TOK-123"
    assert slept == [7.0]                 # honoured the target's Retry-After
    assert len(calls) == 2


def test_minter_caps_the_wait_and_gives_up_after_retries(tmp_path: Path) -> None:
    limited = ResponseRecord(429, '{"error":"mint_rate_limited"}', 1.0)  # no Retry-After
    minter, slept, calls = _minter_with(tmp_path, [limited, limited, ResponseRecord(429, "", 1.0, retry_after=900.0)])
    try:
        minter.mint("fixture-patient-001")
    except TargetUnreachable as exc:
        assert "rate-limited (429)" in str(exc)
    else:
        raise AssertionError("a persistent 429 must fail loudly")
    assert slept == [60.0, 60.0]          # default wait, capped at max_rate_limit_wait_s
    assert len(calls) == 3                # first try + 2 retries


def test_http_sender_parses_retry_after() -> None:
    from redteam.executor.http_sender import _retry_after
    assert _retry_after("60") == 60.0
    assert _retry_after(None) is None
    assert _retry_after("Wed, 21 Oct 2026 07:28:00 GMT") is None
    assert _retry_after("-1") is None
