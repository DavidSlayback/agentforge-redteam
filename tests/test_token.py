"""Token minting caches, mints through the Executor, and the runner injects the token."""

from __future__ import annotations

import json
from pathlib import Path

from redteam.agents.judge.judge import Judge
from redteam.evals.case import AuthContext, OracleConfig, SeedCase, Turn
from redteam.executor.authorization import AuthorizationRegistry
from redteam.executor.executor import Executor
from redteam.executor.http_sender import ResponseRecord
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
        "    base_path: /app\n    enabled: true\n",
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
