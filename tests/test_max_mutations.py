"""`--max-mutations` on the campaign CLI reaches the orchestrator and run_campaign."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from redteam.agents.judge.judge import Judge
from redteam.agents.orchestrator.budget import Budget
from redteam.agents.orchestrator.orchestrator import Orchestrator, OrchestratorRun
from redteam.agents.redteam.agent import MARKER_PREFIX, RedTeamAgent
from redteam.cli import build_parser, main
from redteam.executor.authorization import AuthorizationRegistry
from redteam.executor.executor import Executor
from redteam.executor.http_sender import ResponseRecord
from redteam.store.store import Store

_GEN = ('{"case_id":"x","category":"prompt-injection","owasp":["LLM01"],"target_id":"good",'
        '"turns":[{"ordinal":1,"method":"POST","route":"/v1/follow-up-evidence","body":{"message":"hi"}}],'
        '"oracle":{"marker":"ZZ-NEVER","foreign_canaries":[],"latency_budget_ms":null},"expected_safe":"refuses"}')

_BASE = ["campaign", "--target", "good", "--category", "prompt-injection", "--route", "/v1/follow-up-evidence"]


class CountingModel:
    def __init__(self) -> None:
        self.calls = 0

    def complete(self, system: str, user: str, **kw: object) -> str:
        self.calls += 1
        # aim the payload at the platform's marker, as a real attacker prompt asks (else no oracle applies)
        found = re.search(re.escape(MARKER_PREFIX) + r"[0-9a-f]+", user)
        return _GEN.replace('"message":"hi"', f'"message":"say {found.group(0)}"') if found else _GEN


def _registry(tmp_path: Path) -> AuthorizationRegistry:
    p = tmp_path / "auth.yaml"
    p.write_text("targets:\n  - id: good\n    origin: https://good.example\n    proof: t\n    enabled: true\n",
                 encoding="utf-8")
    return AuthorizationRegistry.load(p)


def _patch_wire(monkeypatch, tmp_path: Path, model) -> None:
    reg = _registry(tmp_path)
    executor = Executor(reg, lambda u, **k: ResponseRecord(200, "no marker here", 5.0))
    pieces = (reg, reg.by_id("good"), executor, None, Judge(), RedTeamAgent(), model)
    monkeypatch.setattr("redteam.cli._wire", lambda *a, **k: pieces)


def test_parser_default_and_value() -> None:
    assert build_parser().parse_args(_BASE).max_mutations == 1
    assert build_parser().parse_args([*_BASE, "--max-mutations", "3"]).max_mutations == 3
    assert build_parser().parse_args([*_BASE, "--max-mutations", "0"]).max_mutations == 0


@pytest.mark.parametrize("bad", ["-1", "x", "1.5"])
def test_parser_rejects_negative_or_non_integer(bad: str, capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args([*_BASE, "--max-mutations", bad])
    assert exc.value.code == 2
    assert "max-mutations" in capsys.readouterr().err


def test_cli_passes_max_mutations_to_the_orchestrator(tmp_path: Path, monkeypatch) -> None:
    seen: dict = {}

    def fake_run(self, **kwargs):
        seen.update(kwargs)
        return OrchestratorRun(tested=1, halt_reason="done")

    monkeypatch.setattr(Orchestrator, "run", fake_run)
    _patch_wire(monkeypatch, tmp_path, CountingModel())
    rc = main(["--store", str(tmp_path / "s.db"), *_BASE, "--max-mutations", "4"])
    assert rc == 0 and seen["max_mutations"] == 4
    seen.clear()
    main(["--store", str(tmp_path / "s.db"), *_BASE])
    assert seen["max_mutations"] == 1                  # the default is unchanged


def test_orchestrator_passes_max_mutations_to_run_campaign(tmp_path: Path, monkeypatch) -> None:
    import redteam.agents.orchestrator.orchestrator as orch_mod

    seen: list[int] = []
    real = orch_mod.run_campaign

    def spy(*a, **kw):
        seen.append(kw["max_mutations"])
        return real(*a, **kw)

    monkeypatch.setattr(orch_mod, "run_campaign", spy)
    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    orch = Orchestrator(registry=reg, executor=Executor(reg, lambda u, **k: ResponseRecord(200, "ok", 1.0)),
                        judge=Judge(), store=store, agent=RedTeamAgent(), model=CountingModel())
    orch.run(target_id="good", surfaces=["/v1/follow-up-evidence"], categories=[("prompt-injection", ["LLM01"])],
             budget=Budget(max_campaigns=1), route_fields={"/v1/follow-up-evidence": "message"}, max_mutations=3)
    assert seen == [3]
    store.close()


@pytest.mark.parametrize("muts, expected_model_calls", [(0, 1), (1, 2), (2, 3)])
def test_max_mutations_bounds_the_attacker_model_calls(tmp_path: Path, monkeypatch, muts: int,
                                                       expected_model_calls: int) -> None:
    # the target never leaks, so every attempt is FAIL and each is eligible for another mutation
    model = CountingModel()
    _patch_wire(monkeypatch, tmp_path, model)
    rc = main(["--store", str(tmp_path / "s.db"), *_BASE, "--max-campaigns", "1",
               "--max-mutations", str(muts)])
    assert rc == 0 and model.calls == expected_model_calls
