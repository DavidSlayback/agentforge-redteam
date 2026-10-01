"""Guards for the closure-probe replay-fidelity mechanism (S9).

The anonymous-mint and rate-limit probes run their real request in a `produce` closure (query
params), so a faithful regression replay depends on `SeedCase.probe_kind` — `dispatch` uses it to
rebuild the exact probe. Two ways that guarantee can rot:

1. a builder stops setting `probe_kind` (then new findings freeze un-faithfully); and
2. the one-time repair that back-filled `probe_kind` onto findings frozen before the field
   existed infers the wrong kind.

These tests lock both down. The end-to-end "open -> reappeared / fixed -> held" behavior is
covered by test_regression.test_mint_finding_replays_faithfully_not_fake_green.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

from redteam.agents.judge.judge import Judge
from redteam.authz_probe import dos_probe, mint_probe, rate_limit_probe
from redteam.executor.authorization import AuthorizationRegistry
from redteam.executor.executor import Executor


def _target(tmp_path: Path):
    p = tmp_path / "auth.yaml"
    p.write_text("targets:\n  - id: good\n    origin: https://good.example\n    proof: test fixture\n    enabled: true\n", encoding="utf-8")
    reg = AuthorizationRegistry.load(p)
    return reg.by_id("good"), Executor(reg, lambda u, **k: None)


def test_every_closure_builder_sets_probe_kind(tmp_path: Path) -> None:
    """If a closure probe forgets probe_kind, its frozen finding replays through the generic path
    and can fake a green — so each builder must stamp the kind `dispatch` reconstructs from."""
    target, ex = _target(tmp_path)
    assert mint_probe(ex, Judge(), target, "p", endpoint="/v1/demo-context").case.probe_kind == "mint"
    assert mint_probe(ex, Judge(), target, "p", endpoint="/v1/source-document-context").case.probe_kind == "mint"
    assert rate_limit_probe(ex, Judge(), target, "p").case.probe_kind == "rate_limit"
    assert dos_probe(ex, Judge(), None, target, "p").case.probe_kind == "dos"


# --- the one-time back-fill repair infers the same kinds the builders stamp ---

_repair_path = Path(__file__).resolve().parents[1] / "scripts" / "repair_probe_kind.py"
_spec = importlib.util.spec_from_file_location("repair_probe_kind", _repair_path)
_repair = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_repair)


def _case(category: str, route: str, body: dict) -> dict:
    return {"category": category, "turns": [{"ordinal": 1, "route": route, "body": body}]}


def test_repair_infers_the_builders_kinds() -> None:
    infer = _repair.infer_probe_kind
    assert infer(_case("broken-authentication", "/v1/demo-context", {"patient_uuid": "p"})) == "mint"
    assert infer(_case("broken-authentication", "/v1/source-document-context", {"patient_uuid": "p"})) == "mint"
    assert infer(_case("denial-of-service", "/v1/demo-context", {"patient_uuid": "p", "_count": 20})) == "rate_limit"
    assert infer(_case("denial-of-service", "/v1/follow-up-evidence", {"message_len": 200000})) == "dos"


def test_repair_leaves_non_closure_cases_null() -> None:
    infer = _repair.infer_probe_kind
    # a BOLA turn probe is a legitimate generic authz case — it must NOT be mislabeled a mint
    assert infer(_case("broken-object-authorization", "/v1/follow-up-evidence", {"patient_uuid": "victim"})) is None
    assert infer(_case("prompt-injection", "/v1/follow-up-evidence", {"message": "x"})) is None
