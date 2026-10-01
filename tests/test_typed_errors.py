"""Typed errors: each is either raised at a real failure site (and tested there) or explicitly
marked RESERVED. This test keeps the two sets from drifting apart silently."""

from __future__ import annotations

import inspect
import json
import re
from pathlib import Path

import httpx
import pytest

import redteam.errors as errors_mod
from redteam.agents.judge.judge import VerdictOutcome
from redteam.agents.judge.rubric import ModelRubric
from redteam.errors import JudgeTimeout, RedteamError, RegressionDetected
from redteam.oracles.base import Observation
from redteam.regression import RegressionReport

SRC = Path(__file__).resolve().parents[1] / "src" / "redteam"
SCHEMA = Path(__file__).resolve().parents[1] / "contracts" / "v1" / "error.schema.json"

# Published in the contract but with no honest failure site today (nothing asks the platform for a
# findings window). Adding a raise site means moving the class out of this set AND its docstring.
RESERVED = {"NoFindingsInWindow"}


def _error_classes() -> list[type[RedteamError]]:
    return [c for _, c in inspect.getmembers(errors_mod, inspect.isclass)
            if issubclass(c, RedteamError) and c is not RedteamError]


def test_reserved_set_matches_the_docstring_markers() -> None:
    marked = {c.__name__ for c in _error_classes() if "RESERVED:" in (c.__doc__ or "")}
    assert marked == RESERVED


def test_every_non_reserved_error_is_raised_in_src_and_reserved_ones_are_not() -> None:
    text = "\n".join(p.read_text(encoding="utf-8") for p in SRC.rglob("*.py") if p.name != "errors.py")
    for cls in _error_classes():
        raised = re.search(rf"raise\s+{cls.__name__}\b", text) is not None
        if cls.__name__ in RESERVED:
            assert not raised, f"{cls.__name__} is raised now: drop it from RESERVED and its docstring"
        else:
            assert raised, f"{cls.__name__} is neither raised in src/ nor marked RESERVED"


def test_reserved_docstring_names_the_contract() -> None:
    for cls in _error_classes():
        if cls.__name__ in RESERVED:
            assert "/contracts/v1/error.schema.json" in cls.__doc__


def test_every_class_code_is_in_the_published_schema() -> None:
    enum = set(json.loads(SCHEMA.read_text(encoding="utf-8"))["properties"]["code"]["enum"])
    assert {c.code for c in _error_classes()} == enum


# --- JudgeTimeout: the rubric model timing out -> INCONCLUSIVE, never a pass ------------------

def _rubric() -> ModelRubric:
    return ModelRubric(base_url="https://judge.example/v1", api_key="k", model="deepseek-x")


def test_rubric_timeout_becomes_an_inconclusive_verdict_naming_judge_timeout(monkeypatch) -> None:
    def slow(*a, **k):
        raise httpx.ReadTimeout("slow")

    monkeypatch.setattr("redteam.agents.judge.rubric.httpx.post", slow)
    v = _rubric().evaluate(Observation(status_code=200, response_text='{"answer":"x"}'))
    assert v.outcome is VerdictOutcome.INCONCLUSIVE
    assert JudgeTimeout.code in v.reason


def test_rubric_timeout_is_raised_as_judge_timeout_internally(monkeypatch) -> None:
    def slow(*a, **k):
        raise httpx.ConnectTimeout("slow")

    monkeypatch.setattr("redteam.agents.judge.rubric.httpx.post", slow)
    with pytest.raises(JudgeTimeout):
        _rubric()._complete(Observation(status_code=200, response_text="x"))


def test_rubric_non_timeout_http_error_is_not_labelled_a_timeout(monkeypatch) -> None:
    def refused(*a, **k):
        raise httpx.ConnectError("refused")

    monkeypatch.setattr("redteam.agents.judge.rubric.httpx.post", refused)
    v = _rubric().evaluate(Observation(status_code=200, response_text="x"))
    assert v.outcome is VerdictOutcome.INCONCLUSIVE and JudgeTimeout.code not in v.reason


# --- RegressionDetected: a reappearance is surfaced as a typed error --------------------------

def test_regression_report_raises_typed_error_on_reappearance() -> None:
    r = RegressionReport(target_sha="abc")
    r.reappeared.append({"case_id": "reg-1", "category": "prompt-injection"})
    with pytest.raises(RegressionDetected) as exc:
        r.raise_if_regressed()
    assert exc.value.code == "regression_detected"
    assert exc.value.reappeared == [{"case_id": "reg-1", "category": "prompt-injection"}]
    assert "reg-1" in str(exc.value) and "abc" in str(exc.value)


def test_regression_report_with_no_reappearance_does_not_raise() -> None:
    r = RegressionReport(target_sha="abc")
    r.held.append("reg-1")
    r.inconclusive.append("reg-2")   # unverified is not a reappearance; `ok` already fails it
    r.raise_if_regressed()
