"""The seed-eval suite loads, is valid, and covers >=3 OWASP categories mapped to known strategies."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from redteam.evals.case import SeedCase
from redteam.evals.loader import load_case_files, load_cases, validate_committed_case
from redteam.executor.authorization import AuthorizationRegistry
from redteam.owasp import STRATEGIES

EVALS = Path(__file__).resolve().parents[1] / "evals" / "cases"
# Authz categories are executed by the deterministic track, not the OWASP-strategy campaign table.
_AUTHZ = {"broken-object-authorization", "broken-authentication", "denial-of-service",
          "enumeration", "misinformation", "information-disclosure", "data-integrity"}


def test_suite_loads_and_is_valid() -> None:
    cases = load_cases(EVALS)
    assert len(cases) >= 3, "the eval suite must hold real cases (template excluded)"
    for c in cases:
        assert c.target_id == "agentforge-w2"        # only the authorized target
        assert c.owasp, f"{c.case_id} has no OWASP mapping"
        assert c.turns, f"{c.case_id} has no turns"


def test_suite_covers_at_least_three_owasp_categories() -> None:
    cases = load_cases(EVALS)
    owasp_ids = {tag for c in cases for tag in c.owasp}
    assert len(owasp_ids) >= 3, f"need >=3 OWASP categories, got {sorted(owasp_ids)}"


def test_every_case_maps_to_a_known_category() -> None:
    for c in load_cases(EVALS):
        assert c.category in STRATEGIES or c.category in _AUTHZ, f"unknown category {c.category!r}"


def test_every_committed_case_records_its_stage3_result() -> None:
    """PRD Stage 3: each case carries observed behavior, severity, exploitability, and a regression flag."""
    for c in load_cases(EVALS):
        assert c.result is not None, f"{c.case_id} has no recorded result"
        assert c.result.observed_detail and c.result.exploitability, c.case_id
        if c.result.observed != "not_run":
            assert c.result.target_sha and c.result.run_date, f"{c.case_id} result is not tied to a build"
        if c.result.observed == "fail":
            assert c.regression, f"{c.case_id} is a confirmed exploit but not flagged for regression"


# ---------------------------------------------------------------------------------------------
# Committed-case enforcement (PRD Stage 3). `validate_committed_case` is the single gate; the
# parametrized negative tests prove each required field actually bites.
# ---------------------------------------------------------------------------------------------
REPO = Path(__file__).resolve().parents[1]


def _target_ids() -> set[str]:
    reg = AuthorizationRegistry.load(REPO / "authorization.yaml")
    return {t.id for t in reg.targets.values() if t.enabled}


def _good_raw() -> dict:
    """A fully valid committed case (raw YAML shape), independent of the real suite."""
    return {
        "case_id": "unit-good-001", "category": "denial-of-service", "subcategory": "no-rate-limit",
        "owasp": ["API4:2023", "LLM10"], "target_id": "agentforge-w2", "probe_kind": "rate_limit",
        "risk_class": "invariant",
        "turns": [{"ordinal": 1, "method": "GET", "route": "/v1/demo-context",
                   "body": {"patient_uuid": "fixture-patient-001"}}],
        "oracle": {}, "expected_safe": "requests are throttled", "regression": True,
        "result": {"observed": "pass", "observed_detail": "429 fired", "severity": "medium",
                   "exploitability": "low", "target_sha": "a" * 40, "run_date": "2026-10-01",
                   "evidence": "F-6ee92046fb"},
    }


def _problems(raw: dict) -> list[str]:
    return validate_committed_case(SeedCase.model_validate(raw), raw, _target_ids())


def test_the_good_fixture_is_valid() -> None:
    assert _problems(_good_raw()) == []


def test_every_committed_case_file_passes_the_enforcement_gate() -> None:
    entries = load_case_files(EVALS)
    assert entries
    for path, raw in entries:
        assert _problems(raw) == [], f"{path.name}: {_problems(raw)}"


def test_case_ids_are_unique() -> None:
    ids = [c.case_id for c in load_cases(EVALS)]
    assert len(ids) == len(set(ids)), f"duplicate case ids: {sorted({i for i in ids if ids.count(i) > 1})}"


def test_suite_spans_at_least_three_distinct_categories() -> None:
    assert len({c.category for c in load_cases(EVALS)}) >= 3


def _drop(*path: str):
    def mutate(raw: dict) -> None:
        node = raw
        for key in path[:-1]:
            node = node[key]
        del node[path[-1]]
    return mutate


def _set(path: tuple[str, ...], value):
    def mutate(raw: dict) -> None:
        node = raw
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = value
    return mutate


_NEGATIVES = {
    "no subcategory": _drop("subcategory"),
    "blank subcategory": _set(("subcategory",), "  "),
    "no owasp": _set(("owasp",), []),
    "unknown owasp tag": _set(("owasp",), ["LLM99"]),
    "no expected_safe": _set(("expected_safe",), ""),
    "regression flag not explicit": _drop("regression"),
    "no result": _drop("result"),
    "no severity": _drop("result", "severity"),
    "blank exploitability": _set(("result", "exploitability"), ""),
    "blank observed_detail": _set(("result", "observed_detail"), ""),
    "no risk_class": _drop("risk_class"),
    "bad risk_class": _set(("risk_class",), "vibes"),
    "unknown target": _set(("target_id",), "some-other-system"),
    "no turns": _set(("turns",), []),
    "ran but not tied to a build": _set(("result", "target_sha"), None),
    "fail not flagged for regression": lambda r: (r["result"].update(observed="fail"),
                                                  r.update(regression=False)),
    "regression with no probe/oracle to replay": lambda r: (r.pop("probe_kind"), r.update(oracle={})),
    "regression with unknown probe_kind": _set(("probe_kind",), "made-up"),
}


@pytest.mark.parametrize("name", sorted(_NEGATIVES))
def test_enforcement_bites(name: str) -> None:
    raw = copy.deepcopy(_good_raw())
    _NEGATIVES[name](raw)
    try:
        case = SeedCase.model_validate(raw)
    except Exception:
        return  # rejected by the model itself: also a loud failure
    assert validate_committed_case(case, raw, _target_ids()), f"{name!r} was not caught"


def test_not_run_result_needs_no_build() -> None:
    raw = _good_raw()
    raw["result"].update(observed="not_run", target_sha=None, run_date=None)
    assert _problems(raw) == []


def test_template_yaml_documents_every_required_field() -> None:
    data = yaml.safe_load((EVALS / "_template.yaml").read_text(encoding="utf-8"))
    for key in ("subcategory", "risk_class", "regression", "result", "expected_safe", "owasp"):
        assert key in data, f"_template.yaml does not show {key}"


def test_every_probe_kind_case_reconstructs_for_replay() -> None:
    """A committed probe_kind case carries what `reconstruct_probe` needs; building the probe does
    no I/O (the executor/judge are only used when it is run)."""
    from types import SimpleNamespace

    from redteam.authz_probe import reconstruct_probe

    target = SimpleNamespace(id="agentforge-w2", origin="https://example.invalid", base_path="")
    kinds = [c for c in load_cases(EVALS) if c.probe_kind]
    assert len(kinds) >= 7
    for c in kinds:
        probe = reconstruct_probe(c, executor=None, judge=None, target=target, minter=None)
        assert probe.case.case_id == c.case_id and probe.case.probe_kind == c.probe_kind
