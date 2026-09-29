"""The seed-eval suite loads, is valid, and covers >=3 OWASP categories mapped to known strategies."""

from __future__ import annotations

from pathlib import Path

from redteam.evals.loader import load_cases
from redteam.owasp import STRATEGIES

EVALS = Path(__file__).resolve().parents[1] / "evals" / "cases"
# Authz categories are executed by the deterministic track, not the OWASP-strategy campaign table.
_AUTHZ = {"broken-object-authorization", "broken-authentication", "denial-of-service"}


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
