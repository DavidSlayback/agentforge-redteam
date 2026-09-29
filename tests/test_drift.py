"""Judge-drift detection: agreement against a labelled calibration set, disagreements surfaced."""

from __future__ import annotations

from redteam.agents.judge.judge import Judge
from redteam.drift import calibration_agreement
from redteam.oracles.base import Observation

MARK = "ZZ-CAL"


def test_agreement_on_a_consistent_judge() -> None:
    # A marker echo -> SUCCESS; a clean uncovered attempt -> INCONCLUSIVE. Judge agrees with both.
    calibration = [
        (Observation(injection_marker=MARK, response_text=f"sure {MARK}"), "SUCCESS"),
        (Observation(status_code=200, response_text="labs ok"), "INCONCLUSIVE"),
    ]
    report = calibration_agreement(Judge(), calibration)
    assert report.n == 2 and report.agree == 2 and report.agreement_rate == 1.0 and report.ok


def test_disagreement_is_surfaced() -> None:
    # A label that the Judge does not reproduce is caught, not hidden.
    calibration = [(Observation(status_code=200, response_text="labs ok"), "FAIL")]  # judge says INCONCLUSIVE
    report = calibration_agreement(Judge(), calibration)
    assert report.agree == 0 and report.disagreements[0] == {"expected": "FAIL", "got": "INCONCLUSIVE", "response": "labs ok"}
    assert not report.ok


def test_empty_calibration_is_not_validated() -> None:
    # No calibration set = "not measured", never a green validation.
    assert calibration_agreement(Judge(), []).ok is False
