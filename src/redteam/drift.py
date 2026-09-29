"""Judge-drift detection — "the judge itself is validated" (P2 / ADR 0003).

The tier-0 deterministic Judge cannot drift by construction (pure functions of the Observation,
bit-identical across runs and versions). Drift matters for the LLM rubric tier: this replays a
human-labeled calibration set through the Judge and measures agreement with the labels. A drop
in agreement across versions is the drift alarm; a low absolute agreement means the judge is not
yet trustworthy for the categories it covers.

The calibration set is HUMAN-AUTHORED (labelled examples of the safe/violation boundary) — until
one exists this reports on an empty set (agreement 1.0 over 0 cases, trivially). Load labelled
cases and pass them in; `calibration_agreement` is the metric.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from redteam.agents.judge.judge import Judge
from redteam.oracles.base import Observation


@dataclass
class DriftReport:
    n: int
    agree: int
    disagreements: list[dict] = field(default_factory=list)

    @property
    def agreement_rate(self) -> float:
        return self.agree / self.n if self.n else 1.0

    @property
    def ok(self) -> bool:
        # An empty calibration set is not evidence of a validated judge — it is "not measured".
        return self.n > 0 and not self.disagreements


def calibration_agreement(judge: Judge, calibration: list[tuple[Observation, str]]) -> DriftReport:
    """Replay each labelled (Observation, expected_outcome) through the Judge and compare. Returns
    the agreement and every disagreement, so a drifting judge is caught (a case whose verdict
    changed from its human label) rather than silently trusted."""
    agree = 0
    disagreements: list[dict] = []
    for obs, expected in calibration:
        got = str(judge.judge(obs).outcome)
        if got == expected:
            agree += 1
        else:
            disagreements.append({"expected": expected, "got": got, "response": (obs.response_text or "")[:120]})
    return DriftReport(n=len(calibration), agree=agree, disagreements=disagreements)
