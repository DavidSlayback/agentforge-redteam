"""Judge-drift detection — "the judge itself is validated" (P2 / ADR 0003, KEY_METRICS #5).

The tier-0 deterministic Judge cannot drift by construction (pure functions of the Observation,
bit-identical across runs and versions). Drift matters for the LLM rubric tier: this replays a
human-labeled calibration set through the Judge and measures agreement with the labels — raw
agreement and Cohen's κ (chance-corrected). A drop in agreement across versions is the drift
alarm; a low absolute agreement means the judge is not yet trustworthy for the categories it
covers. Deterministic entries are still worth calibrating: they test that the oracle definitions
match human intent (a disagreement there is a mis-specified oracle, not drift).

The calibration set is HUMAN-AUTHORED (labelled examples of the safe/violation boundary). The
set file declares its own ``review_status``; a run is only ever reported as *validated* when the
labels are ``human-reviewed``, the set is non-empty, and the Judge agrees on every measured entry.
Anything else — an empty set, unreviewed/draft labels, rubric entries skipped because no rubric
model is configured — is reported as exactly that, never as a validated judge.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel

from redteam.agents.judge.judge import Judge
from redteam.oracles.base import Observation


@dataclass
class DriftReport:
    n: int
    agree: int
    disagreements: list[dict] = field(default_factory=list)
    pairs: list[tuple[str, str]] = field(default_factory=list)   # (expected, got) per entry

    @property
    def agreement_rate(self) -> float:
        return self.agree / self.n if self.n else 1.0

    @property
    def kappa(self) -> float | None:
        """Cohen's κ between the human labels and the Judge. ``None`` when undefined (no entries,
        or both sides use a single identical label so chance agreement is 1)."""
        return cohens_kappa(self.pairs)

    @property
    def ok(self) -> bool:
        # An empty calibration set is not evidence of a validated judge — it is "not measured".
        return self.n > 0 and not self.disagreements


def cohens_kappa(pairs: list[tuple[str, str]]) -> float | None:
    """κ = (p_o − p_e) / (1 − p_e) over (label, verdict) pairs."""
    n = len(pairs)
    if n == 0:
        return None
    p_o = sum(1 for a, b in pairs if a == b) / n
    left = Counter(a for a, _ in pairs)
    right = Counter(b for _, b in pairs)
    p_e = sum((left[c] / n) * (right[c] / n) for c in set(left) | set(right))
    if p_e >= 1.0:
        return None
    return (p_o - p_e) / (1 - p_e)


def calibration_agreement(judge: Judge, calibration: list[tuple[Observation, str]]) -> DriftReport:
    """Replay each labelled (Observation, expected_outcome) through the Judge and compare. Returns
    the agreement and every disagreement, so a drifting judge is caught (a case whose verdict
    changed from its human label) rather than silently trusted."""
    agree = 0
    disagreements: list[dict] = []
    pairs: list[tuple[str, str]] = []
    for obs, expected in calibration:
        got = str(judge.judge(obs).outcome)
        pairs.append((expected, got))
        if got == expected:
            agree += 1
        else:
            disagreements.append({"expected": expected, "got": got, "response": (obs.response_text or "")[:120]})
    return DriftReport(n=len(calibration), agree=agree, disagreements=disagreements, pairs=pairs)


# --- calibration set file format ---------------------------------------------------------

class CalibrationEntry(BaseModel):
    entry_id: str
    tier: Literal["deterministic", "rubric"]   # which Judge tier the entry exercises
    label: Literal["SUCCESS", "PARTIAL", "FAIL", "INCONCLUSIVE"]   # the human's verdict
    rationale: str                              # why the human chose that label
    observation: dict                           # Observation fields (see oracles/base.py)


class CalibrationSet(BaseModel):
    version: str
    labeled_by: str
    review_status: Literal["unreviewed", "human-reviewed"]
    entries: list[CalibrationEntry]


_SET_FIELDS = {"foreign_canaries", "patient_ids_in_response"}


def to_observation(fields: dict) -> Observation:
    """Build an Observation from YAML fields (lists → the frozenset/tuple types it expects).
    Unknown fields raise, so a typo cannot silently drop evidence from a calibration entry."""
    data = dict(fields)
    for key in _SET_FIELDS & data.keys():
        data[key] = frozenset(data[key])
    if "provider_events" in data:
        data["provider_events"] = tuple(data["provider_events"])
    return Observation(**data)


def load_calibration(path: str | Path) -> CalibrationSet:
    cset = CalibrationSet.model_validate(yaml.safe_load(Path(path).read_text(encoding="utf-8")))
    ids = [e.entry_id for e in cset.entries]
    if len(ids) != len(set(ids)):
        raise ValueError(f"duplicate entry_id in calibration set {path}")
    for e in cset.entries:
        to_observation(e.observation)   # validate every entry up front
    return cset


@dataclass
class CalibrationRun:
    set_version: str
    review_status: str
    report: DriftReport
    skipped: list[str] = field(default_factory=list)   # rubric entries with no rubric configured

    @property
    def validated(self) -> bool:
        return self.review_status == "human-reviewed" and not self.skipped and self.report.ok

    @property
    def status(self) -> str:
        if self.report.n == 0:
            return "NOT MEASURED (empty calibration set)"
        if self.review_status != "human-reviewed":
            return "NOT VALIDATED (labels not human-reviewed)"
        if self.skipped:
            return f"NOT VALIDATED ({len(self.skipped)} rubric entries skipped: no rubric model configured)"
        if self.report.disagreements:
            return f"NOT VALIDATED ({len(self.report.disagreements)} disagreement(s) with human labels)"
        return "VALIDATED"


def run_calibration(judge: Judge, cset: CalibrationSet) -> CalibrationRun:
    """Score the Judge against the set. Rubric entries are skipped (and reported) when the Judge
    has no available rubric tier — scoring them would just measure the INCONCLUSIVE fallback."""
    rubric_on = judge.rubric is not None and getattr(judge.rubric, "available", False)
    skipped: list[str] = []
    pairs: list[tuple[Observation, str]] = []
    for e in cset.entries:
        if e.tier == "rubric" and not rubric_on:
            skipped.append(e.entry_id)
            continue
        pairs.append((to_observation(e.observation), e.label))
    return CalibrationRun(cset.version, cset.review_status, calibration_agreement(judge, pairs), skipped)
