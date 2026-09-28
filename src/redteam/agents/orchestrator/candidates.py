"""Candidate campaigns and their priority scores, from system state.

The Orchestrator prioritizes by reading the store: under-tested categories get exploration
weight, categories with open findings get exploitation weight. Scores and their inputs are
returned so a selection can be audited and replayed (Q10 lineage). Weights are explicit and
live here so they can be tuned and defended.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from redteam.observability.queries import pass_fail_by_category
from redteam.store.store import Store

_EXPLORE_WEIGHT = 1.0    # favor categories tried few times
_EXPLOIT_WEIGHT = 0.5    # favor categories with open findings

_OPEN_STATUSES = ("new", "confirmed", "retested")


@dataclass(frozen=True)
class Candidate:
    brief: dict
    score: float
    inputs: dict = field(default_factory=dict)


def _open_findings_by_category(store: Store) -> dict[str, int]:
    q = "SELECT primary_category AS cat, COUNT(*) AS c FROM findings WHERE status IN (%s) GROUP BY primary_category" % (
        ",".join("?" * len(_OPEN_STATUSES))
    )
    return {r["cat"]: r["c"] for r in store.conn.execute(q, _OPEN_STATUSES)}


def build_candidates(
    store: Store,
    target_id: str,
    surfaces: list[str],
    categories: list[tuple[str, list[str]]],
    patient_uuid: str | None = None,
) -> list[Candidate]:
    """One candidate per (category, surface), highest score first."""
    tried_by_cat = {cat: sum(mix.values()) for cat, mix in pass_fail_by_category(store).items()}
    open_by_cat = _open_findings_by_category(store)

    candidates: list[Candidate] = []
    for category, owasp in categories:
        tried = tried_by_cat.get(category, 0)
        open_f = open_by_cat.get(category, 0)
        score = _EXPLORE_WEIGHT / (1 + tried) + _EXPLOIT_WEIGHT * open_f
        for route in surfaces:
            brief = {"category": category, "owasp": owasp, "target_id": target_id, "route": route}
            if patient_uuid:
                brief["patient_uuid"] = patient_uuid
            candidates.append(Candidate(brief=brief, score=score, inputs={"tried": tried, "open_findings": open_f}))
    return sorted(candidates, key=lambda c: -c.score)
