"""Candidate campaigns and their priority scores, from system state.

The Orchestrator prioritizes by reading the store: under-tested categories get exploration
weight, categories with open findings get exploitation weight. Scores and their inputs are
returned so a selection can be audited and replayed (Q10 lineage). Weights are explicit and
live here so they can be tuned and defended.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from redteam.routing import is_deterministic_only
from redteam.store.store import Store

_EXPLORE_WEIGHT = 1.0    # favor (category, route) pairs tested few times
_EXPLOIT_WEIGHT = 0.5    # favor categories with open findings
_UNTESTED_PENALTY = 0.5  # demote a pair whose campaigns could not be tested (skip/block/error),
                         # so a stuck brief stops winning without being counted as covered

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


def _campaign_coverage(store: Store, target_id: str) -> dict[tuple[str, str], dict[str, int]]:
    """Tested/untested campaign counts per (category, route), from Campaign rows only.

    Coverage is the scheduled brief, not the attempt: only campaigns the Orchestrator ran write a
    Campaign row, so regression replays, the deterministic battery and eval runs never move a
    pair's score (they write attempts, not campaigns). Scoped to the target id, not the build
    (owner decision 4), and keyed on the brief's route (the ``surface`` column), so a route the
    model happened to pick for a generated case can no longer be credited (role-review T3.7).
    """
    q = ("SELECT json_extract(categories, '$[0]') AS cat, surface AS route, outcome, COUNT(*) AS c "
         "FROM campaigns WHERE target_id = ? AND outcome IS NOT NULL "
         "GROUP BY cat, route, outcome")
    cov: dict[tuple[str, str], dict[str, int]] = {}
    for r in store.conn.execute(q, (target_id,)):
        bucket = cov.setdefault((r["cat"], r["route"]), {"tested": 0, "untested": 0})
        bucket["tested" if r["outcome"] == "tested" else "untested"] += r["c"]
    return cov


def build_candidates(
    store: Store,
    target_id: str,
    surfaces: list[str],
    categories: list[tuple[str, list[str]]],
    patient_uuid: str | None = None,
    route_fields: dict[str, str] | None = None,
    excluded: set[tuple[str, str]] | None = None,
) -> list[Candidate]:
    """One candidate per (category, surface), highest score first. `route_fields` maps a
    route to the request field that carries the attack payload (schema-aware shaping).

    Coverage is scored per (category, route) from campaign-made records only (see
    `_campaign_coverage`). A pair's tested campaigns lower its exploration weight; its untested
    campaigns (skip/block/error) apply a separate penalty so a stuck brief stops winning without
    being counted as covered. Deterministic-only categories (authz) are excluded because the
    campaign refuses them — proposing one would burn a campaign on a guaranteed SKIP. `excluded`
    is the set of (category, route) pairs the current run has retired after repeated untested
    outcomes (owner decision 3); they are not offered again.
    """
    cov = _campaign_coverage(store, target_id)
    open_by_cat = _open_findings_by_category(store)
    route_fields = route_fields or {}
    excluded = excluded or set()

    candidates: list[Candidate] = []
    for category, owasp in categories:
        if is_deterministic_only(category):
            continue   # runs via `redteam authz`, never the model-driven campaign
        open_f = open_by_cat.get(category, 0)
        for route in surfaces:
            if (category, route) in excluded:
                continue   # retired for the rest of this run (repeated untested outcomes)
            counts = cov.get((category, route), {"tested": 0, "untested": 0})
            tested, untested = counts["tested"], counts["untested"]
            score = (_EXPLORE_WEIGHT / (1 + tested)
                     + _EXPLOIT_WEIGHT * open_f
                     - _UNTESTED_PENALTY * untested)
            brief = {"category": category, "owasp": owasp, "target_id": target_id, "route": route}
            if patient_uuid:
                brief["patient_uuid"] = patient_uuid
            if route in route_fields:
                brief["input_field"] = route_fields[route]
            candidates.append(Candidate(brief=brief, score=score,
                                        inputs={"tried": tested, "untested": untested,
                                                "open_findings": open_f, "route": route}))
    return sorted(candidates, key=lambda c: -c.score)
