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

_EXPLORE_WEIGHT = 1.0    # favor (category, route) pairs tried few times
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


def _tried_by_category_route(store: Store) -> dict[tuple[str, str], int]:
    """Attempt counts per (category, route) — so coverage is route-granular: probing category C
    on route R1 does not suppress R1's sibling R2, which was never exercised (role-review T3.7)."""
    q = ("SELECT s.category AS cat, s.target_route AS route, COUNT(*) AS c "
         "FROM attempts a JOIN attack_specs s ON s.spec_id = a.spec_id "
         "GROUP BY s.category, s.target_route")
    return {(r["cat"], r["route"]): r["c"] for r in store.conn.execute(q)}


def build_candidates(
    store: Store,
    target_id: str,
    surfaces: list[str],
    categories: list[tuple[str, list[str]]],
    patient_uuid: str | None = None,
    route_fields: dict[str, str] | None = None,
) -> list[Candidate]:
    """One candidate per (category, surface), highest score first. `route_fields` maps a
    route to the request field that carries the attack payload (schema-aware shaping).

    Coverage is scored per (category, route); deterministic-only categories (authz) are excluded
    because the campaign refuses them — proposing one would burn a campaign on a guaranteed SKIP.
    """
    tried_by_cr = _tried_by_category_route(store)
    open_by_cat = _open_findings_by_category(store)
    route_fields = route_fields or {}

    candidates: list[Candidate] = []
    for category, owasp in categories:
        if is_deterministic_only(category):
            continue   # runs via `redteam authz`, never the model-driven campaign
        open_f = open_by_cat.get(category, 0)
        for route in surfaces:
            tried = tried_by_cr.get((category, route), 0)
            score = _EXPLORE_WEIGHT / (1 + tried) + _EXPLOIT_WEIGHT * open_f
            brief = {"category": category, "owasp": owasp, "target_id": target_id, "route": route}
            if patient_uuid:
                brief["patient_uuid"] = patient_uuid
            if route in route_fields:
                brief["input_field"] = route_fields[route]
            candidates.append(Candidate(brief=brief, score=score,
                                        inputs={"tried": tried, "open_findings": open_f, "route": route}))
    return sorted(candidates, key=lambda c: -c.score)
