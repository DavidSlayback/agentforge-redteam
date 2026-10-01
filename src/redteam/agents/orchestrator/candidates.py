"""Candidate campaigns and their priority scores, from system state.

The Orchestrator prioritizes by reading the store: under-tested categories get exploration
weight, categories with open findings get exploitation weight. Scores and their inputs are
returned so a selection can be audited and replayed (Q10 lineage). Weights are explicit and
live here so they can be tuned and defended.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from redteam.owasp import NEEDS_CANARY
from redteam.routing import is_deterministic_only
from redteam.store.store import Store

_EXPLORE_WEIGHT = 1.0    # favor (category, route) pairs tested few times
_EXPLOIT_WEIGHT = 0.5    # favor categories with open findings
_UNTESTED_PENALTY = 0.5  # demote a pair whose campaigns could not be tested (skip/block/error)
                         # THIS RUN, so the next pick moves on; the penalty is run-scoped and never
                         # persists (a pair that timed out in one run is not suppressed in the next,
                         # owner decision 3 — "for the rest of the RUN"). The within-run exclusion
                         # after `_EXCLUDE_AFTER_UNTESTED` retirements is the hard stop.
# The exploit term is capped strictly below the exploration gap between an untried pair
# (explore 1.0) and a once-tested pair (explore 0.5), so a category with open findings can never
# out-rank a pair that has never been tried (owner decision 2). It also decays with the tested
# campaigns run since that category's last finding, so one open finding does not pin the category.
_EXPLOIT_CAP = 0.49

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


def _tries_since_last_finding(store: Store, target_id: str) -> dict[str, int]:
    """Per category, the number of tested campaigns run (for this target) since that category's
    most recent open finding. Drives the exploit-term decay: a category keeps exploitation weight
    right after a finding, which fades as it is re-tested without a new one."""
    last = {r["cat"]: r["t"] for r in store.conn.execute(
        "SELECT primary_category AS cat, MAX(updated_at) AS t FROM findings "
        "WHERE status IN (%s) GROUP BY primary_category" % ",".join("?" * len(_OPEN_STATUSES)),
        _OPEN_STATUSES)}
    tested_ts: dict[str, list[str]] = {}
    for r in store.conn.execute(
            "SELECT json_extract(categories, '$[0]') AS cat, created_at FROM campaigns "
            "WHERE target_id = ? AND outcome = 'tested'", (target_id,)):
        tested_ts.setdefault(r["cat"], []).append(r["created_at"])
    # ISO-8601 timestamps compare lexicographically, so "> last finding" is a string comparison.
    return {cat: sum(1 for c in tested_ts.get(cat, []) if ts is None or c > ts)
            for cat, ts in last.items()}


def _tested_by_pair(store: Store, target_id: str) -> dict[tuple[str, str], int]:
    """Tested-campaign count per (category, route), from Campaign rows only.

    Coverage is the scheduled brief, not the attempt: only campaigns the Orchestrator ran write a
    Campaign row, so regression replays, the deterministic battery and eval runs never move a
    pair's score (they write attempts, not campaigns). Scoped to the target id, not the build
    (owner decision 4), and keyed on the brief's route (the ``surface`` column), so a route the
    model happened to pick for a generated case can no longer be credited (role-review T3.7).
    Only ``tested`` counts: an untested outcome from a past run must not suppress a pair forever
    (owner decision 3 scopes that to the run; see ``_UNTESTED_PENALTY`` / the Orchestrator).
    """
    q = ("SELECT json_extract(categories, '$[0]') AS cat, surface AS route, COUNT(*) AS c "
         "FROM campaigns WHERE target_id = ? AND outcome = 'tested' "
         "GROUP BY cat, route")
    return {(r["cat"], r["route"]): r["c"] for r in store.conn.execute(q, (target_id,))}


def build_candidates(
    store: Store,
    target_id: str,
    surfaces: list[str],
    categories: list[tuple[str, list[str]]],
    patient_uuid: str | None = None,
    route_fields: dict[str, str] | None = None,
    excluded: set[tuple[str, str]] | None = None,
    canaries: list[str] | None = None,
    untested_in_run: dict[tuple[str, str], int] | None = None,
) -> list[Candidate]:
    """One candidate per (category, surface), highest score first. `route_fields` maps a
    route to the request field that carries the attack payload (schema-aware shaping).

    Exploration weight comes from the pair's tested campaigns only (see `_tested_by_pair`), so a
    past run's skip/block/error never suppresses a pair again. Untested outcomes are handled
    strictly within the run: `untested_in_run` (counts seen so far in THIS run) applies a penalty
    that nudges the next pick to a sibling, and `excluded` holds pairs the run has retired after
    repeated untested outcomes (owner decision 3). Deterministic-only categories (authz) are
    excluded because the campaign refuses them — proposing one would burn a campaign on a
    guaranteed SKIP.

    Unrunnable briefs are filtered before ranking: a canary-gated category with no canary
    discovered (it would SKIP), and a route with no declared input field (not schedulable — the
    model can no longer pick the route, so a payload cannot reach the AI).
    """
    tested_by_pair = _tested_by_pair(store, target_id)
    open_by_cat = _open_findings_by_category(store)
    tries_since = _tries_since_last_finding(store, target_id)
    route_fields = route_fields or {}
    excluded = excluded or set()
    untested_in_run = untested_in_run or {}

    candidates: list[Candidate] = []
    for category, owasp in categories:
        if is_deterministic_only(category):
            continue   # runs via `redteam authz`, never the model-driven campaign
        if category in NEEDS_CANARY and not canaries:
            continue   # no planted secret to judge on -> would SKIP; not schedulable
        open_f = open_by_cat.get(category, 0)
        for route in surfaces:
            if route not in route_fields:
                continue   # no declared input field -> a payload cannot reach the AI here
            if (category, route) in excluded:
                continue   # retired for the rest of this run (repeated untested outcomes)
            tested = tested_by_pair.get((category, route), 0)
            untested = untested_in_run.get((category, route), 0)   # this run only
            exploit = 0.0
            if open_f:
                exploit = min(_EXPLOIT_WEIGHT * open_f / (1 + tries_since.get(category, 0)), _EXPLOIT_CAP)
            score = (_EXPLORE_WEIGHT / (1 + tested)
                     + exploit
                     - _UNTESTED_PENALTY * untested)
            brief = {"category": category, "owasp": owasp, "target_id": target_id, "route": route,
                     "input_field": route_fields[route]}   # guaranteed present (filtered above)
            if patient_uuid:
                brief["patient_uuid"] = patient_uuid
            candidates.append(Candidate(brief=brief, score=score,
                                        inputs={"tried": tested, "untested": untested,
                                                "open_findings": open_f, "route": route}))
    return sorted(candidates, key=lambda c: -c.score)
