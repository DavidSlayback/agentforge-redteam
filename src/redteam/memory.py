"""Attack memory — what has already been tried against a target, so the Red Team learns.

The store already records every attempt and verdict; this reads them back as a compact
brief the Red Team folds into its next generation, so it varies from what already failed
instead of repeating it. This is the seed of coverage-from-state: the Orchestrator (S6)
will use the same signals to decide where to spend budget next.
"""

from __future__ import annotations

from collections import Counter

from redteam.store.store import Store

_PRIOR = """
SELECT s.spec_id AS case_id, s.turns AS turns, v.outcome AS outcome
FROM attack_specs s
JOIN attempts a ON a.spec_id = s.spec_id
JOIN verdicts v ON v.attempt_id = a.attempt_id
WHERE a.target_id = ? AND s.category = ?
ORDER BY a.rowid DESC
LIMIT ?
"""


def prior_attempts(store: Store, target_id: str, category: str, limit: int = 50) -> list[dict]:
    return [
        {"case_id": r["case_id"], "outcome": r["outcome"], "turns": r["turns"]}
        for r in store.conn.execute(_PRIOR, (target_id, category, limit))
    ]


def history_brief(store: Store, target_id: str, category: str) -> dict:
    """A compact summary for the Red Team: how much was tried here and how it went."""
    rows = prior_attempts(store, target_id, category)
    return {"tried": len(rows), "outcomes": dict(Counter(r["outcome"] for r in rows))}
