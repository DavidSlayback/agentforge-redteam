"""The observability query layer — the six questions the PRD requires the platform to
answer, computed from the store (docs/HARNESS_SPEC.md P6). These are the same rows the
Orchestrator reads to prioritize and a human reads on the dashboard; there is no separate
metrics store.
"""

from __future__ import annotations

from redteam.store.store import Store

_BY_CATEGORY = """
SELECT s.category AS category, v.outcome AS outcome, COUNT(*) AS c
FROM verdicts v
JOIN attempts a ON v.attempt_id = a.attempt_id
JOIN attack_specs s ON a.spec_id = s.spec_id
GROUP BY s.category, v.outcome
"""

_BY_SHA = """
SELECT a.target_sha AS sha, v.outcome AS outcome, COUNT(*) AS c
FROM verdicts v
JOIN attempts a ON v.attempt_id = a.attempt_id
GROUP BY a.target_sha, v.outcome
"""


def cases_per_category(store: Store) -> dict[str, int]:
    return {r["category"]: r["c"] for r in store.conn.execute(
        "SELECT category, COUNT(*) AS c FROM attack_specs GROUP BY category"
    )}


def pass_fail_by_category(store: Store) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for r in store.conn.execute(_BY_CATEGORY):
        out.setdefault(r["category"], {})[r["outcome"]] = r["c"]
    return out


def outcomes_by_sha(store: Store) -> dict[str, dict[str, int]]:
    """Verdict mix per target build — the resilience trend across versions."""
    out: dict[str, dict[str, int]] = {}
    for r in store.conn.execute(_BY_SHA):
        out.setdefault(r["sha"] or "unknown", {})[r["outcome"]] = r["c"]
    return out


def findings_by_status(store: Store) -> dict[str, int]:
    return {r["status"]: r["c"] for r in store.conn.execute(
        "SELECT status, COUNT(*) AS c FROM findings GROUP BY status"
    )}


def cost_summary(store: Store) -> dict[str, float]:
    r = store.conn.execute(
        "SELECT COALESCE(SUM(usd), 0.0) AS usd, COALESCE(SUM(tokens), 0) AS tokens, "
        "COALESCE(SUM(calls), 0) AS calls FROM cost_ledger"
    ).fetchone()
    return {"usd": float(r["usd"]), "tokens": int(r["tokens"]), "calls": int(r["calls"])}


def agent_trace(store: Store, limit: int = 100) -> list[dict[str, object]]:
    return [
        {"ts": r["ts"], "agent": r["agent"], "action": r["action"], "reason": r["reason"]}
        for r in store.conn.execute(
            "SELECT ts, agent, action, reason FROM agent_actions ORDER BY id LIMIT ?", (limit,)
        )
    ]
