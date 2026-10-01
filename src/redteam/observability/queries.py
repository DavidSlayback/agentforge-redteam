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


def queue_depth(store: Store) -> dict[str, int]:
    """Pending work in the store's queues (E10 queue-depth monitoring): campaigns not yet run and
    reports awaiting the human approval gate. A growing depth means the platform is accruing work
    faster than it is draining — the signal an operator or autoscaler watches."""
    campaigns = store.conn.execute(
        "SELECT COUNT(*) AS c FROM campaigns WHERE status = 'new'"
    ).fetchone()["c"]
    pending_reports = store.conn.execute(
        "SELECT COUNT(*) AS c FROM vuln_reports WHERE status = 'pending_approval'"
    ).fetchone()["c"]
    return {"campaigns_pending": int(campaigns), "reports_pending_approval": int(pending_reports)}


def cost_summary(store: Store) -> dict[str, float]:
    r = store.conn.execute(
        "SELECT COALESCE(SUM(usd), 0.0) AS usd, COALESCE(SUM(tokens), 0) AS tokens, "
        "COALESCE(SUM(calls), 0) AS calls FROM cost_ledger"
    ).fetchone()
    return {"usd": float(r["usd"]), "tokens": int(r["tokens"]), "calls": int(r["calls"])}


def owasp_coverage(store: Store) -> dict[str, dict[str, int]]:
    """Verdict mix per OWASP tag — which taxonomy categories have been exercised (E1).

    A spec may carry several tags; each is counted. Tags come from `attack_specs.owasp`
    (json). Specs with no verdict yet are omitted.
    """
    import json

    out: dict[str, dict[str, int]] = {}
    rows = store.conn.execute(
        "SELECT s.owasp AS owasp, v.outcome AS outcome, COUNT(*) AS c "
        "FROM verdicts v JOIN attempts a ON v.attempt_id = a.attempt_id "
        "JOIN attack_specs s ON a.spec_id = s.spec_id "
        "WHERE s.owasp IS NOT NULL GROUP BY s.owasp, v.outcome"
    )
    for r in rows:
        try:
            tags = json.loads(r["owasp"]) or []
        except (ValueError, TypeError):
            tags = []
        for tag in tags:
            out.setdefault(tag, {})
            out[tag][r["outcome"]] = out[tag].get(r["outcome"], 0) + r["c"]
    return out


def agent_trace(store: Store, limit: int = 100) -> list[dict[str, object]]:
    return [
        {"ts": r["ts"], "agent": r["agent"], "action": r["action"], "reason": r["reason"]}
        for r in store.conn.execute(
            "SELECT ts, agent, action, reason FROM agent_actions ORDER BY id LIMIT ?", (limit,)
        )
    ]
