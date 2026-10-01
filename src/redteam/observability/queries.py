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
    """The most recent ``limit`` agent actions, NEWEST FIRST (a long-lived store must show what
    the agents did last, not what they did first). Use ``agent_trace_chronological`` to read the
    same window in the order things happened."""
    return [
        {"ts": r["ts"], "agent": r["agent"], "action": r["action"], "reason": r["reason"]}
        for r in store.conn.execute(
            "SELECT ts, agent, action, reason FROM agent_actions ORDER BY id DESC LIMIT ?", (limit,)
        )
    ]


def agent_trace_chronological(store: Store, limit: int = 100) -> list[dict[str, object]]:
    """The same most-recent window as ``agent_trace``, oldest first -- "what each agent did and in
    what order"."""
    return list(reversed(agent_trace(store, limit)))


def _run_id(campaign_id: str | None) -> str:
    """The orchestrator run a campaign belongs to. Orchestrator campaign ids are
    ``orch-<run>-<seq>``; any other id (an ad-hoc ``run_campaign``) is its own run."""
    cid = campaign_id or "unattributed"
    if cid.startswith("orch-"):
        head, _, _seq = cid[len("orch-"):].rpartition("-")
        if head:
            return head
    return cid


def cost_by_run(store: Store) -> list[dict[str, object]]:
    """Cost per run, chronological. Calls are always metered; ``usd``/``tokens`` are only what
    the ledger recorded. No USD price is wired for the attacker model today, so ``usd`` and
    ``usd_per_attempt`` are None (unknown, not free) when no ledger row for the run carries a
    price. Rates are per ATTEMPT actually run; None when a run ran none.
    """
    runs: dict[str, dict[str, object]] = {}
    for r in store.conn.execute(
        "SELECT campaign_id, MIN(ts) AS first_ts, COALESCE(SUM(calls), 0) AS calls, "
        "COALESCE(SUM(tokens), 0) AS tokens, SUM(usd) AS usd "
        "FROM cost_ledger GROUP BY campaign_id"
    ):
        run = runs.setdefault(_run_id(r["campaign_id"]), {
            "first_ts": r["first_ts"], "campaign_ids": set(), "calls": 0, "tokens": 0, "usd": None})
        run["first_ts"] = min(run["first_ts"], r["first_ts"])
        run["campaign_ids"].add(r["campaign_id"])
        run["calls"] += int(r["calls"])
        run["tokens"] += int(r["tokens"])
        if r["usd"] is not None:
            run["usd"] = (run["usd"] or 0.0) + float(r["usd"])
    attempts_by_campaign = {
        r["campaign_id"]: int(r["c"]) for r in store.conn.execute(
            "SELECT s.campaign_id AS campaign_id, COUNT(*) AS c FROM attempts a "
            "JOIN attack_specs s ON a.spec_id = s.spec_id GROUP BY s.campaign_id")
    }
    out: list[dict[str, object]] = []
    for run_id, run in sorted(runs.items(), key=lambda kv: (kv[1]["first_ts"], kv[0])):
        cids = run.pop("campaign_ids")
        attempts = sum(attempts_by_campaign.get(c, 0) for c in cids)
        out.append({
            "run_id": run_id, "first_ts": run["first_ts"], "campaigns": len(cids), "attempts": attempts,
            "calls": run["calls"], "tokens": run["tokens"], "usd": run["usd"],
            "calls_per_attempt": run["calls"] / attempts if attempts else None,
            "usd_per_attempt": run["usd"] / attempts if attempts and run["usd"] is not None else None,
        })
    return out


def cost_trend(store: Store) -> list[dict[str, object]]:
    """The per-run cost series with a running total and the change in calls-per-attempt versus
    the previous run that had a rate -- "at what rate is cost scaling"."""
    trend: list[dict[str, object]] = []
    cumulative = 0
    prev_rate: float | None = None
    for run in cost_by_run(store):
        cumulative += int(run["calls"])
        rate = run["calls_per_attempt"]
        change = None if rate is None or prev_rate is None else rate - prev_rate
        direction = None if change is None else ("rising" if change > 0 else "falling" if change < 0 else "flat")
        trend.append({**run, "cumulative_calls": cumulative, "rate_change": change, "direction": direction})
        if rate is not None:
            prev_rate = rate
    return trend


def resilience_over_time(store: Store) -> list[dict[str, object]]:
    """Verdict mix per category for each target build, ordered by when that build was first
    attacked (earliest attempt), with the attack-success rate (SUCCESS / decided verdicts;
    INCONCLUSIVE is not a decision) and whether it improved on the previous build. Answers "is
    the target getting more or less resilient over time"."""
    builds: dict[str, dict[str, object]] = {}
    for r in store.conn.execute(
        "SELECT a.target_sha AS sha, s.category AS category, v.outcome AS outcome, "
        "MIN(a.started_at) AS first_seen, COUNT(*) AS c "
        "FROM verdicts v JOIN attempts a ON v.attempt_id = a.attempt_id "
        "JOIN attack_specs s ON a.spec_id = s.spec_id "
        "GROUP BY a.target_sha, s.category, v.outcome"
    ):
        b = builds.setdefault(r["sha"] or "unknown", {"first_seen": r["first_seen"], "categories": {}})
        b["first_seen"] = min(b["first_seen"], r["first_seen"])
        cat = b["categories"].setdefault(r["category"], {})
        cat[r["outcome"]] = cat.get(r["outcome"], 0) + int(r["c"])
    series: list[dict[str, object]] = []
    prev_rate: float | None = None
    for sha, b in sorted(builds.items(), key=lambda kv: (kv[1]["first_seen"], kv[0])):
        totals: dict[str, int] = {}
        for mix in b["categories"].values():
            for outcome, n in mix.items():
                totals[outcome] = totals.get(outcome, 0) + n
        decided = totals.get("SUCCESS", 0) + totals.get("PARTIAL", 0) + totals.get("FAIL", 0)
        rate = totals.get("SUCCESS", 0) / decided if decided else None
        trend = None
        if rate is not None and prev_rate is not None:
            trend = "worsening" if rate > prev_rate else "improving" if rate < prev_rate else "unchanged"
        series.append({"sha": sha, "first_seen": b["first_seen"], "categories": b["categories"],
                       "success_rate": rate, "trend": trend})
        if rate is not None:
            prev_rate = rate
    return series
