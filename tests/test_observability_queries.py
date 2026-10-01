"""Observability queries: newest-first trace, cost per run / trend, resilience over builds."""

from __future__ import annotations

from pathlib import Path

import pytest

from redteam.observability import dashboard, queries, report
from redteam.store.store import Store


@pytest.fixture
def store(tmp_path: Path):
    s = Store.open(tmp_path / "s.db")
    yield s
    s.close()


def _action(store: Store, i: int) -> None:
    with store.transaction():
        store.insert("agent_actions", {"ts": f"2026-10-01T00:00:{i:02d}+00:00", "agent": "a",
                                       "action": f"act{i}", "reason": "r"})


def _seed_attempt(store: Store, *, aid: str, campaign: str, cat: str, sha: str, ts: str, outcome: str) -> None:
    with store.transaction():
        if not store.conn.execute("SELECT 1 FROM campaigns WHERE campaign_id=?", (campaign,)).fetchone():
            store.insert("campaigns", {"campaign_id": campaign, "target_id": "t", "status": "done", "created_at": ts})
        store.insert("attack_specs", {"spec_id": f"s-{aid}", "campaign_id": campaign, "category": cat, "created_at": ts})
        store.insert("attempts", {"attempt_id": aid, "spec_id": f"s-{aid}", "target_id": "t", "target_sha": sha, "started_at": ts})
        store.insert("verdicts", {"verdict_id": f"v-{aid}", "attempt_id": aid, "outcome": outcome, "judged_at": ts})


def _cost(store: Store, campaign: str, ts: str, calls: int, usd: float | None = None, tokens: int | None = None) -> None:
    with store.transaction():
        store.insert("cost_ledger", {"ts": ts, "campaign_id": campaign, "kind": "generation",
                                     "calls": calls, "usd": usd, "tokens": tokens})


def test_agent_trace_is_newest_first_and_keeps_recent_actions_on_a_long_store(store: Store) -> None:
    for i in range(30):
        _action(store, i)
    trace = queries.agent_trace(store, limit=5)
    assert [a["action"] for a in trace] == ["act29", "act28", "act27", "act26", "act25"]


def test_agent_trace_chronological_is_oldest_first_among_the_recent(store: Store) -> None:
    for i in range(30):
        _action(store, i)
    trace = queries.agent_trace_chronological(store, limit=3)
    assert [a["action"] for a in trace] == ["act27", "act28", "act29"]


def test_cost_by_run_groups_orchestrator_campaigns_into_runs(store: Store) -> None:
    _seed_attempt(store, aid="a1", campaign="orch-r1-1", cat="c", sha="x", ts="2026-10-01T00:00:00+00:00", outcome="FAIL")
    _seed_attempt(store, aid="a2", campaign="orch-r1-1", cat="c", sha="x", ts="2026-10-01T00:01:00+00:00", outcome="FAIL")
    _seed_attempt(store, aid="a3", campaign="orch-r1-2", cat="c", sha="x", ts="2026-10-01T00:02:00+00:00", outcome="FAIL")
    _seed_attempt(store, aid="a4", campaign="orch-r2-1", cat="c", sha="x", ts="2026-10-02T00:00:00+00:00", outcome="FAIL")
    _cost(store, "orch-r1-1", "2026-10-01T00:00:01+00:00", 2, usd=0.10, tokens=100)
    _cost(store, "orch-r1-2", "2026-10-01T00:02:01+00:00", 1, usd=0.05, tokens=50)
    _cost(store, "orch-r2-1", "2026-10-02T00:00:01+00:00", 4, usd=0.40, tokens=400)

    runs = queries.cost_by_run(store)
    assert [r["run_id"] for r in runs] == ["r1", "r2"]          # chronological
    r1, r2 = runs
    assert (r1["campaigns"], r1["attempts"], r1["calls"], r1["tokens"]) == (2, 3, 3, 150)
    assert r1["usd"] == pytest.approx(0.15)
    assert r1["calls_per_attempt"] == pytest.approx(1.0)
    assert r2["calls_per_attempt"] == pytest.approx(4.0)
    assert r2["usd_per_attempt"] == pytest.approx(0.40)


def test_cost_by_run_has_no_rate_when_a_run_tested_nothing(store: Store) -> None:
    with store.transaction():
        store.insert("campaigns", {"campaign_id": "orch-r9-1", "target_id": "t", "status": "done", "created_at": "2026-10-01"})
    _cost(store, "orch-r9-1", "2026-10-01T00:00:00+00:00", 3)
    (r,) = queries.cost_by_run(store)
    assert r["attempts"] == 0 and r["calls_per_attempt"] is None and r["usd_per_attempt"] is None
    assert r["usd"] == 0.0   # unpriced calls are not free; usd stays 0 and calls carry the cost


def test_cost_trend_reports_cumulative_and_rate_change(store: Store) -> None:
    _seed_attempt(store, aid="a1", campaign="orch-r1-1", cat="c", sha="x", ts="2026-10-01T00:00:00+00:00", outcome="FAIL")
    _seed_attempt(store, aid="a2", campaign="orch-r2-1", cat="c", sha="x", ts="2026-10-02T00:00:00+00:00", outcome="FAIL")
    _cost(store, "orch-r1-1", "2026-10-01T00:00:01+00:00", 2)
    _cost(store, "orch-r2-1", "2026-10-02T00:00:01+00:00", 6)
    trend = queries.cost_trend(store)
    assert [t["cumulative_calls"] for t in trend] == [2, 8]
    assert trend[0]["rate_change"] is None
    assert trend[1]["rate_change"] == pytest.approx(4.0)         # calls/attempt 2 -> 6
    assert trend[1]["direction"] == "rising"


def test_resilience_over_time_orders_builds_by_first_attempt(store: Store) -> None:
    _seed_attempt(store, aid="a1", campaign="k", cat="inj", sha="bbb", ts="2026-10-02T00:00:00+00:00", outcome="FAIL")
    _seed_attempt(store, aid="a2", campaign="k", cat="inj", sha="aaa", ts="2026-10-01T00:00:00+00:00", outcome="SUCCESS")
    _seed_attempt(store, aid="a3", campaign="k", cat="inj", sha="aaa", ts="2026-10-01T01:00:00+00:00", outcome="FAIL")
    _seed_attempt(store, aid="a4", campaign="k", cat="authz", sha="bbb", ts="2026-10-02T01:00:00+00:00", outcome="FAIL")
    series = queries.resilience_over_time(store)
    assert [b["sha"] for b in series] == ["aaa", "bbb"]
    assert series[0]["first_seen"] == "2026-10-01T00:00:00+00:00"
    assert series[0]["categories"]["inj"] == {"SUCCESS": 1, "FAIL": 1}
    assert series[1]["categories"] == {"inj": {"FAIL": 1}, "authz": {"FAIL": 1}}
    assert series[0]["success_rate"] == pytest.approx(0.5)
    assert series[1]["success_rate"] == 0.0
    assert series[1]["trend"] == "improving"                     # 0.5 -> 0.0 attack success


def test_resilience_over_time_flags_worsening_and_first_build(store: Store) -> None:
    _seed_attempt(store, aid="a1", campaign="k", cat="inj", sha="aaa", ts="2026-10-01T00:00:00+00:00", outcome="FAIL")
    _seed_attempt(store, aid="a2", campaign="k", cat="inj", sha="bbb", ts="2026-10-02T00:00:00+00:00", outcome="SUCCESS")
    series = queries.resilience_over_time(store)
    assert series[0]["trend"] is None and series[1]["trend"] == "worsening"


def test_resilience_over_time_orders_by_earliest_attempt_not_by_name(store: Store) -> None:
    _seed_attempt(store, aid="a1", campaign="k", cat="c", sha="a-late", ts="2026-10-05T00:00:00+00:00", outcome="FAIL")
    _seed_attempt(store, aid="a2", campaign="k", cat="c", sha="z-early", ts="2026-10-01T00:00:00+00:00", outcome="FAIL")
    assert [b["sha"] for b in queries.resilience_over_time(store)] == ["z-early", "a-late"]


def test_report_and_dashboard_render_the_new_sections(store: Store) -> None:
    _seed_attempt(store, aid="a1", campaign="orch-r1-1", cat="inj", sha="aaa", ts="2026-10-01T00:00:00+00:00", outcome="SUCCESS")
    _seed_attempt(store, aid="a2", campaign="orch-r2-1", cat="inj", sha="bbb", ts="2026-10-02T00:00:00+00:00", outcome="FAIL")
    _cost(store, "orch-r1-1", "2026-10-01T00:00:01+00:00", 2)
    _cost(store, "orch-r2-1", "2026-10-02T00:00:01+00:00", 3)
    for i in range(3):
        _action(store, i)
    md = report.render_markdown(store)
    assert "## Cost per run" in md and "r1" in md and "r2" in md
    assert "## Resilience over time" in md and "improving" in md
    assert md.index("act2") < md.index("act0")   # newest action first
    html = dashboard.render_html(store)
    assert "Cost per run" in html and "Resilience over time" in html
    assert html.index("act2") < html.index("act0")
