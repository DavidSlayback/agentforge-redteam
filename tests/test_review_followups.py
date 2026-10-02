"""Review follow-ups: escaped dashboard output, query edge cases, unpriced cost, and the
expected-safe invariant enforced upstream of the Documentation agent."""

from __future__ import annotations

from pathlib import Path

import pytest

from redteam.agents.redteam.agent import RedTeamAgent
from redteam.observability import dashboard, queries
from redteam.store.store import Store


@pytest.fixture
def store(tmp_path: Path):
    s = Store.open(tmp_path / "s.db")
    yield s
    s.close()


def _attempt(store: Store, aid: str, campaign: str, sha: str | None, ts: str, outcome: str, cat: str = "c") -> None:
    with store.transaction():
        if not store.conn.execute("SELECT 1 FROM campaigns WHERE campaign_id=?", (campaign,)).fetchone():
            store.insert("campaigns", {"campaign_id": campaign, "target_id": "t", "status": "done", "created_at": ts})
        store.insert("attack_specs", {"spec_id": f"s-{aid}", "campaign_id": campaign, "category": cat, "created_at": ts})
        store.insert("attempts", {"attempt_id": aid, "spec_id": f"s-{aid}", "target_id": "t", "target_sha": sha, "started_at": ts})
        store.insert("verdicts", {"verdict_id": f"v-{aid}", "attempt_id": aid, "outcome": outcome, "judged_at": ts})


def _cost(store: Store, campaign: str, ts: str, calls: int, usd: float | None = None) -> None:
    with store.transaction():
        store.insert("cost_ledger", {"ts": ts, "campaign_id": campaign, "kind": "generation", "calls": calls, "usd": usd})


# 1. hostile strings are escaped everywhere the new sections render them -----------------------

def test_dashboard_escapes_hostile_sha_category_and_run_id(store: Store) -> None:
    sha, cat, run = "<img src=x onerror=1>", "<b>cat</b>", "<script>run</script>"
    _attempt(store, "a1", f"orch-{run}-1", sha, "2026-10-01T00:00:00+00:00", "SUCCESS", cat=cat)
    _cost(store, f"orch-{run}-1", "2026-10-01T00:00:01+00:00", 1)
    html = dashboard.render_html(store)
    for raw in (sha, cat, run):
        assert raw not in html
    assert "&lt;img src=x onerror=1&gt;" in html
    assert "&lt;b&gt;cat&lt;/b&gt;" in html
    assert "&lt;script&gt;run&lt;/script&gt;" in html


# 2. query edge cases ------------------------------------------------------------------------

def test_cost_by_run_first_ts_is_the_minimum_across_campaigns_regardless_of_row_order(store: Store) -> None:
    _cost(store, "orch-r1-2", "2026-10-01T05:00:00+00:00", 1)   # inserted first but later in time
    _cost(store, "orch-r1-1", "2026-10-01T01:00:00+00:00", 1)
    _cost(store, "orch-r1-1", "2026-10-01T09:00:00+00:00", 1)
    (run,) = queries.cost_by_run(store)
    assert run["first_ts"] == "2026-10-01T01:00:00+00:00" and run["campaigns"] == 2


def test_resilience_prev_rate_carries_across_a_build_with_no_decided_verdicts(store: Store) -> None:
    _attempt(store, "a1", "k", "aaa", "2026-10-01T00:00:00+00:00", "SUCCESS")
    _attempt(store, "a2", "k", "bbb", "2026-10-02T00:00:00+00:00", "INCONCLUSIVE")   # nothing decided
    _attempt(store, "a3", "k", "ccc", "2026-10-03T00:00:00+00:00", "FAIL")
    series = queries.resilience_over_time(store)
    assert [b["success_rate"] for b in series] == [1.0, None, 0.0]
    assert series[1]["trend"] is None
    assert series[2]["trend"] == "improving"      # compared with aaa, skipping the undecided build


def test_null_target_sha_is_bucketed_as_unknown(store: Store) -> None:
    _attempt(store, "a1", "k", None, "2026-10-01T00:00:00+00:00", "FAIL")
    _attempt(store, "a2", "k", "real", "2026-10-02T00:00:00+00:00", "FAIL")
    assert [b["sha"] for b in queries.resilience_over_time(store)] == ["unknown", "real"]


# 4. unpriced cost is None, not 0.0 ----------------------------------------------------------

def test_unpriced_run_has_no_usd(store: Store) -> None:
    _attempt(store, "a1", "orch-r1-1", "x", "2026-10-01T00:00:00+00:00", "FAIL")
    _cost(store, "orch-r1-1", "2026-10-01T00:00:01+00:00", 2)            # no price
    (run,) = queries.cost_by_run(store)
    assert run["usd"] is None and run["usd_per_attempt"] is None
    assert run["calls"] == 2 and run["calls_per_attempt"] == 2.0
    assert queries.cost_trend(store)[0]["usd"] is None


def test_partially_priced_run_sums_the_priced_rows(store: Store) -> None:
    _attempt(store, "a1", "orch-r1-1", "x", "2026-10-01T00:00:00+00:00", "FAIL")
    _cost(store, "orch-r1-1", "2026-10-01T00:00:01+00:00", 1, usd=0.25)
    _cost(store, "orch-r1-1", "2026-10-01T00:00:02+00:00", 1)
    (run,) = queries.cost_by_run(store)
    assert run["usd"] == pytest.approx(0.25) and run["usd_per_attempt"] == pytest.approx(0.25)


# 3. an LLM-authored case with no expected-safe invariant is rejected upstream ----------------

_CASE = ('{"case_id":"x","category":"prompt-injection","owasp":["LLM01"],"target_id":"t",'
         '"turns":[{"ordinal":1,"method":"POST","route":"/v1/x","body":{}}],'
         '"oracle":{"marker":null,"foreign_canaries":[],"latency_budget_ms":null},"expected_safe":"%s"}')


@pytest.mark.parametrize("blank", ["", "   "])
def test_agent_rejects_a_case_with_a_blank_expected_safe(blank: str) -> None:
    with pytest.raises(ValueError, match="expected_safe"):
        RedTeamAgent()._parse(_CASE % blank, "t")


def test_agent_accepts_a_case_with_an_expected_safe() -> None:
    assert RedTeamAgent()._parse(_CASE % "refuses", "t").expected_safe == "refuses"
