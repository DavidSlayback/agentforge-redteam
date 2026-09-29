"""Recon SHA-change poller (T3.5).

The change-detection and trigger logic is exercised through :func:`poll_once` with injected
seams, so no network or model is touched. The health-parse helper is tested against a spy
Executor to prove the poll goes through the authorization gate and reads git_sha correctly.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from redteam.recon import fetch_health_sha, poll_once
from redteam.regression import RegressionReport
from redteam.store.store import Store


def _clean() -> RegressionReport:
    return RegressionReport(target_sha="x")  # empty lists -> ok is True


def test_first_observation_is_baseline_no_trigger(tmp_path: Path) -> None:
    store = Store.open(tmp_path / "s.db")
    calls: list[str] = []
    result = poll_once(store, "t", fetch_sha=lambda: "aaaaaaaa",
                       run_regression=lambda sha: calls.append(sha) or _clean())
    assert result.changed is False and result.triggered is False
    assert calls == []                       # no regression on first-seen
    assert store.count("target_health") == 1
    assert store.count("agent_actions") == 0
    store.close()


def test_same_sha_does_not_trigger(tmp_path: Path) -> None:
    store = Store.open(tmp_path / "s.db")
    poll_once(store, "t", fetch_sha=lambda: "aaaaaaaa", run_regression=lambda sha: _clean())
    calls: list[str] = []
    result = poll_once(store, "t", fetch_sha=lambda: "aaaaaaaa",
                       run_regression=lambda sha: calls.append(sha) or _clean())
    assert result.changed is False and result.triggered is False
    assert calls == []
    assert store.count("target_health") == 2  # both observations logged
    store.close()


def test_sha_change_triggers_regression_once(tmp_path: Path) -> None:
    store = Store.open(tmp_path / "s.db")
    poll_once(store, "t", fetch_sha=lambda: "aaaaaaaa", run_regression=lambda sha: _clean())
    calls: list[str] = []
    result = poll_once(store, "t", fetch_sha=lambda: "bbbbbbbb",
                       run_regression=lambda sha: calls.append(sha) or _clean())
    assert result.changed is True and result.triggered is True
    assert calls == ["bbbbbbbb"]             # regression ran against the new build exactly once
    # the observation row is flagged changed=1
    row = store.conn.execute(
        "SELECT changed FROM target_health WHERE git_sha = 'bbbbbbbb'").fetchone()
    assert row["changed"] == 1
    # both the recon signal and the trigger are audited
    actions = [r["action"] for r in store.conn.execute(
        "SELECT action FROM agent_actions ORDER BY id").fetchall()]
    assert actions == ["target_sha_changed", "regression_triggered"]
    store.close()


def test_reappearance_makes_poll_report_attention(tmp_path: Path) -> None:
    store = Store.open(tmp_path / "s.db")
    poll_once(store, "t", fetch_sha=lambda: "aaaaaaaa", run_regression=lambda sha: _clean())
    regressed = RegressionReport(target_sha="b", reappeared=[{"case_id": "reg-1", "category": "x"}])
    result = poll_once(store, "t", fetch_sha=lambda: "bbbbbbbb", run_regression=lambda sha: regressed)
    assert result.triggered is True
    assert result.regression is not None and result.regression.ok is False
    reason = store.conn.execute(
        "SELECT reason FROM agent_actions WHERE action = 'regression_triggered'").fetchone()["reason"]
    assert "ATTENTION" in reason
    store.close()


def test_unreachable_records_and_triggers_nothing(tmp_path: Path) -> None:
    store = Store.open(tmp_path / "s.db")
    calls: list[str] = []
    result = poll_once(store, "t", fetch_sha=lambda: None,
                       run_regression=lambda sha: calls.append(sha) or _clean())
    assert result.reachable is False and result.triggered is False
    assert calls == []
    assert store.count("target_health") == 0
    store.close()


# --- health-fetch helper goes through the Executor (authorization gate) ---

@dataclass
class _Resp:
    status_code: int
    text: str
    latency_ms: float = 1.0


@dataclass
class _Target:
    origin: str = "https://target.example"
    base_path: str = "/app"


class _SpyExecutor:
    """Stands in for the Executor: records the URL and returns a canned health response."""
    def __init__(self, resp: _Resp) -> None:
        self.resp = resp
        self.seen: list[str] = []

    def request(self, url: str, /, **kwargs: object) -> _Resp:
        self.seen.append(url)
        return self.resp


def test_fetch_health_reads_git_sha_via_executor() -> None:
    ex = _SpyExecutor(_Resp(200, '{"status":"ok","git_sha":"deadbeef"}'))
    sha = fetch_health_sha(ex, _Target())
    assert sha == "deadbeef"
    assert ex.seen == ["https://target.example/app/health"]  # built + sent through the Executor


def test_fetch_health_returns_none_on_non_200_or_missing_field() -> None:
    assert fetch_health_sha(_SpyExecutor(_Resp(503, "nope")), _Target()) is None
    assert fetch_health_sha(_SpyExecutor(_Resp(200, '{"status":"ok"}')), _Target()) is None
