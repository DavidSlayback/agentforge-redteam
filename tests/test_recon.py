"""Recon SHA-change poller (T3.5).

The change-detection, trigger, and crash-safety logic is exercised through :func:`poll_once`
with injected seams, so no network or model is touched. :func:`observe_health` is tested against
the real Executor to prove the poll passes the authorization gate, and :func:`poll_summary`'s
exit-code contract (what a cron job alerts on) is tested directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from redteam.executor.authorization import AuthorizationDenied
from redteam.executor.executor import Executor
from redteam.recon import (
    HealthObservation,
    PollResult,
    observe_health,
    poll_once,
    poll_summary,
)
from redteam.regression import RegressionReport
from redteam.store.store import Store


def _clean() -> RegressionReport:
    return RegressionReport(target_sha="x")  # empty lists -> ok is True


def _ok(sha: str) -> HealthObservation:
    return HealthObservation(reachable=True, git_sha=sha, status_code=200, note="ok")


# --- baseline / no-change ---

def test_first_observation_is_baseline_no_trigger(tmp_path: Path) -> None:
    store = Store.open(tmp_path / "s.db")
    calls: list[str] = []
    result = poll_once(store, "t", observe=lambda: _ok("aaaaaaaa"),
                       run_regression=lambda sha: calls.append(sha) or _clean())
    assert result.changed is False and result.triggered is False
    assert calls == []                       # no regression on first-seen
    assert store.count("target_health") == 1
    assert store.count("agent_actions") == 0
    store.close()


def test_same_sha_does_not_trigger(tmp_path: Path) -> None:
    store = Store.open(tmp_path / "s.db")
    poll_once(store, "t", observe=lambda: _ok("aaaaaaaa"), run_regression=lambda sha: _clean())
    calls: list[str] = []
    result = poll_once(store, "t", observe=lambda: _ok("aaaaaaaa"),
                       run_regression=lambda sha: calls.append(sha) or _clean())
    assert result.changed is False and result.triggered is False
    assert calls == []
    assert store.count("target_health") == 2  # both observations logged
    store.close()


# --- change triggers exactly once, in order, advancing the baseline last ---

def test_sha_change_triggers_regression_once(tmp_path: Path) -> None:
    store = Store.open(tmp_path / "s.db")
    poll_once(store, "t", observe=lambda: _ok("aaaaaaaa"), run_regression=lambda sha: _clean())
    calls: list[str] = []
    result = poll_once(store, "t", observe=lambda: _ok("bbbbbbbb"),
                       run_regression=lambda sha: calls.append(sha) or _clean())
    assert result.changed is True and result.triggered is True
    assert calls == ["bbbbbbbb"]             # regression ran against the new build exactly once
    row = store.conn.execute(
        "SELECT changed FROM target_health WHERE git_sha = 'bbbbbbbb'").fetchone()
    assert row["changed"] == 1               # baseline advanced (observation recorded)
    actions = [r["action"] for r in store.conn.execute(
        "SELECT action FROM agent_actions ORDER BY id").fetchall()]
    assert actions == ["target_sha_changed", "regression_triggered"]
    store.close()


def test_regression_crash_does_not_advance_baseline_or_lose_trigger(tmp_path: Path) -> None:
    """Integrity (review #1): if the regression raises mid-run, the new SHA must NOT become the
    baseline — otherwise the next poll sees no change and the build reads green unverified."""
    store = Store.open(tmp_path / "s.db")
    poll_once(store, "t", observe=lambda: _ok("aaaaaaaa"), run_regression=lambda sha: _clean())

    def boom(sha: str) -> RegressionReport:
        raise RuntimeError("dispatch blew up mid-replay")

    with pytest.raises(RuntimeError):
        poll_once(store, "t", observe=lambda: _ok("bbbbbbbb"), run_regression=boom)

    # baseline still 'aaaaaaaa'; no bbbbbbbb observation, no orphan trigger audit rows
    assert store.count("target_health") == 1
    assert store.conn.execute("SELECT git_sha FROM target_health ORDER BY id DESC LIMIT 1").fetchone()["git_sha"] == "aaaaaaaa"
    assert store.count("agent_actions") == 0

    # the very next poll re-detects the change and retries the regression (nothing was lost)
    calls: list[str] = []
    result = poll_once(store, "t", observe=lambda: _ok("bbbbbbbb"),
                       run_regression=lambda sha: calls.append(sha) or _clean())
    assert result.triggered is True and calls == ["bbbbbbbb"]
    store.close()


# --- reachable-but-unverifiable is an attention condition, not a pass ---

def test_reachable_without_git_sha_is_attention_not_silent(tmp_path: Path) -> None:
    """Integrity (review #2): a target that answers /health but exposes no git_sha must not be
    conflated with 'unreachable' and silently pass."""
    store = Store.open(tmp_path / "s.db")
    poll_once(store, "t", observe=lambda: _ok("aaaaaaaa"), run_regression=lambda sha: _clean())
    calls: list[str] = []
    obs = HealthObservation(reachable=True, git_sha=None, status_code=200, note="200 but no git_sha")
    result = poll_once(store, "t", observe=lambda: obs,
                       run_regression=lambda sha: calls.append(sha) or _clean())
    assert result.reachable is True and result.current_sha is None
    assert result.triggered is False and calls == []
    assert store.count("target_health") == 1  # no new build recorded (baseline unchanged)
    audit = store.conn.execute(
        "SELECT action FROM agent_actions WHERE action = 'health_unverifiable'").fetchone()
    assert audit is not None
    assert poll_summary(result)[0] == 1        # cron alerts
    store.close()


def test_unreachable_records_and_triggers_nothing(tmp_path: Path) -> None:
    store = Store.open(tmp_path / "s.db")
    calls: list[str] = []
    obs = HealthObservation(reachable=False, git_sha=None, status_code=None, note="unreachable")
    result = poll_once(store, "t", observe=lambda: obs,
                       run_regression=lambda sha: calls.append(sha) or _clean())
    assert result.reachable is False and result.triggered is False
    assert calls == []
    assert store.count("target_health") == 0
    assert store.count("agent_actions") == 0
    store.close()


# --- poll_summary exit-code contract (review #4: the thing cron alerts on) ---

def test_poll_summary_exit_codes() -> None:
    def r(**kw) -> PollResult:
        base = dict(target_id="t", reachable=True, previous_sha="aaaaaaaa",
                    current_sha="aaaaaaaa", changed=False, triggered=False, regression=None)
        base.update(kw)
        return PollResult(**base)

    assert poll_summary(r(reachable=False, current_sha=None))[0] == 0            # unreachable
    assert poll_summary(r(current_sha=None))[0] == 1                             # reachable, no sha
    assert poll_summary(r(previous_sha=None))[0] == 0                            # baseline
    assert poll_summary(r())[0] == 0                                             # unchanged
    held = r(current_sha="bbbbbbbb", changed=True, triggered=True, regression=_clean())
    assert poll_summary(held)[0] == 0                                            # held clean
    reappeared = RegressionReport(target_sha="b", reappeared=[{"case_id": "reg-1", "category": "x"}])
    assert poll_summary(r(current_sha="bbbbbbbb", changed=True, triggered=True, regression=reappeared))[0] == 1
    inconclusive = RegressionReport(target_sha="b", inconclusive=["reg-1"])
    assert poll_summary(r(current_sha="bbbbbbbb", changed=True, triggered=True, regression=inconclusive))[0] == 1


# --- observe_health goes through the real Executor's authorization gate (review #3) ---

@dataclass
class _Resp:
    status_code: int
    text: str
    latency_ms: float = 1.0


@dataclass
class _Target:
    origin: str = "https://target.example"
    base_path: str = "/app"


class _SpySender:
    def __init__(self, resp: _Resp | None = None) -> None:
        self.resp = resp
        self.called = False

    def __call__(self, url: str, /, **kwargs: object) -> _Resp:
        self.called = True
        return self.resp


class _DenyingRegistry:
    def assert_authorized(self, url: str):
        raise AuthorizationDenied(url)


def test_observe_health_is_authorized_before_the_sender_runs() -> None:
    """The health poll must pass through the Executor's gate: an unauthorized origin raises and
    the sender is never touched (proves it isn't bypassing the single door)."""
    spy = _SpySender()
    executor = Executor(_DenyingRegistry(), spy)
    with pytest.raises(AuthorizationDenied):
        observe_health(executor, _Target())
    assert spy.called is False


class _AllowRegistry:
    def assert_authorized(self, url: str):
        return None


def test_observe_health_reads_git_sha_and_routes_through_executor() -> None:
    spy = _SpySender(_Resp(200, '{"status":"ok","git_sha":"deadbeef"}'))
    obs = observe_health(Executor(_AllowRegistry(), spy), _Target())
    assert obs.reachable is True and obs.git_sha == "deadbeef"
    assert spy.called is True


def test_observe_health_flags_non200_and_missing_and_null_body() -> None:
    assert observe_health(Executor(_AllowRegistry(), _SpySender(_Resp(503, "nope"))), _Target()).git_sha is None
    assert observe_health(Executor(_AllowRegistry(), _SpySender(_Resp(503, "nope"))), _Target()).reachable is True
    missing = observe_health(Executor(_AllowRegistry(), _SpySender(_Resp(200, '{"status":"ok"}'))), _Target())
    assert missing.reachable is True and missing.git_sha is None
    null_body = observe_health(Executor(_AllowRegistry(), _SpySender(_Resp(200, None))), _Target())
    assert null_body.git_sha is None            # a null/None body must not raise


def test_discover_runs_after_regression_on_change_only(tmp_path: Path) -> None:
    """poll -> regression -> discover: the discovery seam runs only on a real SHA change, after
    regression, and its candidates surface in the summary."""
    store = Store.open(tmp_path / "s.db")
    # baseline: discover must NOT run
    poll_once(store, "t", observe=lambda: _ok("aaaaaaaa"), run_regression=lambda sha: _clean(),
              discover=lambda sha: (_ for _ in ()).throw(AssertionError("discover on baseline")))
    seen: list[str] = []

    class _Summary:
        candidates = [{"x": 1}]

    result = poll_once(store, "t", observe=lambda: _ok("bbbbbbbb"),
                       run_regression=lambda sha: _clean(),
                       discover=lambda sha: seen.append(sha) or _Summary())
    assert seen == ["bbbbbbbb"] and result.discovery is not None
    assert "discovery 1 candidate" in poll_summary(result)[1]
    store.close()
