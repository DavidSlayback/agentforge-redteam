"""Recon — the deterministic service that watches the authorized target for change.

Today it does one thing: poll ``GET {origin}{base_path}/health`` for the running ``git_sha``
and, when that SHA differs from the last observed build, trigger a regression replay of every
frozen finding against the new build. That SHA-change → regression trigger is the
fix-validation loop the PRD asks for (P5/T3.5): a deploy that reopens a frozen vulnerability is
caught automatically and read loudly (``RegressionReport.ok`` is ``False``), rather than waiting
for someone to remember to re-run the suite.

Two invariants matter here:

* **Single door (ADR 0002).** The poll goes through the Executor like every other target
  request, so a ``/health`` check is authorized against the registry too — the platform cannot
  poll an origin it is not allowed to touch.
* **No drifting state.** The last-seen SHA is just the most recent ``target_health`` row for the
  target; there is no separate mutable "current SHA" cell to fall out of sync with the log.

The core, :func:`poll_once`, takes the health fetch and the regression run as injected seams so
the change-detection logic is unit-testable with no network and no model calls; :func:`poll`
wires the live pieces into those seams.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from redteam.errors import TargetUnreachable
from redteam.executor.authorization import AuthorizationRegistry, Target
from redteam.executor.executor import Executor
from redteam.regression import RegressionReport, replay
from redteam.store.store import Store


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class PollResult:
    target_id: str
    reachable: bool
    previous_sha: str | None
    current_sha: str | None
    changed: bool
    triggered: bool
    regression: RegressionReport | None = None


def health_url(target: Target) -> str:
    """The target's health endpoint, built the same way TokenMinter builds route URLs."""
    return f"{target.origin}{target.base_path}/health"


def fetch_health_sha(executor: Executor, target: Target) -> str | None:
    """Return the target's running ``git_sha`` via the Executor, or ``None`` if it cannot be
    read (unreachable, non-200, or the field is absent). Returning ``None`` — rather than
    raising — lets a scheduled poll record "nothing observed" and move on instead of crashing.
    """
    try:
        record = executor.request(health_url(target), method="GET")
    except TargetUnreachable:
        return None
    if getattr(record, "status_code", None) != 200:
        return None
    try:
        sha = json.loads(record.text).get("git_sha")
    except (ValueError, AttributeError):
        return None
    return sha or None


def last_seen_sha(store: Store, target_id: str) -> str | None:
    row = store.conn.execute(
        "SELECT git_sha FROM target_health WHERE target_id = ? ORDER BY id DESC LIMIT 1",
        (target_id,),
    ).fetchone()
    return row["git_sha"] if row is not None else None


def poll_once(
    store: Store,
    target_id: str,
    *,
    fetch_sha: Callable[[], str | None],
    run_regression: Callable[[str], RegressionReport],
) -> PollResult:
    """Observe the target's build once; on a SHA change, run the regression suite.

    * The *first* observation establishes a baseline and does not trigger — there is no prior
      build to validate against. Validating the *current* build is an explicit ``redteam
      regression`` run; this poller catches *subsequent* deploys.
    * An unreachable target records nothing and triggers nothing (``reachable=False``); the next
      poll tries again.
    """
    current = fetch_sha()
    if current is None:
        return PollResult(target_id, reachable=False, previous_sha=last_seen_sha(store, target_id),
                          current_sha=None, changed=False, triggered=False)

    previous = last_seen_sha(store, target_id)
    changed = previous is not None and current != previous
    store.insert("target_health", {
        "target_id": target_id, "git_sha": current,
        "changed": 1 if changed else 0, "observed_at": _now(),
    })

    if not changed:
        return PollResult(target_id, reachable=True, previous_sha=previous,
                          current_sha=current, changed=False, triggered=False)

    # SHA changed against a known baseline: record the recon signal, then trigger regression.
    store.insert("agent_actions", {
        "ts": _now(), "agent": "recon", "action": "target_sha_changed",
        "refs": json.dumps({"target": target_id, "previous_sha": previous, "current_sha": current}),
        "reason": f"target build changed {previous[:8]}..->{current[:8]}..; triggering regression",
    })
    report = run_regression(current)
    store.insert("agent_actions", {
        "ts": _now(), "agent": "recon", "action": "regression_triggered",
        "refs": json.dumps({
            "target": target_id, "sha": current,
            "held": len(report.held), "reappeared": len(report.reappeared),
            "inconclusive": len(report.inconclusive), "unreplayable": len(report.unreplayable),
            "ok": report.ok,
        }),
        "reason": ("regression clean — all frozen findings held"
                   if report.ok else "regression ATTENTION — a frozen finding did not hold"),
    })
    return PollResult(target_id, reachable=True, previous_sha=previous,
                      current_sha=current, changed=True, triggered=True, regression=report)


def poll(
    store: Store,
    registry: AuthorizationRegistry,
    executor: Executor,
    judge: object,
    target: Target,
    target_id: str,
    minter: object | None = None,
) -> PollResult:
    """Wire the live health fetch and regression replay into :func:`poll_once`."""
    return poll_once(
        store, target_id,
        fetch_sha=lambda: fetch_health_sha(executor, target),
        run_regression=lambda sha: replay(store, registry, executor, judge, sha, minter=minter),
    )
