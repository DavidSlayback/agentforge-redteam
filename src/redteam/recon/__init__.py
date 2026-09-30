"""Recon — the deterministic service that watches the authorized target for change.

Today it does one thing: poll ``GET {origin}{base_path}/health`` for the running ``git_sha``
and, when that SHA differs from the last observed build, trigger a regression replay of every
frozen finding against the new build. That SHA-change → regression trigger is the
fix-validation loop the PRD asks for (P5/T3.5): a deploy that reopens a frozen vulnerability is
caught automatically and read loudly (``RegressionReport.ok`` is ``False``), rather than waiting
for someone to remember to re-run the suite.

Three invariants matter here, and two of them are integrity rules the platform lives by
("a missing verdict is never a pass"):

* **Single door (ADR 0002).** The poll goes through the Executor, so a ``/health`` check is
  authorized against the registry too — the platform cannot poll an origin it is not allowed to
  touch. (An unauthorized origin raises ``AuthorizationDenied`` and the poll fails loudly; that
  is a misconfiguration, not a routine outcome.)
* **The baseline advances only after the regression completes.** The new SHA is written as the
  last-seen build *after* ``run_regression`` returns, so a regression that raises mid-run leaves
  the baseline unchanged and the next poll re-detects the change and re-triggers — a crashed
  verification never silently reads as "held".
* **Reachable-but-unverifiable is not a pass.** A target that answers ``/health`` but no longer
  exposes a parseable ``git_sha`` (shape change, 5xx, empty body) is *not* recorded as a build
  and *not* treated as "unreachable, nothing to do"; it is an attention condition (audited, and
  the CLI exits non-zero) because we cannot confirm which build is running.

The core, :func:`poll_once`, takes the health observation and the regression run as injected
seams so the change-detection logic is unit-testable with no network and no model calls;
:func:`poll` wires the live pieces into those seams, and :func:`poll_summary` turns a result into
the CLI's message and exit code.
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


@dataclass(frozen=True)
class HealthObservation:
    """One ``/health`` observation. ``reachable`` means an HTTP response came back at all;
    ``git_sha`` is the parsed build id, or ``None`` when the target answered but did not expose a
    usable one (non-200, wrong shape, empty). Keeping those two facts distinct is what lets the
    poller refuse to score an unverifiable-but-reachable target as green."""
    reachable: bool
    git_sha: str | None
    status_code: int | None
    note: str


@dataclass
class PollResult:
    target_id: str
    reachable: bool
    previous_sha: str | None
    current_sha: str | None       # None when reachable but no parseable git_sha
    changed: bool
    triggered: bool
    note: str = ""
    regression: RegressionReport | None = None
    discovery: object | None = None   # optional DiscoverySummary from a post-regression discovery pass


def health_url(target: Target) -> str:
    """The target's health endpoint, built the same way TokenMinter builds route URLs."""
    return f"{target.origin}{target.base_path}/health"


def observe_health(executor: Executor, target: Target) -> HealthObservation:
    """Observe the target's build via the Executor (so the poll passes the authorization gate).

    Distinguishes three outcomes so the caller can tell "can't reach it" from "reached it but
    can't verify the build": a transport failure is ``reachable=False``; a non-200 or a 200 whose
    body has no usable ``git_sha`` is ``reachable=True, git_sha=None``. ``AuthorizationDenied``
    (an unauthorized origin) is deliberately *not* caught — it means misconfiguration and must
    fail loudly.
    """
    try:
        record = executor.request(health_url(target), method="GET")
    except TargetUnreachable:
        return HealthObservation(reachable=False, git_sha=None, status_code=None, note="unreachable")
    status = getattr(record, "status_code", None)
    if status != 200:
        return HealthObservation(reachable=True, git_sha=None, status_code=status, note=f"non-200 ({status})")
    text = getattr(record, "text", None)
    try:
        sha = json.loads(text).get("git_sha") if text is not None else None
    except (ValueError, AttributeError, TypeError):
        sha = None
    if not sha:
        return HealthObservation(reachable=True, git_sha=None, status_code=status, note="200 but no git_sha")
    return HealthObservation(reachable=True, git_sha=sha, status_code=status, note="ok")


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
    observe: Callable[[], HealthObservation],
    run_regression: Callable[[str], RegressionReport],
    discover: Callable[[str], object] | None = None,
) -> PollResult:
    """Observe the target's build once; on a SHA change, run the regression suite.

    * The *first* observation establishes a baseline and does not trigger — there is no prior
      build to validate against. Validating the *current* build is an explicit ``redteam
      regression`` run; this poller catches *subsequent* deploys.
    * An unreachable target records nothing and triggers nothing (``reachable=False``).
    * A reachable target with no parseable ``git_sha`` records an attention action and advances
      no baseline (``current_sha=None``) — it is not a verified build.
    * On a real change, the regression runs *before* the new SHA is written as the baseline, so a
      regression that raises does not lose the trigger (the next poll re-detects and re-runs).
    """
    obs = observe()
    previous = last_seen_sha(store, target_id)

    if not obs.reachable:
        return PollResult(target_id, reachable=False, previous_sha=previous,
                          current_sha=None, changed=False, triggered=False, note=obs.note)

    if obs.git_sha is None:
        # Reachable but the build can't be verified: audit it and refuse to treat it as a pass.
        store.insert("agent_actions", {
            "ts": _now(), "agent": "recon", "action": "health_unverifiable",
            "refs": json.dumps({"target": target_id, "status": obs.status_code}),
            "reason": f"/health reachable but no usable git_sha ({obs.note}); build unverifiable",
        })
        return PollResult(target_id, reachable=True, previous_sha=previous,
                          current_sha=None, changed=False, triggered=False, note=obs.note)

    current = obs.git_sha
    changed = previous is not None and current != previous

    if not changed:
        store.insert("target_health", {
            "target_id": target_id, "git_sha": current, "changed": 0, "observed_at": _now(),
        })
        return PollResult(target_id, reachable=True, previous_sha=previous,
                          current_sha=current, changed=False, triggered=False, note=obs.note)

    # SHA changed against a known baseline. Run the regression FIRST: if it raises, nothing below
    # runs, the baseline is not advanced, and the next poll re-detects the change and retries — a
    # failed verification is never silently dropped or read as green.
    report = run_regression(current)
    store.insert("agent_actions", {
        "ts": _now(), "agent": "recon", "action": "target_sha_changed",
        "refs": json.dumps({"target": target_id, "previous_sha": previous, "current_sha": current}),
        "reason": f"target build changed {previous[:8]}..->{current[:8]}..; regression triggered",
    })
    store.insert("agent_actions", {
        "ts": _now(), "agent": "recon", "action": "regression_triggered",
        "refs": json.dumps({
            "target": target_id, "sha": current,
            "held": len(report.held), "reappeared": len(report.reappeared),
            "inconclusive": len(report.inconclusive), "unreplayable": len(report.unreplayable),
            "newly_regressed": sorted(report.regressed_categories),
            "newly_fixed": sorted(report.fixed_categories),
            "cross_category_regression": report.cross_category_regression,
            "ok": report.ok,
        }),
        "reason": ("regression clean — all frozen findings held" if report.ok else
                   ("regression ATTENTION — CROSS-CATEGORY regression: fixing "
                    f"{sorted(report.fixed_categories)} reopened {sorted(report.regressed_categories - report.fixed_categories)}"
                    if report.cross_category_regression
                    else "regression ATTENTION — a frozen finding did not hold")),
    })
    # Advance the baseline only now that the regression has actually completed.
    store.insert("target_health", {
        "target_id": target_id, "git_sha": current, "changed": 1, "observed_at": _now(),
    })
    # Best-effort open-ended discovery over the new build's fresh evidence (it logs its own
    # discovery_pass action). Runs after the trust-critical regression + baseline, so it can never
    # affect whether the build reads clean; it only surfaces leads for human triage.
    discovery = discover(current) if discover is not None else None
    return PollResult(target_id, reachable=True, previous_sha=previous, current_sha=current,
                      changed=True, triggered=True, note=obs.note, regression=report, discovery=discovery)


def poll_summary(result: PollResult) -> tuple[int, str]:
    """Turn a poll result into the CLI's (exit_code, message). Exit non-zero whenever the build
    could not be confirmed clean: reachable-but-unverifiable, or a triggered regression that did
    not come back OK — so a scheduled poll can alert on it."""
    if not result.reachable:
        return 0, "unreachable (nothing recorded)"
    if result.current_sha is None:
        return 1, f"reachable but /health has no git_sha — cannot verify build (ATTENTION: {result.note})"
    sha = result.current_sha[:12]
    if result.previous_sha is None:
        return 0, f"git_sha {sha} — baseline recorded (no prior build)"
    if not result.changed:
        return 0, f"git_sha {sha} unchanged — no trigger"
    r = result.regression
    assert r is not None  # a changed result always carries its regression report
    tail = (f"regression held={len(r.held)} reappeared={len(r.reappeared)} "
            f"inconclusive={len(r.inconclusive)} unreplayable={len(r.unreplayable)} "
            f"-> {'OK' if r.ok else 'ATTENTION'}")
    disc = ""
    cands = getattr(result.discovery, "candidates", None)
    if cands is not None:
        disc = f"; discovery {len(cands)} candidate(s)"
    return (0 if r.ok else 1), f"git_sha changed {result.previous_sha[:12]} -> {sha}; {tail}{disc}"


def poll(
    store: Store,
    registry: AuthorizationRegistry,
    executor: Executor,
    judge: object,
    target: Target,
    target_id: str,
    minter: object | None = None,
    discover: Callable[[str], object] | None = None,
) -> PollResult:
    """Wire the live health observation and regression replay into :func:`poll_once`. ``discover``
    (optional) runs an open-ended discovery pass over the new build's evidence after regression."""
    return poll_once(
        store, target_id,
        observe=lambda: observe_health(executor, target),
        run_regression=lambda sha: replay(store, registry, executor, judge, sha, minter=minter),
        discover=discover,
    )
