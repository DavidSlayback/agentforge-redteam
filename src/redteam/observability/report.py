"""Render the observability queries as a plain-text/markdown snapshot — the read-only view
a human inspects. (A served HTML dashboard is a later thin wrapper over the same queries.)
"""

from __future__ import annotations

from redteam.observability import queries
from redteam.store.store import Store


def render_markdown(store: Store) -> str:
    lines: list[str] = ["# Red Team — status", ""]

    cats = queries.cases_per_category(store)
    lines.append("## Cases per category")
    lines += [f"- {cat}: {n}" for cat, n in sorted(cats.items())] or ["- (none)"]

    lines += ["", "## Pass/fail by category"]
    pf = queries.pass_fail_by_category(store)
    if pf:
        for cat, outcomes in sorted(pf.items()):
            mix = ", ".join(f"{o}={n}" for o, n in sorted(outcomes.items()))
            lines.append(f"- {cat}: {mix}")
    else:
        lines.append("- (no verdicts yet)")

    lines += ["", "## Resilience by target build"]
    by_sha = queries.outcomes_by_sha(store)
    if by_sha:
        for sha, outcomes in sorted(by_sha.items()):
            mix = ", ".join(f"{o}={n}" for o, n in sorted(outcomes.items()))
            lines.append(f"- {sha}: {mix}")
    else:
        lines.append("- (no attempts yet)")

    lines += ["", "## Resilience over time (builds, earliest first)"]
    series = queries.resilience_over_time(store)
    if series:
        for b in series:
            rate = "n/a" if b["success_rate"] is None else f"{b['success_rate']:.0%}"
            lines.append(f"- {b['sha']} (first attacked {b['first_seen']}): attack success {rate}"
                         f"{' -- ' + b['trend'] if b['trend'] else ''}")
            for cat, mix in sorted(b["categories"].items()):
                lines.append(f"  - {cat}: " + ", ".join(f"{o}={n}" for o, n in sorted(mix.items())))
    else:
        lines.append("- (no attempts yet)")

    lines += ["", "## Over-refusal (benign clinician set)"]
    from redteam.benign import latest_by_sha
    benign = latest_by_sha(store)
    if benign:
        for b in sorted(benign, key=lambda x: x["target_sha"] or ""):
            rate = "not measured" if b["rate"] is None else f"{b['over_refusals']}/{b['measured']} = {b['rate']:.0%}"
            lines.append(f"- {b['target_sha'] or 'unlabelled'}: over-refusal {rate}; "
                         f"controls {b['controls']}; inconclusive {b['inconclusive']}")
    else:
        lines.append("- (no benign runs yet)")

    lines += ["", "## Findings"]
    fb = queries.findings_by_status(store)
    lines += [f"- {status}: {n}" for status, n in sorted(fb.items())] or ["- (none)"]

    # Cost is metered in model CALLS, the honest unit here: Qwen bills in credits and no USD
    # price is wired, so reporting "$0.0000 / 0 tokens" would read as "free". Show calls only.
    cost = queries.cost_summary(store)
    lines += ["", "## Cost", f"- {cost['calls']} model calls (USD pricing not wired; cost is metered in calls)"]

    lines += ["", "## Cost per run"]
    trend = queries.cost_trend(store)
    if trend:
        for t in trend:
            cpa = "n/a" if t["calls_per_attempt"] is None else f"{t['calls_per_attempt']:.2f}"
            d = f", {t['direction']} ({t['rate_change']:+.2f})" if t["direction"] else ""
            lines.append(f"- {t['run_id']} ({t['first_ts']}): {t['calls']} calls over {t['attempts']} attempts "
                         f"= {cpa} calls/attempt{d}; cumulative {t['cumulative_calls']} calls")
    else:
        lines.append("- (no metered runs yet)")

    q = queries.queue_depth(store)
    lines += ["", "## Queue depth (pending work)",
              f"- campaigns pending: {q['campaigns_pending']}; reports pending approval: {q['reports_pending_approval']}"]

    lines += ["", "## Recent agent actions"]
    trace = queries.agent_trace(store, limit=10)
    lines += [f"- {a['ts']} {a['agent']}/{a['action']}: {a['reason']}" for a in trace] or ["- (none)"]

    return "\n".join(lines) + "\n"
