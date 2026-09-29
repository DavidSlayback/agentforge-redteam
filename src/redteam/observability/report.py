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

    lines += ["", "## Findings"]
    fb = queries.findings_by_status(store)
    lines += [f"- {status}: {n}" for status, n in sorted(fb.items())] or ["- (none)"]

    # Cost is metered in model CALLS, the honest unit here: Qwen bills in credits and no USD
    # price is wired, so reporting "$0.0000 / 0 tokens" would read as "free". Show calls only.
    cost = queries.cost_summary(store)
    lines += ["", "## Cost", f"- {cost['calls']} model calls (USD pricing not wired; cost is metered in calls)"]

    lines += ["", "## Recent agent actions"]
    trace = queries.agent_trace(store, limit=10)
    lines += [f"- {a['ts']} {a['agent']}/{a['action']}: {a['reason']}" for a in trace] or ["- (none)"]

    return "\n".join(lines) + "\n"
