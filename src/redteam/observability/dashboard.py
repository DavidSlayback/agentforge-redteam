"""Render the store as a self-contained HTML dashboard — the human-facing observability view.

Server-side rendered from the store into one static file (no server, no JavaScript, no
external assets), so it adds no attack surface to a security tool and can be opened locally
or shared as one file. Regenerate after a run to refresh it.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path

from redteam.observability import queries
from redteam.store.store import Store

# Plumb design system tokens (David's shared system, plum flavor), vendored from david-brain's
# packs/shared/david-design/dist/tokens.css. Fonts are not loaded: no external assets, so the
# type falls back to each stack's system faces.
_TOKENS = Path(__file__).with_name("plumb_tokens.css").read_text(encoding="utf-8")

# Outcome pills read from the attacker's side: an attack SUCCESS is a finding (fail colours),
# an attack FAIL means the target held (pass colours).
_CSS = _TOKENS + """
:root{--glow:var(--glow-plum)}
*{box-sizing:border-box}
body{margin:0;color:var(--ink);font:400 14px/1.55 var(--font-body);background-color:var(--surface-0);
background-image:radial-gradient(120% 60% at 50% -10%,color-mix(in srgb,var(--accent) 12%,transparent),transparent 70%),
linear-gradient(var(--grid) 1px,transparent 1px),linear-gradient(90deg,var(--grid) 1px,transparent 1px);
background-size:100% 100%,var(--space-5) var(--space-5),var(--space-5) var(--space-5)}
.wrap{max-width:1040px;margin:0 auto;padding:32px 20px}
h1{position:relative;margin:0 0 6px;padding-bottom:12px;font:700 26px/1.2 var(--font-display);letter-spacing:1.2px;
text-transform:uppercase;text-shadow:var(--glow-text)}
h1::after{content:"";position:absolute;left:0;bottom:0;width:96px;height:var(--stroke-heavy);border-radius:var(--radius-pill);
background:var(--accent);box-shadow:var(--glow)}
.sub{color:var(--ink-muted);font:400 11px/18px var(--font-mono);margin:10px 0 24px}
.cards{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:24px}
.card{position:relative;flex:1;min-width:150px;padding:14px 16px;background:var(--surface-1);border:1px solid var(--line);
border-radius:var(--radius-lg);box-shadow:var(--shadow-raised)}
.card::before{content:"";position:absolute;top:-1px;left:20px;right:20px;height:var(--stroke-heavy);border-radius:var(--radius-pill);
background:linear-gradient(90deg,transparent,var(--accent) 20%,var(--accent) 80%,transparent);box-shadow:var(--glow)}
.card .n{font:500 28px/34px var(--font-mono);font-variant-numeric:tabular-nums}
.card .l{color:var(--ink-muted);font:600 10px/16px var(--font-mono);letter-spacing:1.2px;text-transform:uppercase}
h2{margin:32px 0 12px;font:600 14px/20px var(--font-display);letter-spacing:1.6px;text-transform:uppercase;color:var(--ink)}
table{width:100%;border-collapse:separate;border-spacing:0;font-size:13px;background:var(--surface-1);border:1px solid var(--line);
border-radius:var(--radius-md);box-shadow:var(--shadow-raised);overflow:hidden}
th,td{text-align:left;padding:8px 12px;border-top:1px solid var(--line);vertical-align:top}
tr:first-child>th,tr:first-child>td{border-top:0}
th{background:var(--surface-2);color:var(--ink-muted);font:600 10px/16px var(--font-mono);letter-spacing:1.2px;text-transform:uppercase}
tr:hover td{background:color-mix(in srgb,var(--accent) 6%,transparent)}
td.n{font-family:var(--font-mono);font-variant-numeric:tabular-nums}
.pill{display:inline-flex;align-items:center;gap:6px;padding:1px 10px 1px 8px;border-radius:var(--radius-pill);
font:600 10px/18px var(--font-mono);letter-spacing:1.2px;text-transform:uppercase;white-space:nowrap;
border:1px solid color-mix(in srgb,currentColor 45%,transparent)}
.pill::before{content:"";width:6px;height:6px;border-radius:var(--radius-pill);background:currentColor;box-shadow:0 0 6px currentColor}
.s-SUCCESS,.s-new{background:var(--fail-soft);color:var(--fail);box-shadow:var(--glow-fail)}
.s-FAIL,.s-published{background:var(--pass-soft);color:var(--pass)}
.s-INCONCLUSIVE,.s-pending_approval{background:var(--warn-soft);color:var(--warn)}
.muted{color:var(--ink-muted)}code{font-family:var(--font-mono);font-size:.88em}
"""


def _esc(x: object) -> str:
    return html.escape(str(x))


def _mix_table(rows: dict[str, dict[str, int]], key_label: str) -> str:
    if not rows:
        return '<p class="muted">(none yet)</p>'
    outcomes = sorted({o for mix in rows.values() for o in mix})
    head = "".join(f"<th>{_esc(o)}</th>" for o in outcomes)
    body = ""
    for key, mix in sorted(rows.items()):
        cells = "".join(f'<td class="n">{mix.get(o, 0) or ""}</td>' for o in outcomes)
        body += f"<tr><td><code>{_esc(key)}</code></td>{cells}</tr>"
    return f"<table><tr><th>{_esc(key_label)}</th>{head}</tr>{body}</table>"


def render_html(store: Store) -> str:
    cats = queries.cases_per_category(store)
    findings_status = queries.findings_by_status(store)
    cost = queries.cost_summary(store)
    total_cases = sum(cats.values())
    total_findings = sum(findings_status.values())

    findings_rows = ""
    for r in store.conn.execute(
        "SELECT finding_id, primary_category, severity_score, status FROM findings ORDER BY severity_score DESC"
    ):
        findings_rows += (
            f"<tr><td><code>{_esc(r['finding_id'])}</code></td><td>{_esc(r['primary_category'])}</td>"
            f"<td class='n'>{_esc(r['severity_score'])}</td>"
            f"<td><span class='pill s-{_esc(r['status'])}'>{_esc(r['status'])}</span></td></tr>"
        )
    findings_table = (
        f"<table><tr><th>Finding</th><th>Category</th><th>Severity</th><th>Status</th></tr>{findings_rows}</table>"
        if findings_rows else '<p class="muted">No findings yet.</p>'
    )

    trace_rows = "".join(
        f"<tr><td class='muted'>{_esc(a['ts'][11:19])}</td><td>{_esc(a['agent'])}/{_esc(a['action'])}</td>"
        f"<td class='muted'>{_esc(a['reason'])}</td></tr>"
        for a in queries.agent_trace(store, limit=15)
    )

    def _rate(x: object) -> str:
        return "n/a" if x is None else format(x, ".0%")

    def _cats(b: dict) -> str:
        return "; ".join(
            c + ": " + ", ".join(f"{o}={n}" for o, n in sorted(m.items()))
            for c, m in sorted(b["categories"].items()))

    resilience_rows = "".join(
        f"<tr><td><code>{_esc(b['sha'])}</code></td><td class='muted'>{_esc(b['first_seen'])}</td>"
        f"<td class='n'>{_rate(b['success_rate'])}</td><td>{_esc(b['trend'] or '')}</td>"
        f"<td class='muted'>{_esc(_cats(b))}</td></tr>"
        for b in queries.resilience_over_time(store)
    )
    resilience_table = (
        "<table><tr><th>Build</th><th>First attacked</th><th>Attack success</th><th>Trend</th><th>By category</th></tr>"
        f"{resilience_rows}</table>" if resilience_rows else '<p class="muted">(no attempts yet)</p>'
    )
    cost_rows = "".join(
        f"<tr><td><code>{_esc(t['run_id'])}</code></td><td class='muted'>{_esc(t['first_ts'])}</td>"
        f"<td class='n'>{t['calls']}</td><td class='n'>{t['attempts']}</td>"
        f"<td class='n'>{'n/a' if t['calls_per_attempt'] is None else format(t['calls_per_attempt'], '.2f')}</td>"
        f"<td>{_esc(t['direction'] or '')}</td><td class='n'>{t['cumulative_calls']}</td></tr>"
        for t in queries.cost_trend(store)
    )
    cost_table = (
        "<table><tr><th>Run</th><th>Started</th><th>Calls</th><th>Attempts</th><th>Calls/attempt</th>"
        f"<th>Trend</th><th>Cumulative calls</th></tr>{cost_rows}</table>"
        if cost_rows else '<p class="muted">(no metered runs yet)</p>'
    )

    return f"""<!doctype html><html lang="en" data-theme="dark" data-flavor="plum"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Red Team Dashboard</title><style>{_CSS}</style></head><body><div class="wrap">
<h1>AgentForge Red Team</h1>
<p class="sub">Read-only snapshot · generated {_esc(datetime.now(timezone.utc).isoformat(timespec='seconds'))}</p>
<div class="cards">
  <div class="card"><div class="n">{total_cases}</div><div class="l">Cases run</div></div>
  <div class="card"><div class="n">{total_findings}</div><div class="l">Findings</div></div>
  <div class="card"><div class="n">{len(cats)}</div><div class="l">Categories</div></div>
  <div class="card"><div class="n">{cost['calls']}</div><div class="l">Model calls</div></div>
</div>
<h2>Pass / fail by category</h2>{_mix_table(queries.pass_fail_by_category(store), "Category")}
<h2>OWASP coverage</h2>{_mix_table(queries.owasp_coverage(store), "OWASP")}
<h2>Resilience by target build</h2>{_mix_table(queries.outcomes_by_sha(store), "Build (SHA)")}
<h2>Resilience over time</h2>{resilience_table}
<h2>Cost per run</h2>{cost_table}
<h2>Findings</h2>{findings_table}
<h2>Recent agent actions</h2><table><tr><th>Time</th><th>Agent</th><th>Reason</th></tr>{trace_rows or '<tr><td class="muted" colspan="3">(none)</td></tr>'}</table>
<p class="sub" style="margin-top:22px">Synthetic data only · one authorized target · cost in model calls (not USD).</p>
</div></body></html>
"""
