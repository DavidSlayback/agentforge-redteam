"""Render the store as a self-contained HTML dashboard — the human-facing observability view.

Server-side rendered from the store into one static file (no server, no JavaScript, no
external assets), so it adds no attack surface to a security tool and can be opened locally
or attached to a submission. Regenerate after a run to refresh it.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone

from redteam.observability import queries
from redteam.store.store import Store

_CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#161a20;--muted:#616a76;--line:#e4e7eb;--accent:#b4531f;
--good:#0d8a7a;--bad:#d6402c;--warn:#b8860b}
@media(prefers-color-scheme:dark){:root{--bg:#14161a;--card:#1d2026;--ink:#e9ebef;--muted:#9aa2ad;
--line:#2c313a;--accent:#e8895a;--good:#3fc7b4;--bad:#f0806e;--warn:#e6c34d}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:14px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1040px;margin:0 auto;padding:28px 20px}
h1{font-size:22px;margin:0 0 2px}.sub{color:var(--muted);font-size:13px;margin:0 0 20px}
.cards{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:22px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px;flex:1;min-width:150px}
.card .n{font-size:26px;font-weight:700;font-variant-numeric:tabular-nums}
.card .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.05em}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);
border-bottom:1px solid var(--line);padding-bottom:6px;margin:26px 0 10px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
td.n{font-variant-numeric:tabular-nums}
.pill{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600}
.s-SUCCESS,.s-new{background:color-mix(in srgb,var(--bad) 18%,transparent);color:var(--bad)}
.s-FAIL,.s-published{background:color-mix(in srgb,var(--good) 18%,transparent);color:var(--good)}
.s-INCONCLUSIVE,.s-pending_approval{background:color-mix(in srgb,var(--warn) 20%,transparent);color:var(--warn)}
.muted{color:var(--muted)}code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.92em}
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

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
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
<h2>Findings</h2>{findings_table}
<h2>Recent agent actions</h2><table><tr><th>Time</th><th>Agent</th><th>Reason</th></tr>{trace_rows or '<tr><td class="muted" colspan="3">(none)</td></tr>'}</table>
<p class="sub" style="margin-top:22px">Synthetic data only · one authorized target · cost in model calls (not USD).</p>
</div></body></html>
"""
