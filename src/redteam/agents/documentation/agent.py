"""The Documentation Agent — a confirmed Finding to a professional vulnerability report.

Deterministic and reproducible: the report is built from the Finding's own fields and its
evidence in the store, so a security engineer who was not present can reproduce it. High
and critical reports are held behind a human approval gate (they are not published until
`approve` is called). Data quality is validated before any write (E9): required fields,
and no second report for a Finding that already has one.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone

_REQUIRED = ("finding_id", "primary_category", "severity", "dedup_key")

_REMEDIATION = {
    "prompt-injection": "Delimit and datamark untrusted content in prompts; enforce an instruction hierarchy; verify claims against source before display.",
    "indirect-injection": "Treat retrieved/uploaded document content as data, never instructions; datamark it and strip embedded directives before the composer sees it.",
    "sensitive-info-disclosure": "Enforce patient scope on every read; strip non-requested identifiers; redact before any external model call and in logs.",
    "system-prompt-leakage": "Keep no secrets in the system prompt; treat the prompt as non-confidential; deny meta-requests to reveal or restate instructions.",
    "excessive-agency": "Require explicit clinician authority and a confirmation gate before any write; constrain tool/action names and arguments at execution time.",
    "improper-output-handling": "Escape/encode all model-derived values before rendering; never place model output into HTML, SQL, or a shell without a context-aware encoder.",
    "denial-of-service": "Enforce per-client rate limits, request-size caps, and hard time/cost budgets; fail closed when a budget is exceeded.",
    "broken-object-authorization": "Bind every session token to its subject server-side and re-authorize each object access against it; never trust a client-supplied patient/object id.",
    "broken-authentication": "Require and verify a valid session token on every patient route; reject missing, expired, or forged tokens with 401/403 and no data body.",
    "error-disclosure": "Return a generic error to clients; log the stack trace server-side only; disable framework debug pages and DB driver error passthrough in production.",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class DocumentationAgent:
    def _validate(self, finding: dict) -> None:
        missing = [f for f in _REQUIRED if not finding.get(f)]
        if missing:
            raise ValueError(f"finding {finding.get('finding_id')} missing required fields: {missing}")

    def _evidence_for_finding(self, store, finding: dict) -> dict:
        """The actual request/response + oracle detail behind the finding's first verdict, so
        the report shows *what happened*, not just that something did."""
        verdict_ids = json.loads(finding.get("verdict_ids") or "[]")
        if not verdict_ids:
            return {}
        vrow = store.conn.execute(
            "SELECT oracle_results, evidence_ref FROM verdicts WHERE verdict_id = ?", (verdict_ids[0],)
        ).fetchone()
        if vrow is None:
            return {}
        out: dict = {"oracle_results": json.loads(vrow["oracle_results"] or "[]"), "exchanges": []}
        if vrow["evidence_ref"]:
            erow = store.conn.execute(
                "SELECT exchanges FROM evidence WHERE evidence_id = ?", (vrow["evidence_ref"],)
            ).fetchone()
            if erow and erow["exchanges"]:
                out["exchanges"] = json.loads(erow["exchanges"])
        return out

    def _render_evidence(self, evidence: dict) -> str:
        if not evidence:
            return "_No evidence captured for this finding (attempt predates evidence capture)._\n"
        lines = []
        violations = [o for o in evidence.get("oracle_results", []) if o.get("outcome") == "violation"]
        if violations:
            lines.append("**Oracle(s) that fired:** " + ", ".join(
                f"`{o['oracle']}` — {o.get('detail') or 'violation'}" for o in violations))
        for ex in evidence.get("exchanges", []):
            req = json.dumps(ex.get("request"), ensure_ascii=False)
            resp = (ex.get("response") or "")
            resp = resp if len(resp) <= 1200 else resp[:1200] + " …[truncated]"
            lines.append(
                f"\n- `{ex.get('method')} {ex.get('route')}` → **HTTP {ex.get('status_code')}** "
                f"({ex.get('latency_ms')}ms)\n"
                f"  - request: `{req}`\n"
                f"  - response: `{resp}`"
            )
        return "\n".join(lines) + "\n"

    def render_markdown(self, finding: dict, level: str, evidence: dict | None = None) -> str:
        taxonomy = ", ".join(f"{t['scheme']}:{t['id']}" for t in json.loads(finding["taxonomy"] or "[]"))
        remediation = _REMEDIATION.get(finding["primary_category"], "Constrain the affected behavior and add a regression test.")
        return (
            f"# {finding['finding_id']} — {finding['title']}\n\n"
            f"- **Severity (provisional):** {level} — confirm with CVSS v4\n"
            f"- **Category / taxonomy:** {finding['primary_category']} ({taxonomy})\n"
            f"- **Component:** {finding['component']}\n\n"
            f"## Description\n"
            f"A confirmed exploit of {finding['primary_category']} at `{finding['component']}` on the "
            f"authorized synthetic target. Backed by verdicts {finding['verdict_ids']}.\n\n"
            f"## Evidence (what actually happened)\n{self._render_evidence(evidence or {})}\n"
            f"## Reproduction\n"
            f"Replay the attempts referenced in the Finding's verdicts against the same target build; "
            f"the oracle re-fires deterministically on the request shown above.\n\n"
            f"## Observed vs expected\n"
            f"Observed: the deterministic oracle detected a violation (see Evidence). Expected: the "
            f"assistant refuses and the protected invariant holds.\n\n"
            f"## Recommended remediation\n{remediation}\n\n"
            f"## Status\nProvisional. Fix validation pending a re-test on a candidate build.\n"
        )

    def document(self, store, finding_id: str) -> str:
        """Write a VulnReport for a Finding. Returns the report_id. Idempotent per Finding."""
        row = store.conn.execute("SELECT * FROM findings WHERE finding_id = ?", (finding_id,)).fetchone()
        if row is None:
            raise ValueError(f"no such finding: {finding_id}")
        finding = dict(row)
        self._validate(finding)

        existing = store.conn.execute("SELECT report_id FROM vuln_reports WHERE finding_id = ?", (finding_id,)).fetchone()
        if existing is not None:
            return existing["report_id"]

        try:
            level = json.loads(finding["severity"]).get("provisional_level", "")
        except (ValueError, TypeError):
            level = ""
        report_id = "R-" + finding_id[2:]
        evidence = self._evidence_for_finding(store, finding)
        # Fail closed (role-review T1.5): only an explicit low/medium finding backed by captured
        # evidence may auto-publish. High/critical, an unmapped or malformed severity, or a finding
        # with no evidence is held for a human — the gate never fails open on an unknown.
        has_evidence = bool(evidence.get("exchanges"))
        gated = level not in {"low", "medium"} or not has_evidence
        violations = [o for o in evidence.get("oracle_results", []) if o.get("outcome") == "violation"]
        observed = "; ".join(f"{o['oracle']}: {o.get('detail') or 'violation'}" for o in violations) \
            or "oracle detected a violation"
        store.insert("vuln_reports", {
            "schema_version": 1,
            "report_id": report_id,
            "finding_id": finding_id,
            "severity": finding["severity"],
            "description": f"Confirmed {finding['primary_category']} at {finding['component']}.",
            "clinical_impact": "Potential impact on a clinical workflow; assess against patient safety before triage.",
            "repro": json.dumps({"verdict_ids": json.loads(finding["verdict_ids"] or "[]"),
                                 "exchanges": evidence.get("exchanges", [])}),
            "observed_vs_expected": f"{observed} vs. invariant should hold",
            "remediation": _REMEDIATION.get(finding["primary_category"], ""),
            "status": "pending_approval" if gated else "published",
            "fix_validation": json.dumps({"sha": None, "result": None}),
            "approval": json.dumps({"required": gated, "approver": None, "at": None}),
            "created_at": _now(),
        })
        store.insert("agent_actions", {
            "ts": _now(), "agent": "documentation", "action": "report",
            "refs": json.dumps({"finding": finding_id, "report": report_id}),
            "reason": f"{'held for approval' if gated else 'published'} ({level})",
        })
        return report_id

    def approve(self, store, report_id: str, approver: str) -> None:
        """Human approval gate: publish a held critical/high report."""
        store.conn.execute(
            "UPDATE vuln_reports SET status = 'published', approval = ? WHERE report_id = ?",
            (json.dumps({"required": True, "approver": approver, "at": _now()}), report_id),
        )
        store.conn.commit()
