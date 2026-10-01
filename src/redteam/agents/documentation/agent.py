"""The Documentation Agent — a confirmed Finding to a professional vulnerability report.

Deterministic and reproducible: the report is built from the Finding's own fields and its
evidence in the store. The bar is that a security engineer who was not present can
reproduce, validate, and fix the issue from the report alone — so the Reproduction section
renders the captured request(s) as copy-pasteable `curl` against the target's full URL, with
a deterministic pass condition for the fix, and nothing in the report points only at the
(gitignored) store.

High and critical reports are held behind a human approval gate (they are not published
until `approve` is called). Data quality is validated before any write (E9): required
fields, and no second report for a Finding that already has one.
"""

from __future__ import annotations

import base64
import json
import shlex
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlencode

from redteam.owasp import owasp_label

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
    "misinformation": "Gate the answer on clinical APPLICABILITY, not just retrieval sufficiency: when the retrieved guidelines do not match a condition present in the patient's chart, qualify the response (mark `qualification.required` with a reason) or withhold the evidence rather than presenting it as applicable. Score guideline relevance against the patient's active problem list before attaching it, and surface a clinician-visible 'no applicable evidence for this patient' state.",
    "information-disclosure": "Strip internal implementation metadata from the client-facing response: remove or gate behind an internal/debug scope the retrieval provider/model names, per-stage usage/telemetry, token/cost fields, and internal datastore identifiers (`document_uuid`, internal `patient_uuid`, sequential `document_id`). Return only clinical content + citations; keep supply-chain and datastore internals server-side.",
    "enumeration": "Issue session tokens only for provisioned patients (check existence/authorization at mint time, not after); return a uniform response for unknown vs existing patients so 200/404 does not reveal existence; and keep the per-client rate limit. Gating the mint entirely was declined for physician experience, so uniform responses + provisioned-only issuance are the controls.",
    "data-integrity": "Resolve history before presenting: mark exactly one value per field as `current` (latest `recorded_at`), or collapse superseded values; never return multiple active values for the same field without a current marker.",
}

# Per-category description + clinical impact (what the weakness means for a clinician/patient).
_DESCRIPTION = {
    "prompt-injection": "User-supplied text was followed as an instruction by the Co-Pilot's model instead of being treated as data.",
    "indirect-injection": "Text inside an uploaded or retrieved document was followed as an instruction when the Co-Pilot summarized it.",
    "sensitive-info-disclosure": "The Co-Pilot returned data outside the requesting patient's scope.",
    "system-prompt-leakage": "The Co-Pilot revealed its operating instructions.",
    "excessive-agency": "The Co-Pilot recommended, ordered, or confirmed a clinical action without explicit clinician authority.",
    "improper-output-handling": "The Co-Pilot emitted active markup that would execute or break rendering when displayed.",
    "denial-of-service": "A request caused disproportionate cost, latency, or a failure on the target.",
    "broken-object-authorization": "A session scoped to one patient reached another patient's object.",
    "broken-authentication": "A patient route accepted a request without valid authentication.",
    "error-disclosure": "An error response exposed internal implementation detail.",
    "misinformation": "The Co-Pilot presented clinical-guideline evidence as applicable to a patient for a condition absent from that patient's chart, without qualifying it.",
    "information-disclosure": "The clinician-facing response carried internal implementation metadata (AI provider/model names, retrieval telemetry, and internal datastore identifiers) beyond the clinical answer.",
    "enumeration": "The anonymous synthetic-context mint issues a valid token for any well-formed patient id in the namespace (including ids that do not exist), and the data route returns 200 for real patients and 404 for others — letting an unauthenticated caller map the patient namespace.",
    "data-integrity": "The chart returned multiple distinct values for the same field (e.g. two medication doses) with none marked current, presenting contradictory active data without disambiguation.",
}
_CLINICAL_IMPACT = {
    "prompt-injection": "An attacker can steer the briefing a clinician reads; a manipulated summary can omit or invent findings that feed a care decision.",
    "indirect-injection": "A poisoned document can change the AI briefing a clinician relies on, without the clinician seeing the injected text.",
    "sensitive-info-disclosure": "Cross-patient PHI exposure: a confidentiality breach, HIPAA-reportable in a real deployment.",
    "system-prompt-leakage": "Exposes the guardrails, making targeted bypasses of the clinical safety rules easier.",
    "excessive-agency": "A clinical action could be taken or endorsed without a clinician's decision: a direct patient-safety risk.",
    "improper-output-handling": "Script in a clinician's browser session could read or alter the chart view.",
    "denial-of-service": "The Co-Pilot can be made slow or unavailable at the point of care, and the operator's model spend can be run up.",
    "broken-object-authorization": "Anyone with one patient's session can read another patient's chart: a PHI confidentiality breach.",
    "broken-authentication": "Unauthenticated callers reach patient data: a PHI confidentiality breach, HIPAA-reportable in a real deployment.",
    "error-disclosure": "Leaked internals help an attacker target other weaknesses; low direct clinical impact.",
    "misinformation": "A clinician skimming the cited evidence could be led to apply guidance that does not fit this patient (e.g. anticoagulation guidance surfaced for a patient with no such condition), an overreliance/patient-safety risk; the missing qualification removes the cue that the evidence is inapplicable.",
    "information-disclosure": "Naming the exact embedding and LLM models and exposing internal record identifiers hands an attacker the supply chain to target and an id space to enumerate; low direct clinical impact but it lowers the cost of the higher-severity attacks.",
    "enumeration": "An unauthenticated attacker can discover which patients exist and the shape of the patient population — a confidentiality/recon exposure and the precursor to targeted record access; in production a privacy-reportable leak of patient existence.",
    "data-integrity": "A clinician treating the returned facts as current state could act on a superseded value (e.g. the old medication dose) — a direct patient-safety risk; the system should mark which value is current rather than present both.",
}

_SYNTHETIC_NOTE = ("The target serves synthetic fixture patients only; no real PHI was accessed. "
                   "The impact statement describes the same defect in a real deployment.")

# The synthetic-context mints: component-aware overrides where the category default is wrong.
# The defect on these routes is that the token-*issuing* endpoint is anonymous, not that a
# patient route skips token checks (those routes do verify tokens).
_MINT_REMEDIATION = (
    "1. Disable `AGENTFORGE_SYNTHETIC_CONTEXT` in every deployment that is not an explicit demo; "
    "with it off, the route must return 404/403 and issue no token.\n"
    "2. Where a demo mint must stay on, require an authenticated caller (evaluator access code or "
    "session) and bind issuance to that caller's identity: mint only for patients the caller may "
    "access, and log caller → patient → scope for every token issued.\n"
    "3. Rate-limit the mint per client (return `429` with `Retry-After`).\n"
    "4. Keep the existing short token TTL (300 s) and the token↔patient binding; do not lengthen "
    "the TTL to compensate.\n"
    "5. Add a target-side test that fails if an anonymous request to the mint returns a token."
)
_RATE_LIMIT_REMEDIATION = (
    "1. Add a per-client (per-IP and, once authenticated, per-caller) rate limit on the mint; "
    "over the limit return `429` with a `Retry-After` header and issue no token.\n"
    "2. Disable `AGENTFORGE_SYNTHETIC_CONTEXT` outside demos, which removes the anonymous "
    "endpoint entirely; otherwise require an authenticated caller and bind issuance to it.\n"
    "3. Keep the existing short token TTL (300 s).\n"
    "4. Add a target-side test that fails if N rapid anonymous requests all succeed."
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _public_params(request) -> dict:
    """The request fields actually sent on the wire (harness annotations start with `_`)."""
    if not isinstance(request, dict):
        return {}
    return {k: v for k, v in request.items() if not str(k).startswith("_")}


def _is_git_sha(value) -> bool:
    return isinstance(value, str) and 7 <= len(value) <= 40 and all(ch in "0123456789abcdef" for ch in value)


def _decode_token_claims(token: str) -> dict:
    """Best-effort decode of a `payload.signature` demo token's payload (base64url JSON)."""
    try:
        payload = token.split(".", 1)[0]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except (ValueError, TypeError):
        return {}


@dataclass
class DocumentationAgent:
    def _validate(self, finding: dict) -> None:
        missing = [f for f in _REQUIRED if not finding.get(f)]
        if missing:
            raise ValueError(f"finding {finding.get('finding_id')} missing required fields: {missing}")

    # ---- gathering -------------------------------------------------------------------

    def _evidence_for_finding(self, store, finding: dict) -> dict:
        """The actual request/response + oracle detail behind the finding's first verdict, so
        the report shows *what happened*, not just that something did. Also records which
        target and builds the finding was observed on."""
        verdict_ids = json.loads(finding.get("verdict_ids") or "[]")
        if not verdict_ids:
            return {}
        vrow = store.conn.execute(
            "SELECT v.oracle_results, v.evidence_ref, s.expected_safe_ref, a.target_id, a.attempt_id "
            "FROM verdicts v LEFT JOIN attempts a ON a.attempt_id = v.attempt_id "
            "LEFT JOIN attack_specs s ON s.spec_id = a.spec_id WHERE v.verdict_id = ?", (verdict_ids[0],)
        ).fetchone()
        if vrow is None:
            return {}
        out: dict = {"oracle_results": json.loads(vrow["oracle_results"] or "[]"), "exchanges": [],
                     "expected_safe": vrow["expected_safe_ref"] or "", "target_id": vrow["target_id"],
                     "attempt_id": vrow["attempt_id"]}
        if vrow["evidence_ref"]:
            erow = store.conn.execute(
                "SELECT exchanges FROM evidence WHERE evidence_id = ?", (vrow["evidence_ref"],)
            ).fetchone()
            if erow and erow["exchanges"]:
                out["exchanges"] = json.loads(erow["exchanges"])
        marks = ",".join("?" * len(verdict_ids))
        seen = store.conn.execute(
            f"SELECT a.target_sha, a.started_at, a.spec_id FROM verdicts v JOIN attempts a ON a.attempt_id = v.attempt_id "
            f"WHERE v.verdict_id IN ({marks}) ORDER BY a.started_at", verdict_ids
        ).fetchall()
        case = store.conn.execute(
            "SELECT case_id, spec_id FROM regression_cases WHERE finding_id = ?", (finding["finding_id"],)
        ).fetchone()
        # A regression replay that reappears is deduped onto this finding, so its build shows up
        # here too. Mark those sightings: a reappearance on a fix build is a fix-validation result
        # ("reappeared"), not a baseline sighting to hide.
        replay_prefix = f"{case['spec_id']}-rt" if case and case["spec_id"] else None
        out["seen_on"] = [{"sha": r["target_sha"], "at": r["started_at"],
                           "replay": bool(replay_prefix and (r["spec_id"] or "").startswith(replay_prefix))}
                          for r in seen]
        out["regression_case"] = case["case_id"] if case else None
        return out

    def _replays_for_finding(self, store, finding_id: str) -> list[dict]:
        """Regression replays of this finding's frozen case (spec ids `<frozen>-rt<hex>`)."""
        case = store.conn.execute(
            "SELECT spec_id FROM regression_cases WHERE finding_id = ?", (finding_id,)
        ).fetchone()
        if case is None or not case["spec_id"]:
            return []
        rows = store.conn.execute(
            "SELECT a.target_sha, a.started_at, v.outcome FROM attempts a "
            "JOIN verdicts v ON v.attempt_id = a.attempt_id WHERE a.spec_id LIKE ? ORDER BY a.started_at",
            (case["spec_id"] + "-rt%",),
        ).fetchall()
        return [{"sha": r["target_sha"], "at": r["started_at"], "outcome": r["outcome"]} for r in rows]

    def _report_row(self, store, finding_id: str) -> dict | None:
        row = store.conn.execute(
            "SELECT report_id, status, approval FROM vuln_reports WHERE finding_id = ?", (finding_id,)
        ).fetchone()
        return dict(row) if row else None

    def context(self, store, finding: dict, registry=None) -> dict:
        """Everything render_markdown needs beyond the finding row."""
        evidence = self._evidence_for_finding(store, finding)
        target = registry.by_id(evidence["target_id"]) if registry and evidence.get("target_id") else None
        return {"evidence": evidence, "target": target, "report": self._report_row(store, finding["finding_id"]),
                "replays": self._replays_for_finding(store, finding["finding_id"])}

    # ---- classification --------------------------------------------------------------

    @staticmethod
    def _violations(evidence: dict) -> list[dict]:
        return [o for o in evidence.get("oracle_results", []) if o.get("outcome") == "violation"]

    def _kind(self, finding: dict, evidence: dict) -> str:
        """'read-mint' | 'write-mint' | 'mint-rate-limit' | 'generic' — component-aware override."""
        component = finding.get("component") or ""
        if not component.endswith("-context"):
            return "generic"
        if any(o.get("oracle") == "rate_limit" for o in self._violations(evidence)):
            return "mint-rate-limit"
        if finding["primary_category"] == "broken-authentication":
            body = " ".join(str(ex.get("response") or "") for ex in evidence.get("exchanges", []))
            return "write-mint" if ("source-document" in component or '"scope":"write' in body) else "read-mint"
        return "generic"

    # ---- rendering -------------------------------------------------------------------

    def _render_evidence(self, evidence: dict) -> str:
        if not evidence:
            return "_No evidence captured for this finding (attempt predates evidence capture)._\n"
        lines = []
        violations = self._violations(evidence)
        if violations:
            lines.append("**Oracle(s) that fired:** " + ", ".join(
                f"`{o['oracle']}` — {o.get('detail') or 'violation'}" for o in violations))
        for ex in evidence.get("exchanges", []):
            req = json.dumps(ex.get("request"), ensure_ascii=False)
            resp = (ex.get("response") or "")
            resp = resp if len(resp) <= 1200 else resp[:1200] + " …[truncated]"
            latency = ex.get("latency_ms")
            latency = f"{latency:.0f}ms" if isinstance(latency, (int, float)) else f"{latency}ms"
            lines.append(
                f"\n- `{ex.get('method')} {ex.get('route')}` → **HTTP {ex.get('status_code')}** ({latency})\n"
                f"  - request (fields starting `_` are harness annotations, not sent): `{req}`\n"
                f"  - response: `{resp}`"
            )
            claims = self._token_claims(ex)
            if claims:
                lines.append("  - decoded token payload (unsigned view): `"
                             + json.dumps(claims, ensure_ascii=False) + "`")
        return "\n".join(lines) + "\n"

    @staticmethod
    def _token_claims(exchange: dict) -> dict:
        try:
            body = json.loads(exchange.get("response") or "")
        except (ValueError, TypeError):
            return {}
        token = body.get("demo_token") if isinstance(body, dict) else None
        return _decode_token_claims(token) if isinstance(token, str) else {}

    @staticmethod
    def _base_url(target) -> str:
        if target is None:
            return "$TARGET_BASE"   # documented in the repro when the registry wasn't available
        return f"{target.origin}{target.base_path}"

    @staticmethod
    def _url(ex: dict, base: str) -> str:
        url = f"{base}{ex.get('route')}"
        params = _public_params(ex.get("request"))
        if (ex.get("method") or "GET").upper() == "GET" and params:
            url += "?" + urlencode(params)
        return url

    def _curl(self, ex: dict, base: str) -> str:
        method = (ex.get("method") or "GET").upper()
        params = _public_params(ex.get("request"))
        url = self._url(ex, base)
        if method == "GET":
            return f'curl -s "{url}"'
        body = shlex.quote(json.dumps(params, ensure_ascii=False))
        return f'curl -s -X {method} "{url}" -H "Content-Type: application/json" -d {body}'

    def _render_repro(self, finding: dict, evidence: dict, target, kind: str) -> str:
        exchanges = evidence.get("exchanges", [])
        if not exchanges:
            return ("No request/response evidence was captured for this finding, so no exact request "
                    "can be given. Re-run the probe that produced it before relying on this report.\n")
        base = self._base_url(target)
        target_id = evidence.get("target_id") or (target.id if target else "<target-id>")
        out = []
        if target is None:
            out.append("Set `TARGET_BASE` to the target's origin + base path from `authorization.yaml`.\n")
        out.append(f"Record the build under test first: `curl -s \"{base}/health\"` → note `git_sha`.\n")
        out.append("Minimal attack sequence (no credentials, no cookies, no headers):\n")
        steps = []
        validate = ""
        for ex in exchanges:
            req = ex.get("request") if isinstance(ex.get("request"), dict) else {}
            cmd = self._curl(ex, base)
            n = req.get("_repeated")
            if isinstance(n, int) and n > 1:
                url = self._url(ex, base)
                steps.append(f'for i in $(seq 1 {n}); do curl -s -o /dev/null -w "%{{http_code}}\\n" "{url}"; done '
                             f"| sort | uniq -c")
                validate = (f"**Validate (deterministic):** fixed when at least one `429` appears within {n} "
                            f"requests (and later requests carry `Retry-After`). Vulnerable when all {n} return "
                            f"`200`, as observed: {ex.get('response')}.")
            else:
                steps.append(cmd)
        out.append("```bash\n" + "\n".join(steps) + "\n```\n")
        if not validate:
            if kind in ("read-mint", "write-mint"):
                validate = ("**Validate (deterministic):** fixed when the request above returns `401`/`403` "
                            "(or `404` with the synthetic mint disabled) and the body contains no `demo_token`. "
                            "Vulnerable when it returns `200` with a `demo_token`, as observed.")
            else:
                oracles = ", ".join(f"`{o['oracle']}`" for o in self._violations(evidence)) or "the oracle"
                validate = (f"**Validate (deterministic):** fixed when the response no longer triggers "
                            f"{oracles} (see Observed vs expected for the invariant).")
        out.append(validate + "\n")
        case_note = f" (this finding's case is `{evidence['regression_case']}`)" if evidence.get("regression_case") else ""
        out.append(f"Platform replay: re-runs every frozen regression case{case_note} with the same probe and "
                   "oracle against the live target; exit code 0 only if all held. Needs this repo's `.env` "
                   "(see README).\n")
        out.append(f"```bash\nuv run redteam regression --target {target_id} --sha <git_sha from /health>\n```\n")
        return "\n".join(out)

    def _observed(self, evidence: dict, kind: str) -> str:
        exchanges = evidence.get("exchanges", [])
        violations = self._violations(evidence)
        detail = "; ".join(f"`{o['oracle']}`: {o.get('detail') or 'violation'}" for o in violations)
        if kind in ("read-mint", "write-mint") and exchanges:
            ex = exchanges[0]
            claims = self._token_claims(ex)
            scope = claims.get("scope") or "unknown"
            subj = claims.get("patient_uuid") or _public_params(ex.get("request")).get("patient_uuid", "?")
            ttl = ""
            try:
                ttl = f", valid {json.loads(ex.get('response') or '{}').get('expires_in_seconds')} s"
            except (ValueError, TypeError):
                pass
            return (f"an anonymous `{ex.get('method')} {ex.get('route')}` returned HTTP {ex.get('status_code')} "
                    f"with a signed `demo_token` (scope `{scope}`, patient `{subj}`{ttl}). {detail}")
        if exchanges:
            ex = exchanges[0]
            return f"`{ex.get('method')} {ex.get('route')}` → HTTP {ex.get('status_code')}. {detail or 'oracle violation'}"
        return detail or "the deterministic oracle detected a violation"

    def _description(self, finding: dict, kind: str) -> tuple[str, str]:
        c = finding["component"]
        if kind == "read-mint":
            return (f"`{c}` issues a signed, patient-scoped **read** token (`read-briefing`) to any caller, "
                    "with no authentication. The patient routes do verify that token and its patient binding, "
                    "but because the token is free, that check protects nothing: an anonymous caller mints a "
                    "token for any patient id and then reads that patient's chart and AI briefing.",
                    "Anyone on the internet can read any patient's chart. In a real deployment this is a PHI "
                    "confidentiality breach, HIPAA-reportable.")
        if kind == "write-mint":
            return (f"`{c}` issues a signed **write** token (`write-source-document`) to any caller, with no "
                    "authentication. That token is what the document-upload route (`/v1/source-documents`) "
                    "accepts, so an anonymous caller obtains upload capability for a patient's record "
                    "(limited by the target's per-patient upload allow-list).",
                    "Anyone can upload source documents into a patient's record: an integrity breach. A poisoned "
                    "document then feeds the clinician's AI briefing, so it can shape what the clinician reads "
                    "about that patient.")
        if kind == "mint-rate-limit":
            return (f"`{c}` is anonymous and applies no rate limit: every rapid repeated request from one client "
                    "was served with `200`. Absence of a `429` within the observed count is evidence, not proof, "
                    "that no throttle exists at higher volume.",
                    "Lets a script probe patient ids at full speed (enumeration) and abuse cost/availability of "
                    "the Co-Pilot at the point of care. Combined with the anonymous mint, nothing slows bulk "
                    "harvesting of patient-scoped tokens.")
        cat = finding["primary_category"]
        return (_DESCRIPTION.get(cat, f"A confirmed {cat} weakness.") + f" Component: `{c}`.",
                _CLINICAL_IMPACT.get(cat, "Assess against patient safety before triage."))

    @staticmethod
    def _fix_builds(finding: dict, evidence: dict, replays: list[dict]) -> list[dict]:
        """The finding's status on every build after the one it was found on.

        Each build's status is its LATEST observation of any kind: a fresh hunt that re-finds
        the weakness counts exactly like a replay that reappears, so the order the hunt and the
        replay happened to run in cannot decide it. Only a clean replay FAIL is ``held``; any
        other outcome is ``inconclusive``, never a pass. The baseline is the build of the first
        fresh sighting (and ``first_seen_sha`` when recorded); later sightings on it are just
        re-confirmations. Returns ``[{sha, at, result}]`` in order of each build's first event.
        """
        fresh = [{"sha": s["sha"], "at": s["at"] or "", "outcome": "SUCCESS"}
                 for s in evidence.get("seen_on", []) if not s.get("replay")]
        baseline = {fresh[0]["sha"]} if fresh else set()
        if finding.get("first_seen_sha"):
            baseline.add(finding["first_seen_sha"])
        events = sorted(fresh + [{**r, "at": r["at"] or ""} for r in replays], key=lambda e: e["at"])
        latest: dict = {}
        for e in events:
            if e["sha"] not in baseline:
                latest[e["sha"]] = e        # insertion order = first event; value = latest event
        word = {"FAIL": "held", "SUCCESS": "reappeared"}
        return [{"sha": sha, "at": e["at"], "result": word.get(e["outcome"], "inconclusive")}
                for sha, e in latest.items()]

    def _fix_validation(self, finding: dict, evidence: dict, replays: list[dict]) -> str:
        builds = self._fix_builds(finding, evidence, replays)
        if not builds:
            return json.dumps({"sha": None, "result": None})
        return json.dumps(max(builds, key=lambda b: b["at"]))

    def _render_status(self, finding: dict, evidence: dict, report: dict | None, replays: list[dict]) -> str:
        lines = [f"- **Finding status:** `{finding.get('status') or 'new'}`"]
        if report:
            try:
                approval = json.loads(report.get("approval") or "{}")
            except ValueError:
                approval = {}
            appr = ""
            if approval.get("approver"):
                appr = f" (approved by {approval['approver']} at {approval.get('at')})"
            elif approval.get("required"):
                appr = " (held for human approval: critical/high or unevidenced)"
            lines.append(f"- **Report {report['report_id']}:** `{report['status']}`{appr}")
        else:
            lines.append("- **Report:** not yet written to the store")
        seen = list({s["sha"]: s for s in reversed(evidence.get("seen_on", []))}.values())[::-1]  # first sighting per build
        if seen:
            labels = any(not _is_git_sha(s["sha"]) for s in seen)
            lines.append("- **Observed on builds:** " + ", ".join(
                f"`{s['sha'] or 'unrecorded'}` ({(s['at'] or '')[:10]})" for s in seen)
                + (" (non-hex values are run labels recorded before `/health` git SHAs were passed, "
                   "not target commits)" if labels else ""))
        builds = self._fix_builds(finding, evidence, replays)
        lines.append("\n**Fix validation:**")
        if builds:
            for b in builds:
                result = "inconclusive (not a pass)" if b["result"] == "inconclusive" else b["result"]
                lines.append(f"- `{b['sha']}` — {result} ({b['at'][:10]})")
            last = max(builds, key=lambda b: b["at"])
            if last["result"] != "held":
                lines.append(f"- Latest build `{last['sha']}` is {last['result']}: not validated as fixed.")
        else:
            lines.append("No harness replay on a fixed build is recorded in this store yet. See "
                         "`docs/findings/README.md` for the current fix disposition (a fix may be "
                         "deployed, risk-accepted, or pending); validate with the commands above on "
                         "the fixed build's `/health` `git_sha`.")
        return "\n".join(lines) + "\n"

    def render_markdown(self, finding: dict, level: str, evidence: dict | None = None, *,
                        target=None, report: dict | None = None, replays: list[dict] | None = None) -> str:
        evidence = evidence or {}
        kind = self._kind(finding, evidence)
        taxonomy = "; ".join(owasp_label(t["id"]) for t in json.loads(finding["taxonomy"] or "[]")) or "unmapped"
        if kind in ("read-mint", "write-mint"):
            remediation = _MINT_REMEDIATION
        elif kind == "mint-rate-limit":
            remediation = _RATE_LIMIT_REMEDIATION
        else:
            remediation = _REMEDIATION.get(finding["primary_category"],
                                           "Constrain the affected behavior and add a regression test.")
        description, impact = self._description(finding, kind)
        # Expected behavior is the case's own invariant, not a hardcoded LLM-refusal line (wrong for
        # authz/DoS findings where no assistant is in the loop) — derived from expected_safe (T2.3).
        expected = evidence.get("expected_safe") or "the protected invariant holds"
        where = f"{self._base_url(target)}{finding['component']}" if target else finding["component"]
        refs = ", ".join(json.loads(finding.get("verdict_ids") or "[]"))
        return (
            f"# {finding['finding_id']} — {finding['title']}\n\n"
            f"- **ID:** {finding['finding_id']}\n"
            f"- **Severity (provisional):** {level} — confirm with CVSS v4\n"
            f"- **Category:** {finding['primary_category']}\n"
            f"- **Taxonomy:** {taxonomy}\n"
            f"- **Component:** `{where}`\n\n"
            f"## Description\n{description}\n\n"
            f"**Clinical impact:** {impact}\n\n"
            f"_{_SYNTHETIC_NOTE}_\n\n"
            f"## Reproduction\n{self._render_repro(finding, evidence, target, kind)}\n"
            f"## Observed vs expected\n"
            f"- **Observed:** {self._observed(evidence, kind)}\n"
            f"- **Expected:** {expected}.\n\n"
            f"## Evidence (what actually happened)\n{self._render_evidence(evidence)}\n"
            f"## Recommended remediation\n{remediation}\n\n"
            f"## Status\n{self._render_status(finding, evidence, report, replays or [])}\n"
            f"## References\n"
            f"- Verdicts: {refs or 'none'} (platform store; `uv run redteam evidence <attempt_id>` dumps the "
            f"raw exchange{', first attempt `' + evidence['attempt_id'] + '`' if evidence.get('attempt_id') else ''})\n"
        )

    # ---- persistence -----------------------------------------------------------------

    def document(self, store, finding_id: str, registry=None) -> str:
        """Write a VulnReport for a Finding. Returns the report_id. Idempotent per Finding: a
        second call refreshes the derived text fields of the existing report but never creates
        a second row and never touches its status or approval."""
        row = store.conn.execute("SELECT * FROM findings WHERE finding_id = ?", (finding_id,)).fetchone()
        if row is None:
            raise ValueError(f"no such finding: {finding_id}")
        finding = dict(row)
        self._validate(finding)

        try:
            level = json.loads(finding["severity"]).get("provisional_level", "")
        except (ValueError, TypeError, AttributeError):
            level = ""
        ctx = self.context(store, finding, registry)
        evidence = ctx["evidence"]
        kind = self._kind(finding, evidence)
        description, impact = self._description(finding, kind)
        remediation = (_MINT_REMEDIATION if kind in ("read-mint", "write-mint")
                       else _RATE_LIMIT_REMEDIATION if kind == "mint-rate-limit"
                       else _REMEDIATION.get(finding["primary_category"], ""))
        derived = {
            "description": description,
            "clinical_impact": impact,
            "repro": json.dumps({"verdict_ids": json.loads(finding["verdict_ids"] or "[]"),
                                 "exchanges": evidence.get("exchanges", []),
                                 "steps": self._render_repro(finding, evidence, ctx["target"], kind)}),
            "observed_vs_expected": f"{self._observed(evidence, kind)} vs. "
                                    f"{evidence.get('expected_safe') or 'invariant should hold'}",
            "remediation": remediation,
            "fix_validation": self._fix_validation(finding, evidence, ctx["replays"]),
        }

        existing = store.conn.execute("SELECT report_id FROM vuln_reports WHERE finding_id = ?", (finding_id,)).fetchone()
        if existing is not None:
            sets = ", ".join(f"{k} = ?" for k in derived)
            store.conn.execute(f"UPDATE vuln_reports SET {sets} WHERE report_id = ?",
                               (*derived.values(), existing["report_id"]))
            store.conn.commit()
            return existing["report_id"]

        report_id = "R-" + finding_id[2:]
        # Fail closed (role-review T1.5): only an explicit low/medium finding backed by captured
        # evidence may auto-publish. High/critical, an unmapped or malformed severity, or a finding
        # with no evidence is held for a human — the gate never fails open on an unknown.
        has_evidence = bool(evidence.get("exchanges"))
        gated = level not in {"low", "medium"} or not has_evidence
        store.insert("vuln_reports", {
            "schema_version": 1,
            "report_id": report_id,
            "finding_id": finding_id,
            "severity": finding["severity"],
            **derived,
            "status": "pending_approval" if gated else "published",
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
