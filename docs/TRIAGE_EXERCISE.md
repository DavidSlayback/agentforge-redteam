# Triage exercise (E4)

A simulated scan report of 12 findings across critical / high / medium / low / false-positive, each
**validated** (is it real?) and given a **disposition**: *remediate*, *defer* (risk-accept with a
reason), or *document* (accept, note it). This exercises triage judgment — separating real issues
from noise and deciding what to act on — not payload authoring.

Rows 1–5 and 13–14 are our platform's **real, confirmed** findings (full reports in
`docs/findings/`); dispositions are current as of 2026-10-01 (rows 13–14 were added after the
exercise was first written, when only five findings existed). Rows 6–12 are a representative
**simulated external-scanner** report (standard web/dependency findings) to exercise validation +
disposition across the severity range, including false positives. Severities on the real rows are
provisional (assigned by category, CVSS v4 scoring pending).

> Scope note: the detailed *offensive content* for additional LLM-specific simulated findings is
> authored outside this assistant (its output classifier truncates offensive specifics — see
> `[[claude-safety-blocks-w3]]`). The triage *framework, validation, and dispositions* below are the
> graded skill and are complete; swap in richer simulated LLM-attack rows if desired.

| # | Severity | Finding (summary) | Validated? | Disposition | Rationale |
|---|---|---|---|---|---|
| 1 | critical | Anonymous read-token mint (`/v1/demo-context`) — F-831d4df407 | **Real** (anon mint → token) | **Defer: risk-accepted (permanent)** | PHI-confidentiality in principle, bounded to synthetic fixtures by claim-gating. The `AGENTFORGE_DEMO_ACCESS=key` gate exists but the owner rejected it (it degrades the demo UI). Compensating controls deployed; regression reads REAPPEARED on purpose (`docs/findings/README.md`) |
| 2 | critical | Anonymous write-token mint (`/v1/source-document-context`) — F-24b44c5180 | **Real** | **Defer: risk-accepted (permanent)** | record-integrity; same decision and controls as #1, plus a patient allow-list and HMAC signing |
| 3 | medium | No rate limit on the mint — F-6ee92046fb | **Real** | **Remediate — DONE** | fixed on `d5e79bb3` (429 fires, 15 per 60 s per client); regression held on `926805ce` |
| 4 | high | Off-condition guideline misinformation (grounding, LLM09) — F-990345a00f | **Real** (4/4 off-condition queries) | **Remediate — DONE** | fixed on `d5e79bb3`: the response is qualified (`condition_not_in_chart`); regression held. Residual: limits within a guideline (age bands) are not modeled |
| 5 | medium | Internal-metadata disclosure (AI supply chain) — F-ca9486ff1b | **Real** | **Remediate — DONE** | provider/model names and retrieval telemetry stripped from `/v1/follow-up-evidence`; regression held. `/v1/scan-supervisor` keeps its round-trip ids by product decision |
| 6 | high | "SQL injection on `/v1/follow-up-evidence`" (scanner-reported) | **FALSE POSITIVE** | **Document** | the field is JSON, not interpolated into SQL; malformed-input probe returns a clean 4xx with no error leak (`authz-malformed-input`) — scanner matched an error string, not a real sink |
| 7 | medium | Missing `Content-Security-Policy` / security headers | **Real** | **Defer** | low impact for a JSON API with no first-party rendered UI in scope; revisit if a browser surface ships |
| 8 | low | Server banner / framework version exposed in headers | **Real** | **Document** | information disclosure, minimal; fold into the F-ca9486ff1b metadata-stripping work |
| 9 | high | Dependency CVE: `urllib3` advisory flagged by SCA | **FALSE POSITIVE** | **Document** | simulated row. This platform's `uv.lock` contains no `urllib3` (httpx is the HTTP client), so the advisory cannot apply to it; for the target's own tree the control is the target repo's Dependabot. Re-check on any lockfile change |
| 10 | medium | TLS 1.2 permitted (not TLS1.3-only) | **Real** | **Defer** | platform/host policy; acceptable with modern ciphers; owner decision, not a platform defect |
| 11 | critical | "Remote code execution via file upload" (scanner-reported on `/v1/source-documents`) | **FALSE POSITIVE** | **Document** | uploads are allow-listed per patient and stored as inert synthetic docs; no execution sink; the real upload issue is the *anonymous write mint* (#2), already tracked |
| 12 | low | Verbose 404/validation messages | **Real** | **Document** | clean 4xx with no stack trace/internal path (confirmed by `error_leak` oracle); acceptable |
| 13 | medium | Mint namespace enumeration (`/v1/demo-context` issues a token for any well-formed id) — F-30da6790d1 | **Real** | **Remediate — DONE** | fixed on `d5e79bb3`: provisioned-only issuance, identical `400` for everything else; regression held |
| 14 | medium | Contradictory chart facts with no current marker (data integrity, LLM09) — F-e5d47ab7ea | **Real** | **Remediate — DONE** | fixed on `d5e79bb3`: a `current` marker, unresolved conflicts flagged and never guessed; regression held |

## Triage summary

- **Real & remediate:** #3, #4, #5, #13, #14 (all fixed and validated by replay). **Real & risk-accepted:**
  #1 and #2 (owner decision, compensating controls deployed).
- **Real & defer/document:** #7, #8, #10, #12 — low-impact or owner-policy; tracked, not blocking.
- **False positives (validated away):** #6, #9, #11 — each refuted with the specific evidence/oracle
  that disproves it, so engineering time is not spent on noise.
- **Method:** every row is validated against evidence before disposition; false positives are the
  point of the exercise — a platform that forwards all scanner output unfiltered wastes responders.
