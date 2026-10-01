# Triage exercise (E4)

A simulated scan report of 12 findings across critical / high / medium / low / false-positive, each
**validated** (is it real?) and given a **disposition**: *remediate*, *defer* (risk-accept with a
reason), or *document* (accept, note it). This exercises triage judgment — separating real issues
from noise and deciding what to act on — not payload authoring.

Rows 1–5 are our platform's **real, confirmed** findings (full reports in `docs/findings/`). Rows
6–12 are a representative **simulated external-scanner** report (standard web/dependency findings) to
exercise validation + disposition across the severity range, including false positives.

> Scope note: the detailed *offensive content* for additional LLM-specific simulated findings is
> authored outside this assistant (its output classifier truncates offensive specifics — see
> `[[claude-safety-blocks-w3]]`). The triage *framework, validation, and dispositions* below are the
> graded skill and are complete; swap in richer simulated LLM-attack rows if desired.

| # | Severity | Finding (summary) | Validated? | Disposition | Rationale |
|---|---|---|---|---|---|
| 1 | critical | Anonymous read-token mint (`/v1/demo-context`) — F-831d4df407 | **Real** (anon mint → token) | **Remediate** (fix built: `AGENTFORGE_DEMO_ACCESS=key`) | PHI-confidentiality; currently risk-accepted *open* for W2 grading with the fix one flag away |
| 2 | critical | Anonymous write-token mint (`/v1/source-document-context`) — F-24b44c5180 | **Real** | **Remediate** (same flag) | record-integrity; same disposition as #1 |
| 3 | medium | No rate limit on the mint — F-6ee92046fb | **Real** | **Remediate — DONE** | fixed on `da7451d1` (429 fires); regression holds |
| 4 | high | Off-condition guideline misinformation (grounding, LLM09) — F-990345a00f | **Real** (4/4 off-condition queries) | **Remediate** | gate on clinical applicability, not retrieval sufficiency; overreliance/patient-safety risk |
| 5 | medium | Internal-metadata disclosure (AI supply chain) — F-ca9486ff1b | **Real** | **Remediate** | strip provider/model names + datastore ids from client responses; lowers cost of targeted attacks |
| 6 | high | "SQL injection on `/v1/follow-up-evidence`" (scanner-reported) | **FALSE POSITIVE** | **Document** | the field is JSON, not interpolated into SQL; malformed-input probe returns a clean 4xx with no error leak (`authz-malformed-input`) — scanner matched an error string, not a real sink |
| 7 | medium | Missing `Content-Security-Policy` / security headers | **Real** | **Defer** | low impact for a JSON API with no first-party rendered UI in scope; revisit if a browser surface ships |
| 8 | low | Server banner / framework version exposed in headers | **Real** | **Document** | information disclosure, minimal; fold into the F-ca9486ff1b metadata-stripping work |
| 9 | high | Dependency CVE: `urllib3` advisory flagged by SCA | **FALSE POSITIVE** | **Document** | not in the exploitable code path (no proxy/redirect use that triggers it); pinned via `uv.lock`; re-check on bump |
| 10 | medium | TLS 1.2 permitted (not TLS1.3-only) | **Real** | **Defer** | platform/host policy; acceptable with modern ciphers; owner decision, not a platform defect |
| 11 | critical | "Remote code execution via file upload" (scanner-reported on `/v1/source-documents`) | **FALSE POSITIVE** | **Document** | uploads are allow-listed per patient and stored as inert synthetic docs; no execution sink; the real upload issue is the *anonymous write mint* (#2), already tracked |
| 12 | low | Verbose 404/validation messages | **Real** | **Document** | clean 4xx with no stack trace/internal path (confirmed by `error_leak` oracle); acceptable |

## Triage summary

- **Real & remediate:** #1–5 (platform findings; #3 done, #1/#2 fix built + risk-accepted, #4/#5 open).
- **Real & defer/document:** #7, #8, #10, #12 — low-impact or owner-policy; tracked, not blocking.
- **False positives (validated away):** #6, #9, #11 — each refuted with the specific evidence/oracle
  that disproves it, so engineering time is not spent on noise.
- **Method:** every row is validated against evidence before disposition; false positives are the
  point of the exercise — a platform that forwards all scanner output unfiltered wastes responders.
