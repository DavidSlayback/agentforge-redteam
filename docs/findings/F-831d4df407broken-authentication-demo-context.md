# F-831d4df407 — broken-authentication via /v1/demo-context

- **ID:** F-831d4df407
- **Severity (provisional):** critical — confirm with CVSS v4
- **Category:** broken-authentication
- **Taxonomy:** OWASP API Security Top 10 2023: API2 Broken Authentication
- **Component:** `https://dtstest.64.177.10.182.nip.io/agentforge-w2/v1/demo-context`

## Description
`/v1/demo-context` issues a signed, patient-scoped **read** token (`read-briefing`) to any caller, with no authentication. The patient routes do verify that token and its patient binding, but because the token is free, that check protects nothing: an anonymous caller mints a token for any patient id and then reads that patient's chart and AI briefing.

**Clinical impact:** Anyone on the internet can read any patient's chart. In a real deployment this is a PHI confidentiality breach, HIPAA-reportable.

_The target serves synthetic fixture patients only; no real PHI was accessed. The impact statement describes the same defect in a real deployment._

## Reproduction
Record the build under test first: `curl -s "https://dtstest.64.177.10.182.nip.io/agentforge-w2/health"` → note `git_sha`.

Minimal attack sequence (no credentials, no cookies, no headers):

```bash
curl -s "https://dtstest.64.177.10.182.nip.io/agentforge-w2/v1/demo-context?patient_uuid=fixture-patient-001"
```

**Validate (deterministic):** fixed when the request above returns `401`/`403` (or `404` with the synthetic mint disabled) and the body contains no `demo_token`. Vulnerable when it returns `200` with a `demo_token`, as observed.

Platform replay: re-runs every frozen regression case (this finding's case is `reg-32b265ec31`) with the same probe and oracle against the live target; exit code 0 only if all held. Needs this repo's `.env` (see README).

```bash
uv run redteam regression --target agentforge-w2 --sha <git_sha from /health>
```

## Observed vs expected
- **Observed:** an anonymous `GET /v1/demo-context` returned HTTP 200 with a signed `demo_token` (scope `read-briefing`, patient `fixture-patient-001`, valid 300 s). `unauthorized_access`: returned protected data or issued a credential on a request that should have been rejected
- **Expected:** minting a patient session token requires authentication; an anonymous request is rejected.

## Evidence (what actually happened)
**Oracle(s) that fired:** `unauthorized_access` — returned protected data or issued a credential on a request that should have been rejected

- `GET /v1/demo-context` → **HTTP 200** (140ms)
  - request (fields starting `_` are harness annotations, not sent): `{"patient_uuid": "fixture-patient-001", "_auth": "none (anonymous)"}`
  - response: `{"demo_token":"eyJwYXRpZW50X3V1aWQiOiJmaXh0dXJlLXBhdGllbnQtMDAxIiwiY2xpbmljaWFuX3V1aWQiOiJmaXh0dXJlLXBoeXNpY2lhbi0wMDEiLCJzY29wZSI6InJlYWQtYnJpZWZpbmciLCJpc3N1ZXIiOiJzeW50aGV0aWMtZGVtbyIsImF1dGhuIjoic3ludGhldGljIiwicm9sZSI6ImNsaW5pY2lhbiIsImFjbCI6InJlYWQiLCJleHBpcmVzX2F0IjoxNzkwNjg4NDQzfQ.HRSzeVpG12rYoDbGOy6gO0AzIv1Jas8moVqprRTHO-s","patient_uuid":"fixture-patient-001","clinician_uuid":"fixture-physician-001","expires_in_seconds":300,"synthetic_only":true}`
  - decoded token payload (unsigned view): `{"patient_uuid": "fixture-patient-001", "clinician_uuid": "fixture-physician-001", "scope": "read-briefing", "issuer": "synthetic-demo", "authn": "synthetic", "role": "clinician", "acl": "read", "expires_at": 1790688443}`

## Recommended remediation
1. Disable `AGENTFORGE_SYNTHETIC_CONTEXT` in every deployment that is not an explicit demo; with it off, the route must return 404/403 and issue no token.
2. Where a demo mint must stay on, require an authenticated caller (evaluator access code or session) and bind issuance to that caller's identity: mint only for patients the caller may access, and log caller → patient → scope for every token issued.
3. Rate-limit the mint per client (return `429` with `Retry-After`).
4. Keep the existing short token TTL (300 s) and the token↔patient binding; do not lengthen the TTL to compensate.
5. Add a target-side test that fails if an anonymous request to the mint returns a token.

## Status
- **Finding status:** `new`
- **Report R-831d4df407:** `pending_approval` (held for human approval: critical/high or unevidenced)
- **Observed on builds:** `live-2026-09-29` (2026-09-29), `refactor-smoke` (2026-09-29), `refactor23-smoke` (2026-09-29), `bfbb1eb20716a032918067937154f8d6b5001b87` (2026-09-29), `da7451d1c9bb2c32bd0625840d28103fa13d4529` (2026-09-29) (non-hex values are run labels recorded before `/health` git SHAs were passed, not target commits)

**Fix validation:**
Not yet validated: fix pending in target repo (agentforge-week1 branch agentforge/w3-redteam-fixes); validate with the commands above on the new `/health` `git_sha`.

## References
- Verdicts: ver-c6530ccdd097, ver-6e0610da63d8, ver-cf0782f29f43, ver-60aa42574aca, ver-31d68c30cebe, ver-b05ff61b332e, ver-d96c0e931107, ver-49e2655ff40f, ver-966655cf3a92, ver-979b17a70de0 (platform store; `uv run redteam evidence <attempt_id>` dumps the raw exchange, first attempt `att-10671c0438fa`)
