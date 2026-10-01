# F-30da6790d1 — enumeration via /v1/demo-context

- **ID:** F-30da6790d1
- **Severity (provisional):** medium — confirm with CVSS v4
- **Category:** enumeration
- **Taxonomy:** OWASP API Security Top 10 2023: API1 Broken Object Level Authorization; OWASP API Security Top 10 2023: API3 Broken Object Property Level Authorization
- **Component:** `https://dtstest.64.177.10.182.nip.io/agentforge-w2/v1/demo-context`

## Description
The anonymous synthetic-context mint issues a valid token for any well-formed patient id in the namespace (including ids that do not exist), and the data route returns 200 for real patients and 404 for others — letting an unauthenticated caller map the patient namespace. Component: `/v1/demo-context`.

**Clinical impact:** An unauthenticated attacker can discover which patients exist and the shape of the patient population — a confidentiality/recon exposure and the precursor to targeted record access; in production a privacy-reportable leak of patient existence.

_The target serves synthetic fixture patients only; no real PHI was accessed. The impact statement describes the same defect in a real deployment._

## Reproduction
Record the build under test first: `curl -s "https://dtstest.64.177.10.182.nip.io/agentforge-w2/health"` → note `git_sha`.

Minimal attack sequence (no credentials, no cookies, no headers):

```bash
curl -s "https://dtstest.64.177.10.182.nip.io/agentforge-w2/v1/demo-context?patient_uuid=fixture-patient-995"
```

**Validate (deterministic):** fixed when the response no longer triggers `enumeration` (see Observed vs expected for the invariant).

Platform replay: re-runs every frozen regression case (this finding's case is `reg-4f5ac656a5`) with the same probe and oracle against the live target; exit code 0 only if all held. Needs this repo's `.env` (see README).

```bash
uv run redteam regression --target agentforge-w2 --sha <git_sha from /health>
```

## Observed vs expected
- **Observed:** `GET /v1/demo-context` → HTTP 200. `enumeration`: mint issued a token for an unprovisioned namespace id (fixture-patient-995) — enables enumeration
- **Expected:** the mint issues tokens only for provisioned patients, not for any well-formed id in the namespace.

## Evidence (what actually happened)
**Oracle(s) that fired:** `enumeration` — mint issued a token for an unprovisioned namespace id (fixture-patient-995) — enables enumeration

- `GET /v1/demo-context` → **HTTP 200** (212ms)
  - request (fields starting `_` are harness annotations, not sent): `{"patient_uuid": "fixture-patient-995", "_auth": "none (anonymous)"}`
  - response: `{"demo_token":"eyJwYXRpZW50X3V1aWQiOiJmaXh0dXJlLXBhdGllbnQtOTk1IiwiY2xpbmljaWFuX3V1aWQiOiJmaXh0dXJlLXBoeXNpY2lhbi0wMDEiLCJzY29wZSI6InJlYWQtYnJpZWZpbmciLCJpc3N1ZXIiOiJzeW50aGV0aWMtZGVtbyIsImF1dGhuIjoic3ludGhldGljIiwicm9sZSI6ImNsaW5pY2lhbiIsImFjbCI6InJlYWQiLCJhdWQiOiJhZ2VudGZvcmdlLXcyIiwiZXhwaXJlc19hdCI6MTc5MDgxODU3NH0.Vr4QZTfZdk_6nfNRw_QYBEawLBpJJ7idvBVC66TaRWs","patient_uuid":"fixture-patient-995","clinician_uuid":"fixture-physician-001","expires_in_seconds":300,"synthetic_only":true}`
  - decoded token payload (unsigned view): `{"patient_uuid": "fixture-patient-995", "clinician_uuid": "fixture-physician-001", "scope": "read-briefing", "issuer": "synthetic-demo", "authn": "synthetic", "role": "clinician", "acl": "read", "aud": "agentforge-w2", "expires_at": 1790818574}`

## Recommended remediation
Issue session tokens only for provisioned patients (check existence/authorization at mint time, not after); return a uniform response for unknown vs existing patients so 200/404 does not reveal existence; and keep the per-client rate limit. Gating the mint entirely was declined for physician experience, so uniform responses + provisioned-only issuance are the controls.

## Status
- **Finding status:** `new`
- **Report R-30da6790d1:** `published`
- **Observed on builds:** `da7451d1c9bb2c32bd0625840d28103fa13d4529` (2026-10-01)

**Fix validation:**
No harness replay on a fixed build is recorded in this store yet. See `docs/findings/README.md` for the current fix disposition (a fix may be deployed, risk-accepted, or pending); validate with the commands above on the fixed build's `/health` `git_sha`.

## References
- Verdicts: ver-00cbaa93dd98 (platform store; `uv run redteam evidence <attempt_id>` dumps the raw exchange, first attempt `att-a1ba5eb297ae`)
