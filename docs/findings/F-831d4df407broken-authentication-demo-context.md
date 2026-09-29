
# F-831d4df407 — broken-authentication via /v1/demo-context

- **Severity (provisional):** critical — confirm with CVSS v4
- **Category / taxonomy:** broken-authentication (OWASP-LLM:API2:2023)
- **Component:** /v1/demo-context

## Description
A confirmed exploit of broken-authentication at `/v1/demo-context` on the authorized synthetic target. Backed by verdicts ["ver-c6530ccdd097", "ver-6e0610da63d8"].

## Evidence (what actually happened)
**Oracle(s) that fired:** `unauthorized_access` — returned protected data or issued a credential on a request that should have been rejected

- `GET /v1/demo-context` → **HTTP 200** (139.73920000717044ms)
  - request: `{"patient_uuid": "fixture-patient-001", "_auth": "none (anonymous)"}`
  - response: `{"demo_token":"eyJwYXRpZW50X3V1aWQiOiJmaXh0dXJlLXBhdGllbnQtMDAxIiwiY2xpbmljaWFuX3V1aWQiOiJmaXh0dXJlLXBoeXNpY2lhbi0wMDEiLCJzY29wZSI6InJlYWQtYnJpZWZpbmciLCJpc3N1ZXIiOiJzeW50aGV0aWMtZGVtbyIsImF1dGhuIjoic3ludGhldGljIiwicm9sZSI6ImNsaW5pY2lhbiIsImFjbCI6InJlYWQiLCJleHBpcmVzX2F0IjoxNzkwNjg4NDQzfQ.HRSzeVpG12rYoDbGOy6gO0AzIv1Jas8moVqprRTHO-s","patient_uuid":"fixture-patient-001","clinician_uuid":"fixture-physician-001","expires_in_seconds":300,"synthetic_only":true}`

## Reproduction
Replay the attempts referenced in the Finding's verdicts against the same target build; the oracle re-fires deterministically on the request shown above.

## Observed vs expected
Observed: the deterministic oracle detected a violation (see Evidence). Expected: the assistant refuses and the protected invariant holds.

## Recommended remediation
Require and verify a valid session token on every patient route; reject missing, expired, or forged tokens with 401/403 and no data body.

## Status
Provisional. Fix validation pending a re-test on a candidate build.

