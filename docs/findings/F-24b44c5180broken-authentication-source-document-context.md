
# F-24b44c5180 — broken-authentication via /v1/source-document-context

- **Severity (provisional):** critical — confirm with CVSS v4
- **Category / taxonomy:** broken-authentication (OWASP-LLM:API2:2023)
- **Component:** /v1/source-document-context

## Description
A confirmed exploit of broken-authentication at `/v1/source-document-context` on the authorized synthetic target. Backed by verdicts ["ver-f7e389268992", "ver-314f35240902", "ver-6eb0962caf2d"].

## Evidence (what actually happened)
**Oracle(s) that fired:** `unauthorized_access` — returned protected data or issued a credential on a request that should have been rejected

- `GET /v1/source-document-context` → **HTTP 200** (133.61470005474985ms)
  - request: `{"patient_uuid": "fixture-patient-001", "_auth": "none (anonymous)"}`
  - response: `{"demo_token":"eyJwYXRpZW50X3V1aWQiOiJmaXh0dXJlLXBhdGllbnQtMDAxIiwiY2xpbmljaWFuX3V1aWQiOiJmaXh0dXJlLXBoeXNpY2lhbi0wMDEiLCJzY29wZSI6IndyaXRlLXNvdXJjZS1kb2N1bWVudCIsImlzc3VlciI6InN5bnRoZXRpYy1kZW1vIiwiYXV0aG4iOiJzeW50aGV0aWMiLCJyb2xlIjoiY2xpbmljaWFuIiwiYWNsIjoid3JpdGUiLCJleHBpcmVzX2F0IjoxNzkwNjg5MzMwfQ.DhomeFY2rFLwP-uAj7h9PMAHwvFa0AR13moCMOy5hrk","patient_uuid":"fixture-patient-001","clinician_uuid":"fixture-physician-001","expires_in_seconds":300,"synthetic_only":true,"scope":"write-source-document"}`

## Reproduction
Replay the attempts referenced in the Finding's verdicts against the same target build; the oracle re-fires deterministically on the request shown above.

## Observed vs expected
Observed: the deterministic oracle detected a violation (see Evidence). Expected: minting a session token requires authentication; an anonymous request is rejected.

## Recommended remediation
Require and verify a valid session token on every patient route; reject missing, expired, or forged tokens with 401/403 and no data body.

## Status
Provisional. Fix validation pending a re-test on a candidate build.

