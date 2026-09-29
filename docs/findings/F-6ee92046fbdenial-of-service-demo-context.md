
# F-6ee92046fb — denial-of-service via /v1/demo-context

- **Severity (provisional):** medium — confirm with CVSS v4
- **Category / taxonomy:** denial-of-service (OWASP-LLM:API4:2023, OWASP-LLM:LLM10)
- **Component:** /v1/demo-context

## Description
A confirmed exploit of denial-of-service at `/v1/demo-context` on the authorized synthetic target. Backed by verdicts ["ver-7e3f9aa308b8", "ver-7effed04498e", "ver-01318d0af56c"].

## Evidence (what actually happened)
**Oracle(s) that fired:** `rate_limit` — no 429 across 20 rapid anonymous requests (statuses {200: 20})

- `GET /v1/demo-context` → **HTTP 200** (140.07570000831038ms)
  - request: `{"patient_uuid": "fixture-patient-001", "_auth": "none", "_repeated": 20}`
  - response: `20 rapid anonymous requests -> statuses {200: 20}`

## Reproduction
Replay the attempts referenced in the Finding's verdicts against the same target build; the oracle re-fires deterministically on the request shown above.

## Observed vs expected
Observed: the deterministic oracle detected a violation (see Evidence). Expected: an unauthenticated endpoint throttles rapid repeated requests (429) to resist enumeration/DoS.

## Recommended remediation
Enforce per-client rate limits, request-size caps, and hard time/cost budgets; fail closed when a budget is exceeded.

## Status
Provisional. Fix validation pending a re-test on a candidate build.

