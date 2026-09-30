# F-6ee92046fb — denial-of-service via /v1/demo-context

- **ID:** F-6ee92046fb
- **Severity (provisional):** medium — confirm with CVSS v4
- **Category:** denial-of-service
- **Taxonomy:** OWASP API Security Top 10 2023: API4 Unrestricted Resource Consumption; OWASP LLM Top 10 2025: LLM10 Unbounded Consumption
- **Component:** `https://dtstest.64.177.10.182.nip.io/agentforge-w2/v1/demo-context`

## Description
`/v1/demo-context` is anonymous and applies no rate limit: every rapid repeated request from one client was served with `200`. Absence of a `429` within the observed count is evidence, not proof, that no throttle exists at higher volume.

**Clinical impact:** Lets a script probe patient ids at full speed (enumeration) and abuse cost/availability of the Co-Pilot at the point of care. Combined with the anonymous mint, nothing slows bulk harvesting of patient-scoped tokens.

_The target serves synthetic fixture patients only; no real PHI was accessed. The impact statement describes the same defect in a real deployment._

## Reproduction
Record the build under test first: `curl -s "https://dtstest.64.177.10.182.nip.io/agentforge-w2/health"` → note `git_sha`.

Minimal attack sequence (no credentials, no cookies, no headers):

```bash
for i in $(seq 1 20); do curl -s -o /dev/null -w "%{http_code}\n" "https://dtstest.64.177.10.182.nip.io/agentforge-w2/v1/demo-context?patient_uuid=fixture-patient-001"; done | sort | uniq -c
```

**Validate (deterministic):** fixed when at least one `429` appears within 20 requests (and later requests carry `Retry-After`). Vulnerable when all 20 return `200`, as observed: 20 rapid anonymous requests -> statuses {200: 20}.

Platform replay: re-runs every frozen regression case (this finding's case is `reg-e7eb5a693a`) with the same probe and oracle against the live target; exit code 0 only if all held. Needs this repo's `.env` (see README).

```bash
uv run redteam regression --target agentforge-w2 --sha <git_sha from /health>
```

## Observed vs expected
- **Observed:** `GET /v1/demo-context` → HTTP 200. `rate_limit`: no 429 across 20 rapid anonymous requests (statuses {200: 20})
- **Expected:** an unauthenticated endpoint throttles rapid repeated requests (429) to resist enumeration/DoS.

## Evidence (what actually happened)
**Oracle(s) that fired:** `rate_limit` — no 429 across 20 rapid anonymous requests (statuses {200: 20})

- `GET /v1/demo-context` → **HTTP 200** (140ms)
  - request (fields starting `_` are harness annotations, not sent): `{"patient_uuid": "fixture-patient-001", "_auth": "none", "_repeated": 20}`
  - response: `20 rapid anonymous requests -> statuses {200: 20}`

## Recommended remediation
1. Add a per-client (per-IP and, once authenticated, per-caller) rate limit on the mint; over the limit return `429` with a `Retry-After` header and issue no token.
2. Disable `AGENTFORGE_SYNTHETIC_CONTEXT` outside demos, which removes the anonymous endpoint entirely; otherwise require an authenticated caller and bind issuance to it.
3. Keep the existing short token TTL (300 s).
4. Add a target-side test that fails if N rapid anonymous requests all succeed.

## Status
- **Finding status:** `new`
- **Report R-6ee92046fb:** `published`
- **Observed on builds:** `live-2026-09-29` (2026-09-29), `refactor-smoke` (2026-09-29), `refactor23-smoke` (2026-09-29), `bfbb1eb20716a032918067937154f8d6b5001b87` (2026-09-29) (non-hex values are run labels recorded before `/health` git SHAs were passed, not target commits)

**Fix validation:**
- `da7451d1c9bb2c32bd0625840d28103fa13d4529` — held (2026-09-29)
- `da7451d1c9bb2c32bd0625840d28103fa13d4529` — held (2026-09-30)
- `da7451d1c9bb2c32bd0625840d28103fa13d4529` — held (2026-09-30)

## References
- Verdicts: ver-7e3f9aa308b8, ver-7effed04498e, ver-01318d0af56c, ver-bc5235422c88, ver-c66d0370044e (platform store; `uv run redteam evidence <attempt_id>` dumps the raw exchange, first attempt `att-728b25f521db`)
