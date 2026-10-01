---
status: accepted
date: 2026-09-28
---

# One Executor is the only path to the Target

Only the deterministic Executor service can open a network connection to the Target. It
checks the authorization registry on every request, holds the Target credentials and
synthetic identities, and records each exchange. The Red Team Agent produces attack
specifications as data and never sends a request itself. The Red Team is the least
trusted component, since it writes adversarial text by design, so it gets neither
network access nor credentials. With one door, the authorization gate is structural,
not a policy each agent is supposed to follow; this is how the platform satisfies the
PRD's requirement that it cannot be turned against systems it should not attack.

## Considered options

- **Each agent calls the Target directly through a shared client library.** Rejected:
  authorization becomes a convention every caller must honor, and a prompt-injected or
  misbehaving agent could bypass it.
- **Red Team drives PyRIT's HTTP target itself.** Rejected for the same reason; PyRIT is
  used inside the Executor instead.

## Consequences

- The Executor is a throughput bottleneck by design; rate limiting, backoff, and budget
  enforcement live there.
- Multi-turn attacks are expressed as specifications the Executor plays out turn by turn,
  so the Red Team adapts between turns through the store rather than holding a live
  session.

## Implementation status (2026-10-01)

The boundary is built and tested: only `executor/http_sender.py` opens a socket to a target, every
request passes `AuthorizationRegistry.assert_authorized`, redirects are never followed, and the
registry loads fail-closed. Two consequences above are narrower than written. The Executor enforces
**authorization and a 90 s timeout**, not rate limiting, backoff or budget: the only backoff is the
token minter's `Retry-After` wait on a mint `429` (2 retries), and the budget lives in the
Orchestrator's `CallBudget` and Governor. Multi-turn play-out is not implemented, because the target's
composer is stateless. Model providers (attacker, rubric, discovery, Jev) are called directly by their
clients and are outside the gate, which governs targets. `docs/EXTERNAL_APIS.md` has the per-API
detail.
