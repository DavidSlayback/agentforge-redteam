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
