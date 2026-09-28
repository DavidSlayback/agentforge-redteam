---
status: accepted
date: 2026-09-28
---

# Black-box access modes (the no-token version)

The demo-context token minting (S3) is a **test scaffold**, not the attack surface. It
stands in for a *victim clinician's authenticated session* so injection attempts reach the
AI. A real external attacker of a production deployment would not have it — in production
`AGENTFORGE_SYNTHETIC_CONTEXT` is off and `/v1/demo-context` returns 404. So the platform
must not *depend* on token minting to be a red team; it must generalize over how access is
obtained, and treat the token as one mode among several.

## Access modes (an `AccessProvider` the runner asks for per case)

| Mode | Who the attacker is | How access is obtained | What it tests |
|---|---|---|---|
| `unauthenticated` | External, no session | none — hit the endpoint directly | Unauth surfaces: `/v1/traces`, `/v1/metrics`, `/observability`, `/evals` (PHI-in-logs, info disclosure, stored-XSS). **Already supported today**: a case with `auth=None` sends no token. |
| `indirect` | External, supplies content only | a *victim's* authenticated session processes attacker-controlled content (a malicious upload, poisoned OCR text, a document field) | Indirect prompt injection (LLM01). The token scaffolds the victim session; the **payload is what the attacker really controls**. The finding is about content-influence, not access. |
| `synthetic-token` | Test convenience | mint via `/v1/demo-context` (current `TokenMinter`) | Direct authenticated probing during development. A scaffold, not a realistic external vector. |
| `token-manipulation` | External, has one token or none | take a legitimate token and mutate it, or forge one | Auth failures / identity exploitation (PRD "identity and role"): replay, expiry bypass, scope escalation (read→write), cross-patient reuse, HMAC forgery on the module. |

## Consequences

- The current `TokenMinter` is the `synthetic-token` provider. `unauthenticated` already
  works (no auth fields). `indirect` reuses `synthetic-token` for the victim session but the
  Red Team owns the payload — no new access code, just where the payload sits. Only
  `token-manipulation` is new provider code (a transform over a base token, or a forger).
- **The most realistic and highest-value black-box work needs no mint at all**:
  unauthenticated-surface attacks and indirect content injection. The demo-context path is a
  convenience for reaching the AI quickly, not the threat model's center.
- The threat model (`THREAT_MODEL.md`) should be written around these modes, and each eval
  case tagged with its access mode, so coverage is honest about *how* an attacker would get
  there — not just which category was hit.
- If demo-context is disabled on the target, the platform loses only the `synthetic-token`
  convenience; `unauthenticated` and `token-manipulation` (forgery) still run fully.

## Not doing

We do not attempt to steal or ride a real clinician's live session, and we do not implement
credential theft. The `token-manipulation` mode operates only on synthetic tokens for the
authorized synthetic target.
