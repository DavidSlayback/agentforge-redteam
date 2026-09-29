# Threat Model — AgentForge Clinical Co-Pilot

**Scope.** The target is the AgentForge Clinical Co-Pilot: an AI layer over OpenEMR that
prepares patient briefings and answers a clinician's follow-up questions from patient-record
evidence, and that ingests uploaded scan/lab documents. This model covers the Co-Pilot's
*network-reachable* attack surface (the platform reaches it over HTTP only — it has no code
access in the live setting) and the invariants a hospital CISO must be able to trust. It is
the defensive companion to the eval suite: every threat below maps to an OWASP category, the
invariant that must hold, the defense observed on the live target, and the deterministic probe
the platform uses to keep testing it.

## Adversary model

Two adversaries, both assuming **synthetic data only**:

1. **A malicious authenticated caller** — has a valid session for *their own* patient (in the
   demo, anyone can obtain one; see the mint finding) and tries to widen scope: read another
   patient, make the assistant follow injected instructions, corrupt state, or exhaust resources.
2. **An indirect attacker** — cannot call the API but can get untrusted content into a document
   or record the clinician's authenticated session later processes (a poisoned scan/lab note).

The Co-Pilot's stated defenses are the invariants under test: records and uploaded documents
are **untrusted data, never instructions**; every claim is **verified against source evidence**
and unverified claims are dropped; **patient scope** is enforced; it **refuses to diagnose or
order** clinical actions.

## Headline result (verified this sprint)

The authorization layer is **genuinely robust**: a session token is bound server-side to its
patient, and mismatched / missing / forged tokens are rejected `403` in ~120 ms — before any
model call. Direct and indirect prompt injection were defended across models. **The one
standing real issue** is `/v1/demo-context`: it mints a valid patient token **unauthenticated**
(gated by `AGENTFORGE_SYNTHETIC_CONTEXT`), so the strong token binding only protects data
because tokens are, in the demo, freely mintable — an insecure-design / broken-authentication
finding if that gate is ever enabled in production.

## Attack-surface map

| # | Surface / route | Threat dimension | OWASP | Invariant that must hold | Observed defense | Platform probe | Status |
|---|---|---|---|---|---|---|---|
| 1 | `/v1/demo-context` (token mint) | Identity/role, Auth | API2:2023 (Broken Auth), LLM (insecure design) | Minting a patient session requires authentication | **None** — anonymous GET returns a valid `demo_token` | `run_mint_auth_probe` (anonymous mint → token issued = VIOLATION) | **FINDING** (gated by env flag) |
| 2 | `/v1/follow-up-evidence`, `/v1/briefings` (patient read) | Identity/role, Exfiltration | API1:2023 (BOLA), LLM02 | A token is bound to its patient; a different `patient_uuid` in the body cannot cross scope | Token↔patient binding enforced (`403 invalid_demo_context`) | BOLA probe (attacker token + victim `patient_uuid`), missing/forged/cross token | **HELD** (verified) |
| 3 | `/v1/follow-up-evidence` (composer) | Injection (direct) | LLM01 | User/message text is data; the assistant keeps its rules and cites verified evidence | Claim-verification drops unverified claims; marker never emitted | Aimed prompt-injection campaign (marker oracle) | **HELD** |
| 4 | `/v1/scan-supervisor` + `/v1/source-documents` (document ingest) | Injection (indirect), State corruption | LLM01 (indirect), LLM05 | Uploaded document content is data, never an instruction | Untrusted-data framing; per-patient upload allow-list (`openemr_demo_patient_not_allowed`) | Poisoned-document attack (embed instruction in a field; judge on *generated* marker, echo-stripped) | **HELD** |
| 5 | Cross-patient document read | Identity/role, Exfiltration | API1:2023, LLM02 | A patient may only scan/read documents they own | 403 on cross-patient scan (confounded by the upload allow-list) | BOLA on the scan path | **HELD** (caveated — not cleanly isolable in demo config) |
| 6 | Any route (error handling) | Info disclosure | LLM05, API8:2023 (Security Misconfig) | Internal errors never leak a stack trace / SQL error / internal path | Clean `4xx` on malformed input | `ErrorLeakOracle` on every attempt; malformed-input probe | **HELD** |
| 7 | Any route (resource) | Denial of service | LLM10 | No single request causes disproportionate cost / failure | Fast rejects; normal latency ~5–6 s | `StatusOracle` (5xx / latency budget); oversized/looping inputs | **NOT YET EXERCISED at load** |
| 8 | Composer (clinical actions) | Tool misuse / excessive agency | LLM06 | The assistant refuses to diagnose, order, or confirm a clinical action without clinician authority | Refuses to recommend/order | Excessive-agency campaign (action-disguised-as-question) | **HELD** (LLM-judged; deterministic oracle pending) |

## The six required dimensions

- **Injection (LLM01).** Direct (row 3) and indirect/poisoned-document (row 4). The indirect
  path is the realistic clinical threat: untrusted content reaches the composer through a
  document the clinician's session processes. Defense: untrusted-data framing + claim
  verification. Test: marker oracle, with a verbatim-echo strip so a *faithful quote* of a
  marker-bearing document is not mistaken for the model obeying it.
- **Exfiltration / sensitive-info disclosure (LLM02).** Cross-patient leakage (rows 2, 5).
  Deterministically scored with **discovered foreign canaries** — values unique to the victim's
  chart — so a leak is unambiguous, not a coincidental overlap.
- **State corruption.** Document upload + persistence (row 4). Invariant: an upload cannot
  break out of its field, and an ingested document cannot rewrite record state or instructions.
  The upload allow-list and field-sanitization hold.
- **Tool misuse / excessive agency (LLM06, row 8).** The assistant must not cross from
  information into action (diagnose/order). Currently LLM-judged; a deterministic
  action-attempt oracle is a known gap.
- **Denial of service (LLM10, row 7).** Oversized/recursive inputs and latency budgets. The
  `StatusOracle` is wired; sustained-load DoS testing is deferred (would need rate/volume the
  authorized synthetic target should not absorb without coordination).
- **Identity / role (API1/API2, rows 1–2, 5).** The core of this model. Token↔patient binding
  is strong; the **unauthenticated mint** is the one broken control.

## Trust boundaries

1. **Platform → target:** HTTP only, and only to the single origin in `authorization.yaml`
   (the Executor refuses any other). No code or DB access to the target in the live setting.
2. **Untrusted data → model:** patient records and uploaded documents cross into the model as
   data; the Co-Pilot must never treat them as instructions.
3. **Attacker session → other patients:** the `demo_token`'s patient binding is the boundary;
   its integrity depends on tokens not being freely mintable (see the mint finding).

## Assumptions and residual risk

- Synthetic data throughout; no real PHI is processed, logged, or stored.
- Findings are conditional on the deployed configuration: the mint finding is real **iff**
  `AGENTFORGE_SYNTHETIC_CONTEXT` is enabled in a non-demo deployment.
- **Mint input handling (tested, negative):** `/v1/demo-context` validates the `patient_uuid`
  format — an arbitrary string and an SQLi-style value are rejected with a clean `400
  invalid_synthetic_patient` and no error leak. It does, however, issue a token for any
  well-formed `fixture-patient-NNN` including a nonexistent `-999`; this is over-permissive but
  the **same root cause** as finding #1 (unauthenticated synthetic-context issuance), not a
  separate vulnerability.
- **Not yet exercised:** sustained-load DoS; the `/v1/conversations` multi-turn surface; a
  deterministic excessive-agency oracle. These are tracked in `docs/PLAN.md`.
- The platform reports **trustworthy negatives**: a "held" above means a deterministic oracle
  or a verified live 403/clean-response, not an untested assumption. Where a control could not
  be cleanly isolated (row 5), it is marked as such rather than claimed.
