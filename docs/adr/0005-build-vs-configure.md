# ADR 0005 — Build-vs-configure: why a custom platform, not an off-the-shelf scanner (E3)

**Status:** accepted (2026-09-30). Extends ADR 0003 (platform architecture) with the explicit
tool-by-tool build-vs-configure record the PRD's E3 asks for.

## Context

The PRD requires a *multi-agent adversarial-evaluation platform* that finds LLM/agent
vulnerabilities in a clinical Co-Pilot, converts confirmed exploits into a versioned regression
harness, documents them as reproducible reports, and tracks resilience across target builds — with
Judge independence, an authorization boundary, and honest verdicts. The question E3 poses: for each
capability, do we **configure an existing tool** or **build**?

## Decision

Build the orchestration/judge/regression/documentation core; **use existing offensive tools as
pinned libraries/sidecars at runtime** where they fit (PyRIT as a library; garak/spikee as
sidecars — see `docs/PLAN.md` settled decisions). The reasons, per candidate:

| Tool / category | What it does well | Why NOT the platform (configure-only) | Our choice |
|---|---|---|---|
| **Burp Suite / OWASP ZAP** (DAST proxies) | classic web scanning, fuzzing, request tampering | web/HTTP-centric; no concept of an LLM verdict, cross-patient canary, grounding, or a drift-checked judge; can't convert a finding into a versioned replay case or map to the LLM Top 10 | **configure-adjacent, not core** — the Executor is HTTP-only and could sit behind a proxy, but the graded capabilities (judge independence, regression fidelity, reports) are ours to build |
| **Semgrep** (SAST) | static code analysis | the course scope is the **deployed LLM/agent layer, black-box over HTTP** (kickoff call); no target source access; SAST answers a different question | **out of scope** (not a code-audit assignment) |
| **garak** (LLM probe suite) | prebuilt LLM attack probes (injection, leakage, toxicity) | strong probe library, but it is a *runner*, not an orchestrator+judge+regression+docs platform; its judging is not independent-by-construction, not drift-checked, and not a deterministic-oracle-first design; no authorization registry | **run as a sidecar** at runtime against the authorized target; the platform owns verdicts, dedup, regression, and reporting |
| **PyRIT** (Microsoft) | attack generation/orchestration primitives | useful generation/scoring primitives, but we need a *single-door authorization boundary*, deterministic oracles first, and store-mediated multi-agent coordination it does not impose | **use as a library** for primitives; keep our control plane + Executor boundary |
| **Commercial LLM-security scanners** | turnkey managed scanning | opaque judging (can't prove independence or no-drift to a CISO), no control over the authorization boundary, no in-repo regression artifact, recurring cost | **rejected** — the graded bar is a *defensible, auditable, self-hosted* platform |

## Consequences

- We own the retry/timeout/recovery logic a framework would provide (documented standing risk in
  `ARCHITECTURE.md`); failure drills must test it.
- The deterministic core (Executor boundary, oracles, regression replay, dedup, reports) is the
  graded differentiator and is built; offensive *content/technique* generation leans on pinned
  tools/models at runtime, not reimplemented.
- Judge independence and honest verdicts — the properties a configured scanner cannot guarantee —
  are structural here (deterministic oracles first; non-Qwen rubric; candidates-not-verdicts for the
  discovery tier).
