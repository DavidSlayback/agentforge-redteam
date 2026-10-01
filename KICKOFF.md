# KICKOFF — AgentForge Red Team (Week 3)

Handoff into this repo's first working session. Read this, then `AGENTS.md`, then
`docs/W3_ADVERSARIAL_PRIOR_ART_RESEARCH_2026-09-27.md`. Prepared 2026-09-28.

> **Status note, 2026-10-01.** This file is the kickoff brief and is kept as written, apart from the
> corrections flagged below. The current state is in `docs/PLAN.md` and the status table at the end
> of `ARCHITECTURE.md`. Where the kickoff plan and the code differ: PyRIT, garak and spikee are **not**
> wired (not in `pyproject.toml`, `uv.lock` or `src/`; the Red Team calls the attacker model
> directly); the Judge has no EHR-write state-diff oracle (black-box, not built); the Documentation
> agent is deterministic, not an LLM; the "unattended Hardening Drill" has no `drill` command; and no
> peer integration was done.

## What this is

A **multi-agent adversarial evaluation platform** that continuously red-teams the
AgentForge Clinical Co-Pilot (the OpenEMR AI layer from Weeks 1–2) and proves fixes
hold without breaking the clinician. Graded PRD; separate repo from the Co-Pilot.

Full PRD text: `.scratch/assignments/w3.txt`. The teaser it expands:

> Attack your own Clinical Co-Pilot. Build a multi-agent adversarial evaluation platform
> that autonomously discovers vulnerabilities, generates and mutates attacks, judges
> results independently, prioritizes coverage from system state, documents findings
> professionally, and proves fixes hold without breaking the clinician — validated by an
> unattended Hardening Drill against planted vulnerabilities you did not author.

## Scope boundary (read first)

The target is **the Clinical Co-Pilot David owns and deploys** — nothing else. The
platform is target-agnostic in architecture but **authorization-gated in execution**: a
target runs only if it is in an authorization registry with recorded proof. This is both a
safety line and a graded requirement (PRD Appendix, item 9). This repo is **not** a
general scanner for third-party/public systems. See `AGENTS.md`.

## The target

- Deployed W2 Co-Pilot: `https://dtstest.64.177.10.182.nip.io/agentforge-w2/`
  (`/health` returns `{status, git_sha}`). Confirm it is live and SHA-pinned at the start
  of every checkpoint (Stage 1 hard gate: the deployed target URL is submitted each time,
  and the platform must run against the live system, not a mock).
- Architecture and HTTP routes: the `agentforge-week1` repo
  (`W2_ARCHITECTURE.md`, `agentforge/src/server.js`). The platform reaches it over HTTP
  only; it does not import Co-Pilot code.

## Required platform (PRD, not optional)

Multi-agent — a single-agent or pipeline architecture **fails** the assignment. Distinct
roles, distinct trust levels, coordinated:

- **Red Team Agent** — generates novel adversarial inputs, mutates partial successes,
  runs multi-turn sequences. Model choice is yours to defend (frontier models often
  refuse offensive-security workflows; smaller/local models may fit better here).
- **Judge Agent** — independent of the attack engine; decides success/fail/partial with
  criteria consistent across runs and versions; must not drift; validate the judge itself.
- **Orchestrator** — reads system state (coverage gaps, open findings, regressions,
  cost) and decides what to target next; triggers regression runs; halts when cost
  accrues without signal.
- **Documentation Agent** — turns a confirmed exploit into a reproducible, professional
  vuln report with no human writing it. Behind a human approval gate for high severity.
- **Regression & validation harness** — confirmed exploits → deterministic, versioned,
  queryable test cases; detects reappearance; flags fixes that regress another category.
  A test that "passes" only because behavior shifted is worse than none.
- **Observability layer** — the data substrate the Orchestrator reads and a human can
  inspect: coverage per category, pass/fail over versions, resilience trend, open/closed
  findings, per-run and per-agent cost, and an ordered agent-action trace.

## Hard-gate deliverables (root files)

| File | Gate |
|---|---|
| `THREAT_MODEL.md` | Stage 2. ~500-word summary + full attack-surface map (injection, exfiltration, state corruption, tool misuse, DoS, identity/role). |
| `ARCHITECTURE.md` | Stage 4. ~500-word summary, names each agent + I/O + trust level + coordination, agent-interaction diagram, build-vs-configure records, AI-use disclosure. |
| `KEY_METRICS.md` | Metrics + rationale defensible to a hospital CTO. |
| `USERS.md` | Users, workflows, why automation is right. |
| `evals/` | ≥3 attack categories, reproducible results, each case mapped to OWASP. |
| `contracts/` | Versioned JSON Schemas for every inter-agent message + typed errors. |
| Vuln reports | ≥3 distinct, reproducible by a security engineer not present at discovery. |
| Cost analysis | Actual dev spend + projected at 100/1K/10K/100K runs (not per-token × n). |

OWASP mapping is required on every case: OWASP LLM Top 10 (prompt injection, insecure
output handling, sensitive info disclosure, excessive agency, supply chain) plus the
classic web risks relevant to the Co-Pilot (broken access control, injection, insecure
design, auth failures, logging failures, SSRF).

## Settled decisions (carry forward)

- **Language: Python** (uv, pydantic). Platform reaches the target over HTTP only.
- **Judge:** deterministic oracles first (canaries, EHR-write state diffs, cross-patient
  checks, schema/citation checks); a narrow, different-family LLM judge only where no
  oracle exists; human lane for clinical-harm calls. *(Built: canary, cross-patient and
  authorization oracles, grounding, metadata, rate-limit, enumeration and contradiction checks,
  and the rubric tier. Not built: EHR-write state diffs and the clinical-harm human lane.)*
- **Tools:** import PyRIT as a library (converters, seed loaders, HTTP target, selected
  attacks); run garak and spikee as sidecars; keep our own finding store. Skip
  LLM-heavy frameworks in the inner loop. See the prior-art note for pinned versions.
  *(As of 2026-10-01 this was planned, not done: none of the three tools is installed or called;
  only "keep our own finding store" was built. See ADR 0005 and `ARCHITECTURE.md`.)*
- **Attack techniques** come from the pinned tools at runtime and David's course
  presentation on adversarial techniques — not from assistant-generated catalogs.

## First task: design the architecture

The PRD gives wide latitude. Before building, produce the architecture (Stage 4) — but
it is cheap to start Stages 1–2 in parallel (confirm the live target; draft the threat
model from the prior-art surface map). Key design questions to decide and defend:

1. Agent framework: custom orchestration vs LangGraph/CrewAI/AutoGen — justify.
2. How agents communicate (message contracts in `/contracts`) and hand off/recover.
3. What signals the Orchestrator reads to prioritize, and how coverage is represented.
4. How the Judge stays consistent and is itself validated (drift detection).
5. Where human approval gates sit (Documentation Agent for critical findings; any
   remediation trigger) and how the authorization registry gates targets.
6. Where AI is used vs deterministic tooling, with the build-vs-configure record.
7. Cost/rate-limit/model strategy at scale; which model powers each role.
8. State/coordination + observability backend (the Orchestrator's data substrate).

The prior-art note maps each of these to published patterns and is the backbone for
`ARCHITECTURE.md`. Start `docs/PLAN.md` as the single plan file.

## Cadence

One-week sprint, Central time. Early submission **Tuesday 11:59 PM** (deployed target,
eval framework, observability wired, demo video; technical interview Wed/Thu). Final
**Friday noon** (production-ready platform, demo video, social post; AI interview after).

## Standard: build to what a hospital CISO would trust to run continuously against
systems their physicians depend on — not the flashiest demo jailbreak.
