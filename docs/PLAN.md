# AgentForge Red Team — plan

The single plan file (see `AGENTS.md`). Keep it current at decision boundaries.

**Goal:** by Friday noon CT, a deployed multi-agent adversarial platform runs live
against the authorized Clinical Co-Pilot target, converts confirmed exploits into a
regression harness, documents findings professionally, and proves fixes hold without
raising over-refusal — every claim tied to a target SHA and a reproducible run.

## Status (2026-09-28)

No agents built yet. Live target **confirmed** (`/health` → `git_sha bfbb1eb2…`). Done
this session: requirements matrix (below), architecture grilling Q1–Q15 (all closed),
`CONTEXT.md` glossary, `docs/adr/0001–0003`, `ARCHITECTURE.md` draft (Stage 4 gate), and a
shareable decision page (artifact `CAJNwV8dqwQbs2fttuMHLJ`). Next: `THREAT_MODEL.md`
(Stage 2) and `USERS.md`, then first live agent role + seed evals (Stage 3).

**Architecture Defense (peer session):** 1 hour, groups of 3–5, 5-min present + 5-min Q&A
each, alphabetical order. David presents and defends this architecture live. `ARCHITECTURE.md`
"Known tradeoffs / failure modes" is written to serve that Q&A (why-X-over-Y, failure
modes, edge cases). Source: `~/Downloads/architecture_review_guide (2).pdf`.

## Course clarifications (kickoff call, 2026-09-28)

From the recorded intro call (Byron). These override convenience where they narrow scope.

- **Scope = the LLM/agent layer, not OpenEMR.** Byron twice: most interested in *LLM and
  agent vulnerabilities* (prompt injection, PHI/cross-patient leakage, tool/action misuse,
  multi-turn state), **not** the OpenEMR PHP or dependency/supply-chain scanning. The
  threat model and seed evals center on the AI surface. Classic web/OWASP rows stay only
  where they touch that surface.
- **Black-box confirmed.** Assume **no** target codebase access; hit the chatbot over HTTP
  only. The platform should in principle be pointable at another chatbot. Matches the
  single-Executor / HTTP-only design.
- **Fixes are REQUIRED, not stretch.** "When you find a vulnerability, fix it and show that
  you fixed it." Elevates the fix → regression-holds loop (P5) to a graded requirement.
- **Auto-fix is a bonus, not required.** Surface the bug + proposed fix; do not auto-apply
  unless deliberately wired. Matches the "platform never applies fixes to the target" gate.
- **Separate/greenfield repo is allowed and encouraged.** Our standalone repo is right.
- **Deadlines show in LOCAL time (portal bug), not Central.** Early = **Tue midnight**,
  final = **Fri noon** — confirm the local offset in the portal. (SC1/SC2.)
- **Model refusals are expected by design.** Frontier models refuse offensive-security work
  and are too costly to run continuously → open-weights attacker on a cheap key. This is
  also why detailed offensive content trips output safety classifiers in *this* assistant
  session; the specific offensive text (threat-model findings, attack seeds) is authored by
  David or a model without that filter. See `[[claude-safety-blocks-w3]]`.
- **Architecture Defense:** today 2:30 CT, via the portal (not Google Meet), **plan-only
  and ungraded** (reflective survey), one-slide norm. David is handling it.

## Source record

| Source | Path |
|---|---|
| PRD (18 pp) | `.scratch/assignments/w3.txt` (gitignored; from the assignment PDF) |
| Prior art | `docs/W3_ADVERSARIAL_PRIOR_ART_RESEARCH_2026-09-27.md` |
| Idea bank | `.scratch/assignments/w3-idea-bank.md` (gitignored, speculative) |

## Requirements matrix

Built from `.scratch/assignments/w3.txt` (18 pp) on 2026-09-28. Source column cites the
PRD page. Classes: `HARD_GATE` (named hard gate), `CORE` (required platform capability),
`GRADED` (engineering requirement graded alongside core), `OPTIONAL` (PRD "Optional Engineering Deliverables"), `SUBMISSION` (submission
artifact), `SAFETY` (trust boundary), `SCHEDULE` (checkpoint). Status: `not started`
(scaffold/stub only) until a wired, tested, live-observed path exists (see `AGENTS.md`
"done").

### Hard gates + submission artifacts

| ID | Source | Requirement | Class | Acceptance criterion | Status |
|---|---|---|---|---|---|
| G1 | p7 Stage 1 | Co-Pilot running locally **and** deployed; deployed URL submitted every checkpoint; platform tests the **live** system, not a mock | HARD_GATE | `/health` returns SHA at submission; a run record ties results to that SHA | live target confirmed 2026-09-28 (`git_sha bfbb1eb2…`, HTTP 200); platform not built |
| G2 | p8 Stage 2 | `THREAT_MODEL.md`: ~500-word summary + full attack-surface map over 6 categories (injection, exfiltration, state corruption, tool misuse, DoS, identity/role); per category: surface, impact, difficulty, existing defenses | HARD_GATE | Doc opens with summary naming highest-risk categories + coverage priority; all 6 categories mapped with the 4 fields | stub |
| G3 | p8 Stage 3 | `evals/`: reproducible suite ≥3 attack categories; each case = category/subcategory, input sequence, expected-safe, observed (pass/fail/partial), severity+exploitability, regression flag; **+ ≥1 agent role running live against deployed target** | HARD_GATE | Suite reruns to same verdicts; ≥3 categories; one live agent role demonstrated | stub |
| G4 | p9 Stage 4 | `ARCHITECTURE.md`: ~500-word summary, names each agent (role, I/O, trust level, coordination), interaction diagram; addresses the 8 design bullets | HARD_GATE | Summary + every agent named + diagram + all 8 bullets answered defensibly | stub |
| G5 | p6 | `KEY_METRICS.md`: metrics + rationale defensible to a hospital CTO | HARD_GATE | Small metric set, each with what-it-proves rationale | stub |
| G6 | p14 | `USERS.md`: users, workflows, use cases, explicit justification automation is right | SUBMISSION | Users + workflows + why-automate argument | stub |
| S1 | p14 | Independent repo: setup guide, architecture overview, deployed link, run-against-target instructions | SUBMISSION | README covers all four | partial (README scaffold) |
| S2 | p14 | Demo video 3–5 min showing platform running **live** attacks against target | SUBMISSION | One video per submission | not started |
| S3 | p10,14 | ≥3 distinct vuln reports, reproducible by a security engineer not present at discovery; format = id+severity, description+clinical impact, minimal repro, observed vs expected, remediation, status+fix-validation | SUBMISSION | 3 reports meeting the reproduce-bar | not started |
| S4 | p14 | AI cost analysis: actual dev spend + projected at 100/1K/10K/100K runs; arch changes per scale; **not** per-token×n | SUBMISSION | 4 scale points + architectural notes | not started |
| S5 | p14 | Publicly accessible deployed target; platform runs live tests against it for early + final | SUBMISSION | Same as G1, per checkpoint | target live; platform not built |
| S6 | p14 | Technical interview (early), social post (final), AI interview (final) | SUBMISSION | Scheduled/posted at each gate | not started |

### Platform (multi-agent) — CORE

| ID | Source | Requirement | Class | Acceptance criterion | Status |
|---|---|---|---|---|---|
| P0 | p9 | Multi-agent architecture (single-agent/pipeline **fails**); distinct roles, contexts, trust levels, coordinated | CORE | Named distinct agents with separate contexts | not started |
| P1 | p9–10 | Red Team Agent: novel inputs, mutate partial successes, multi-turn sequences; model choice defended | CORE | Generates + mutates + multi-turn, live | not started |
| P2 | p4–5,12 | Judge Agent: verdict success/fail/partial, consistent across runs+versions, independent of attack engine, no drift, judge itself validated | CORE | Independent context/model; drift detection documented + calibration set | not started |
| P3 | p5,11 | Orchestrator: reads state (coverage gaps, open findings, regressions, cost), prioritizes next target, triggers regression on target change, halts when cost accrues without signal | CORE | Prioritization from real signals; budget halt | not started |
| P4 | p10 | Documentation Agent: confirmed exploit → professional report, no human writing; human approval gate for high severity | CORE | Report meets S3 bar; critical behind gate | not started |
| P5 | p11 | Regression & validation harness: versioned queryable store; auto full suite on Orchestrator trigger; detect reappearance; flag cross-category regressions; a test passing due to behavior shift is worse than none | CORE | Deterministic replay; reappearance + cross-category detection | not started |
| P6 | p11 | Observability layer answers: cases per category; pass/fail across categories+versions; resilience trend; open/in-progress/resolved findings; run cost + scaling rate; per-agent ordered action trace | CORE | All 6 queryable from the store (SQLite, settled) | not started |

### Engineering requirements — E1 graded; E2–E15 optional (see R1)

| ID | Source | Requirement | Class | Status |
|---|---|---|---|---|
| E1 | p12 | OWASP mapping on **every** case: LLM Top 10 + classic web risks (broken access control, injection, insecure design, vuln components, auth failures, logging failures, SSRF) | GRADED | not started |
| E2 | p12 | Every case exercises a boundary, invariant, or regression risk; static payload lists insufficient | OPTIONAL | not started |
| E3 | p12 | Build-vs-configure decision records (Burp/ZAP/Semgrep/garak/commercial) — required Architecture Defense deliverable | OPTIONAL | not started |
| E4 | p12 | Triage exercise: simulated scan report ≥10 findings across critical/high/medium/false-positive; validate/remediate/defer/document each | OPTIONAL | not started |
| E5 | p12–13 | Versioned JSON-Schema contracts in `/contracts` for every inter-agent message; contract tests both sides; breaking change → version bump | OPTIONAL | stub (`contracts/` README) |
| E6 | p13 | Explicit typed error schemas (target unreachable, budget exceeded, judge timeout, no findings in window, regression detected) in `/contracts` | OPTIONAL | not started |
| E7 | p13 | Rate limits + auth documented for every external API (LLM providers, target, observability); handling = backoff/queue/abort in `ARCHITECTURE.md` | OPTIONAL | not started |
| E8 | p12–13 | AI-use disclosure in `ARCHITECTURE.md`: each AI role, following deterministic verification/human gate, residual risk; judge-drift detect+correct | OPTIONAL | not started |
| E9 | p13 | Exploit DB data-quality: unique id, required fields, no dup attack sequences; validated in Doc Agent before write | OPTIONAL | not started |
| E10 | p13 | Exploit DB migration support (add field without data loss); document approach; queue-depth monitoring if a queue is used | OPTIONAL | not started |
| E11 | p13 | Data model + access controls: who writes/reads exploits, human approval before publish; lineage/reporting | OPTIONAL | not started |
| E12 | p13 | SQL indexes on common queries (severity/category/version); regression full-scan SLO verified in CI | OPTIONAL | not started |
| E13 | p13 | Baseline CPU/mem/latency/throughput under representative run (100 cases + full regression) | OPTIONAL | not started |
| E14 | p13 | Load test: 100 consecutive cases vs live target; platform metrics; identify bottleneck + the architectural fix | OPTIONAL | not started |
| E15 | p12–13 | ATO-style evidence packet (arch + data-flow diagram, auth model, dependency versions, platform self-scan, test evidence, sample incident/postmortem); + integration packet if the peer integration-week exercise applies (see R3) | OPTIONAL | not started |

### Safety / trust boundary (AGENTS.md + PRD Appendix item 9)

| ID | Source | Requirement | Class | Status |
|---|---|---|---|---|
| SA1 | p18 §9; AGENTS.md | Authorization registry: a target runs only with recorded proof (owned or written permission + scope); platform cannot be turned against unauthorized systems | SAFETY | not started |
| SA2 | AGENTS.md; p2 | Synthetic data only; no real PHI processed/logged/stored; redaction tested against a real workflow trace | SAFETY | not started |
| SA3 | p18 §9 | Access controls: who triggers runs / views reports; approval before Doc Agent files a critical report; auditable per-agent trace of any unattended run | SAFETY | not started |

### Schedule

| ID | Source | Milestone | Class |
|---|---|---|---|
| SC1 | p6 | **Early: Tue 11:59 PM CT** — deployed agent, eval framework, observability wired, demo video; technical interview Wed/Thu | SCHEDULE |
| SC2 | p6 | **Final: Fri noon CT** — production-ready platform, demo video, social post; AI interview 24 h after | SCHEDULE |

### Reconciliation (resolve before decomposition)

- **R1 — "optional" contradiction. RESOLVED 2026-09-28 (revised same day): optional.** p12 header reads "Optional Engineering Deliverables" while its body copies the preceding section's "not optional" intro. David's final call: the heading governs; **E2–E15 are optional**, E1 (OWASP mapping) stays graded. Parts still arrive via other routes and are *not* optional: agent I/O, message format, AI-vs-deterministic split and rate-limit/cost handling are G4 Stage-4 bullets (overlapping E5/E7/E8); versioned `/contracts` schemas are a repo rule (`AGENTS.md`) and R3's plug-in-able contract (overlapping E5/E6); a "defend the model choice" record is P1 (overlapping E3). Pick further optional items by value once core slices are sized.
- **R2 — GitHub vs GitLab.** PRD S1 says "GitHub Repository"; repo `AGENTS.md` says GitLab `origin` on `labs.gauntletai.com` is the graded source of truth, GitHub a mirror. *Interpretation:* push both; GitLab is primary/graded, GitHub satisfies the PRD's public-repo wording. No conflict if both stay in sync.
- **R3 — integration-week peer exercise. RESOLVED 2026-09-28: build solo.** p12–13 describe each student building one agent role and integrating a *classmate's* agent through published contracts only. David's call: we own and build every role; contracts are written so an independently built agent *could* plug in through `/contracts` alone. Integration packet deferred unless a cohort swap is assigned. *Recommended interpretation:* build all agents solo but honor the contract discipline (E5/E6) so a peer *could* integrate; produce the integration packet only if the cohort exercise is actually assigned. Consequence if wrong: a missing integration-week artifact. **Confirm with course staff.**
- **R4 — metric thresholds (`OPEN`).** PRD leaves pass thresholds open (over-refusal ceiling, fix-holds criteria). Decide numeric thresholds in `KEY_METRICS.md` during that gate; the prior-art note declines to set them from the teaser alone.

## Settled decisions

- Language: Python (uv, pydantic); HTTP-only access to the target.
- Judge: deterministic oracles first; narrow different-family LLM judge only where no
  oracle exists; human lane for clinical-harm calls.
- Tools: PyRIT as a library; garak/spikee as sidecars; own finding store.
- Authorization-gated execution; synthetic data only.
- Observability substrate: **custom SQLite** as the Orchestrator's source of truth (P6).
- Architecture-decision deliverable: an **ADR** in-repo + a shareable page, later folded
  into `ARCHITECTURE.md` (satisfies the E3 build-vs-configure record).

- **Coordination: custom control plane** — deterministic controller + SQLite blackboard
  and work queue; agents are isolated workers exchanging typed messages. See
  `docs/adr/0001-custom-control-plane.md`. (Grilling Q2, 2026-09-28.)
- **Vocabulary + lineage:** seed case → variant → attempt → verdict → finding → report →
  regression case, every record linkable end-to-end on demand. See `CONTEXT.md`. (Q1.)
- **Campaign execution:** local replica of the real Co-Pilot for volume (mutation, load
  test, sweeps); every finding re-confirmed once on the deployed SHA; regression-on-deploy
  and demo run live. Target change: move its query embeddings off the free-tier Gemini key
  (see Q12 below) and document it as a Stage 1 testability change. Degraded
  retrieval → `INCONCLUSIVE`, never a pass. (Q3.)
- **Orchestrator: hybrid** — deterministic ranking + hard budget/halt/auth rules; a small
  LLM picks among top-k candidate campaigns and logs its rationale; cannot override
  controls. (Q4.)
- **Red Team provider:** David's direct Qwen API key preferred (cheapest). Model chosen by
  a measured bake-off **after** the architecture settles (Q5).
- **Human gates:** publish Critical/High reports; `INCONCLUSIVE` + clinical-harm review
  queue; authorization-registry changes. Autonomous: in-budget campaigns, finding →
  regression promotion, Medium/Low reports. Never: the platform proposing or applying
  fixes to the target. (Q6.)
- **Hardening Drill:** design for it, don't build it — one-command, bounded, resumable,
  real exit code, target-agnostic recon; no planted-bug scoring until staff confirm. (Q7.)

- **Roster + network boundary:** four agents (Orchestrator, Red Team, Judge,
  Documentation) plus deterministic services (Executor, Regression runner, Recon). The
  Executor is the only component with network access to the Target and checks the
  authorization registry on every request; the Red Team emits attack specs as data only.
  See `docs/adr/0002-single-executor-network-boundary.md`. (Q9.)
- **Lineage depth:** records plus the decisions behind them — Orchestrator choice and its
  inputs, variant mutation ancestry, Judge model/prompt version, oracle version. Full LLM
  prompt/response kept for Judge calls and for Red Team calls that led to a success
  verdict; hash + token counts otherwise. (Q10.)
- **Runtime + regression trigger:** end state is a container on the Vultr host (isolated
  compose service, `/health` SHA polling, nightly budget-capped campaign, read-only
  authed dashboard). For now, scheduled jobs (cron) doing the same polling and nightly run
  are acceptable, per course staff. (Q11.)
- **Target embeddings:** move to OpenRouter `google/gemini-embedding-2`; spot-check
  cosine ≈ 1.0 against stored corpus vectors before reuse, else re-embed the 42 chunks.
  Document in the target repo as a Stage 1 testability change. (Q12.)
- **Provider blocks are a distinct outcome.** Alibaba's `DataInspectionFailed` filter
  cannot be disabled. A blocked Red Team generation is a typed outcome (bake-off measures
  its rate; fallback is a non-Alibaba open-weights provider). A Target response blocked
  by an upstream provider filter is not evidence the Target's defense held →
  `INCONCLUSIVE` for regression purposes.

- **Orchestrator selector: Jev (TypeSafe), pinned `jev-1.13.0`.** One Choice call picks
  among the deterministic top-k. Three confidence bands: at/above threshold take Jev's
  pick; mid band take deterministic top-1 and log the disagreement; very low take
  deterministic top-1 and flag on the dashboard — never stall on a human. Threshold set
  from logged decisions (vendor example floor 0.5). Lineage records state snapshot,
  candidates with score components, per-option probabilities, and model version in place
  of a free-text rationale. (Q13.)
- **Judge LLM: chosen by bake-off** after the architecture settles, against a 20–30 case
  human-labeled calibration set (κ agreement, injection resistance, rerun stability, cost
  per verdict). Candidates: DeepSeek pinned to one OpenRouter provider (default if the
  bake-off is cut), one stronger third-vendor closed model, and Jev. Jev is independent of
  Qwen per David (base model not stated in public docs — cite as owner knowledge in the
  AI-use disclosure). Pairing two judges with disagreement → `INCONCLUSIVE` is decided by
  bake-off results. (Q8′, Q14.)

- **Approvals + access (SA3): CLI only.** Pending reports wait for an operator `approve`
  command that writes an approval record into lineage; only operators with shell access
  to the host trigger runs; dashboard is read-only behind basic auth. In-dashboard
  approval is a listed end state. (Q15.)

## Open decisions

None in the architecture tree (grilling closed 2026-09-28). Deferred measurements, not
decisions: Red Team model bake-off (Q5) and Judge bake-off (Q8′/Q14).

## Execution slices

Specced in `docs/HARNESS_SPEC.md` (S0–S9, mapped to requirement IDs). **Tuesday cut: S0–S5**
— scaffold, safety core (authorization.yaml + Executor + store), oracles + Judge, seed evals
(≥3 OWASP categories, content authored unfiltered), dashboard, and a minimal Red Team — so
Red Team + Judge both run live against the deployed target. **Friday: S6–S9** — Orchestrator,
Documentation + reports, regression harness + Red Team multi-turn, drill/metrics/cost/deploy.

Harness spec is decision-complete (D1–D5 resolved). Still authored separately (safety
classifier): `THREAT_MODEL.md` findings and `evals/` seed content.

**Build status (2026-09-28, pushed to both remotes). `uv run pytest` = 60 passed.**
S0 ✓ scaffold · S1 ✓ safety core (live: unlisted origin blocked, /health 200) · S2 ✓
oracles + tier-0 Judge · S3 ✓ run loop + token minting (live: authed briefing 200) · S4 ✓
observability · S5 ✓ Red Team + campaign + attack memory (live: multi-agent loop ran) ·
S6 ✓ Orchestrator (ranker + budget/halt; Jev selector gated on a key) · S7 ✓ finding
promotion + Documentation agent + human gate · S8 ✓ regression harness · CLI ✓ (`redteam`
report/approve/regression/campaign) · USERS.md ✓ · KEY_METRICS.md ✓. Each behavior slice
reviewed (self or subagent) and its findings applied. ADR 0001–0004, harness spec,
architecture doc + shareable page, requirements matrix, offensive handoff all in.

**Unblocked 2026-09-28 (session 2):** cost is in **model calls, not USD** (Qwen bills in
credits); platform is **resilient** to target drops (→ INCONCLUSIVE, not crash); **Jev
selector live** (key in .env, `--selector jev`, confidence-band fallback verified 0.23→
deterministic); **HTML dashboard** (`redteam dashboard --out`). `uv run pytest` = 63.

**Schema-aware shaping DONE — attacks now reach the AI (2026-09-28).** Recon found the
injection surface: `POST /v1/follow-up-evidence` with a `message` field + token returns 200
and runs the text through the AI. The Red Team places its payload in the route's known field
(`_ROUTE_FIELDS` in the CLI → brief `input_field` → per-turn shaping). **First real run: 6
attacks reached the AI (all HTTP 200), all judged FAIL — the Co-Pilot defended.** Honest
zero-findings: the target resisted these six, not a plumbing failure.

- **Windows gotcha:** run the CLI with `MSYS_NO_PATHCONV=1` in Git Bash (or from PowerShell)
  — otherwise a leading-slash `--route /v1/...` is rewritten to a Windows path and 400s.
- **To find real vulns from here:** more campaigns + multi-turn + the indirect/document
  surface (upload-borne injection via `/v1/scan-supervisor` after a source doc); stronger
  Red Team objectives. The loop and oracles are proven; this is attack-strength work.

**Other remaining work needs David (classifier / spend / human):**
1. **Real findings** — run authed attack campaigns per `docs/HANDOFF-offensive.md`
   (`redteam campaign --target agentforge-w2 --category prompt-injection --patient
   fixture-patient-001 --route /v1/scan-supervisor`). Needs an unfiltered model/David to
   author+drive attack content. Turns the green harness into findings + vuln reports.
2. **THREAT_MODEL.md findings** (Stage 2 hard gate) — authored outside this assistant.
3. **Benign + calibration sets** — for KEY_METRICS #4 (over-refusal) and #5 (judge κ).
4. **Jev key** (optional) — `AGENTFORGE_REDTEAM_JEV_KEY` + `typesafe-sdk` to activate the
   Jev selector; deterministic selector is the live default otherwise.
5. **Cost pricing (S9)** — wire qwen3.8-flash price so `cost_summary` reports USD and the
   AI Cost Analysis is real.
6. **Submission** — demo video, social post; confirm local-time deadlines in the portal.

**S5 live-demonstrated (2026-09-28):** the full multi-agent loop ran against the **deployed**
target — Red Team (qwen3.8-flash, target's own endpoint) generated 3 cases across 3 OWASP
categories, Executor sent them, Judge verdicted, each non-success mutated once; all recorded,
dashboard rendered. Outcome: **6× FAIL, 0 findings** — every attempt got **HTTP 400**,
rejected at the target's request-validation layer before reaching the AI. Honest read: the
loop works end to end; there is nothing to find yet because the attacks are malformed and
unauthenticated. Store at `var/redteam.db` (gitignored). Key in `.env` (gitignored).

**Token minting DONE (2026-09-28, live-verified).** Discovered the session contract
black-box (probing the live site): `GET /v1/demo-context?patient_uuid=fixture-patient-00N`
mints a 300s patient-scoped `demo_token` that patient routes require in the body. Fixture
patients `fixture-patient-001..008` + `-dup`; clinician `fixture-physician-001`. `TokenMinter`
mints through the Executor (single-door held); the runner injects the token when a case has
an `auth` patient. `Target.base_path` (`/agentforge-w2`) added. **An authenticated briefing
now returns 200, not 400 — attempts reach the AI.**

Attacker note: `/v1/demo-context` is an unauthenticated synthetic-context mint — a
determined attacker would find and use it exactly as we did. In production this gate
(`AGENTFORGE_SYNTHETIC_CONTEXT`) must be off; its exposure is itself an insecure-design
finding worth documenting.

**To turn the loop into real findings (next, classifier-relevant / content layer):**
- **Authenticated attack campaign:** run the Red Team with `patient_uuid` set + a marker
  oracle — prompt-injection attempts now reach the AI and produce real SUCCESS/FAIL verdicts.
- **Planted canaries + cross-patient:** learn a value unique to patient-002 (authed as 002),
  then run as patient-001 trying to leak it (foreign-canary oracle) — deterministic LLM02.
- **More oracles:** scope/access-control, excessive-agency (action), output-handling (render).
- **Browser/conversational surface:** drive the chat UI with the built-in browser for
  indirect + multi-turn injection and an output-render (stored-XSS) oracle. Bigger lift.
- Optional: the LLM rubric Judge tier for criteria no oracle covers.

**Still authored separately (safety classifier):** `THREAT_MODEL.md` findings, and any
hand-authored `evals/` seed content (the Red Team now generates cases at runtime, so seed
files are optional, not required, for the demo).
