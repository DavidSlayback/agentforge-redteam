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
- **Red Team provider:** David's direct Qwen API key (Alibaba). Model is env-swappable
  (`AGENTFORGE_REDTEAM_MODEL`) and per-run via `redteam campaign --model <name>`. Default
  `qwen3.8-flash`. **Follow-up (David has an Alibaba MAX plan):** once the loop is landing
  clean aimed attempts, run the Q5 bake-off across stronger models (qwen3.8-max / qwen-max
  class) — a more capable attacker may craft attacks that actually breach a well-defended
  target. Compare refusal/provider-block rate, valid-variant rate, findings, and cost.
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

**Aimed attacks + cross-patient canaries + qwen3.8-max (2026-09-28).** The Red Team is now
OWASP-objective-grounded and target-aware. Cross-patient disclosure is deterministically
scorable: `--victim-patient` derives the victim's unique fact values as canaries.
- **Trustworthy negative:** attacker patient-001, victim patient-002, `--model qwen3.8-max`.
  The disclosure oracle **applied** (`canary_leak: safe`, not N/A) — a real scored
  cross-patient test — and **patient scope held**; injection also FAIL. No breach.
- **Caught + fixed a false positive first:** an earlier aimed run flagged a bogus
  prompt-injection "finding" from a ~5s (normal) response tripping a model-set latency
  budget. Fixed: latency judges DoS only; the platform (not the model) owns category/owasp.
- Model note: `qwen3.8-max` works on the MAX plan; `qwen-max`/`qwen3.8-plus` 404.

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

---

## 2026-09-29 — framework self-audit: why zero findings was a measurement artifact

David's challenge: "There's no way we don't have vulnerabilities. OpenEMR had obvious ones
and I didn't focus on not adding more. What is wrong with this framework?" He is right, and
the audit found a structural blind spot, not a well-defended target.

**Diagnosis — the platform was a narrow LLM prompt-injection tester in a red-team costume:**
1. **Every attack went through a properly-authenticated channel.** `TokenMinter.auth_fields`
   always mints a *matching* token and the runner (`runner.py`, `body = {**turn.body,
   **auth_fields}`) *overwrites* the body with self-consistent credentials. The attacker was
   always correctly scoped. We could not even express a token↔patient mismatch — i.e. **BOLA
   / IDOR**, the canonical medical-records bug and OpenEMR's signature class.
2. **The cross-patient "attack" was a politeness test, not an authz test.** `canary.py` mints
   a *legitimate* victim token to discover secrets, then only checks whether the AI
   *volunteers* them in the attacker's correctly-scoped session. We never sent the attacker's
   token with the victim's `patient_uuid` to demand the victim's chart.
3. **Oracles only fired on what we planted** (marker we told the model to emit; canary we
   pre-registered; 5xx/latency). No oracle for *unscripted* bad behavior: unauthorized data
   returned, or a stack trace / SQL error / internal path leaked in a body.
   The target's stated defenses are tuned to defeat exactly the marker oracle, through the one
   channel it controls — so "clean" meant "the LLM didn't parrot our token," not "secure."
4. **Replay could not faithfully re-run its own findings.** `regression.replay` called
   `run_case` for every frozen case — stomping any tampered auth (BOLA) and sending a document
   payload as a plain message (indirect). A frozen finding would falsely read "held/fixed."

**Fix — a deterministic authorization-probe track (no LLM judge; authz is binary):**
- New categories `broken-object-authorization` (API1 / LLM02) and `broken-authentication`
  (API2), executed by `authz_probe.run_authz_case`, which **inverts the merge precedence**:
  body wins over minted auth, so a token↔patient mismatch survives to the wire.
- Probes: cross-patient BOLA (attacker token + victim `patient_uuid`, scored by the foreign-
  canary oracle); missing-token, forged-token (scored by a new `UnauthorizedAccessOracle`:
  data returned on a request that should be 401/403 = VIOLATION); malformed-body error-leak
  (new `ErrorLeakOracle`: stack-trace / SQL / internal-path signatures = VIOLATION).
- Shared `dispatch.py` routes authz→run_authz_case, indirect→document, else→run_case, used by
  **both** campaign and replay — fixing the replay-fidelity bug for authz *and* document cases.
- `redteam authz` CLI subcommand runs the battery with no attacker model/key required.

**Status: DONE + live-verified (2026-09-29). `uv run pytest` = 99 passed.**

**Live result on `/v1/follow-up-evidence` (attacker=001, victim=002), evidence in the store:**
- BOLA (attacker token + victim `patient_uuid`) → **HTTP 403 `invalid_demo_context`** in ~120ms.
- Missing / forged / cross token → **all 403** in ~120–160ms (fail-fast, before any model call).
- The `demo_token` is a signed blob binding `patient_uuid=001`; the server rejects any mismatch.
  These are now **real, re-runnable, evidence-backed** tests (the token↔patient binding would
  regress loudly), not the earlier unexamined "clean." Document path: uploads are allow-listed
  per patient (`openemr_demo_patient_not_allowed`); a clean cross-patient doc-read IDOR was not
  isolable in this demo config (only one patient may use the scan path) — recorded as a caveat,
  not a disproof.
- **The one standing real issue** remains `/v1/demo-context`: it mints a valid patient token
  **unauthenticated**, so the (correct) token binding only holds because tokens are freely
  mintable for any patient. Insecure-design finding, caveated by the `AGENTFORGE_SYNTHETIC_CONTEXT`
  gate; write up via the Documentation agent.

**Framework self-audit fixes (subagent review, 2026-09-29) — all landed + tested:**
1. **Evidence capture** (was: bodies discarded) — new `evidence` table (migration 0004);
   `finalize` stores full request+response per exchange + oracle `detail`; `attempts/verdicts
   .evidence_ref` populated. `redteam evidence <attempt_id>` dumps it; the Documentation report
   now renders an **Evidence (what actually happened)** section. This was the core "give the LLM
   the data to reason about what happened" gap.
2. **Authz findings were auto-publishing** — `broken-object-authorization`/`broken-authentication`
   had no severity entry → defaulted to medium → escaped the approval gate. Now critical → gated.
3. **Opportunistic-oracle mislabeling** — a failed prompt-injection that merely 500'd was filed
   as a prompt-injection finding (wrong OWASP/remediation, dedup inflation). `findings._classify`
   now reclassifies a sole status/error-leak violation to its true class (DoS / error-disclosure).
4. **BOLA fail-silent** — when no distinctive canary is found, the probe logged nothing; now emits
   a visible `coverage_gap` action + `COVERAGE-GAP` line.
5. **Campaign fake-pass** — routing an authz category through `campaign` scored only StatusOracle
   (a real BOLA → FAIL "defense held"); campaign now refuses authz categories loudly.
6. **Indirect-injection echo false-positive** — the stripper removed the raw payload but the doc
   embeds the *sanitized* one; a quoted multi-line payload slipped through. Now strips the
   sanitized form too.
7. **Misleading cost** — the report printed "$0.0000 / 0 tokens" (never populated); now "N model
   calls (USD pricing not wired)".
8. **Resilience-by-build was one `unknown` bucket** — `attempts.target_sha` was never written;
   now threaded end-to-end (`--target-sha`), and regression replay labels its attempts with the
   sha under test.
9. **Replay fidelity** — replay routed everything through `run_case`, re-scoping BOLA and
   flattening document attacks (a frozen finding would falsely read "held"); replay now uses the
   shared `dispatch`.

---

## 2026-09-29 — remaining hard-gate deliverables: execution plan

Reprioritized (David): vuln-finding was the *last* part; the graded hard gates are the
contracts, threat model, wiring, observability, and reports. Early submission is **tonight
(Tue) 11:59 PM CDT**; final Friday noon. Conductor route: docs/non-behavioral slices with
contract tests where behavior exists; subagent review per slice.

| # | Deliverable | State entering | Acceptance evidence | Order |
|---|---|---|---|---|
| A | `contracts/` — v1 JSON Schemas for 6 inter-agent messages + typed errors, + contract tests | jsonschema dep added; 1/6 written | files under `contracts/v1/`; `test_contracts` validates real produced instances + rejects a bad one | **1st** |
| B | `THREAT_MODEL.md` — ~500-word summary + attack-surface map (injection, exfiltration, state corruption, tool misuse, DoS, identity/role), OWASP-mapped, w/ defenses + how we test each | 4-line stub | all 6 dimensions covered, each → OWASP + defense + platform probe; ties to real live results | **2nd** |
| C | `evals/` — ≥3 attack categories, reproducible, each mapped to OWASP | only `_template.yaml` | committed seed cases (≥3 OWASP categories) + a test that loads/validates them | 3rd |
| D | Vuln reports ≥3, reproducible by someone not present | machinery done; mint finding promotable | ≥3 evidence-backed reports rendered via Documentation agent (mint-auth is #1) | 4th |
| E | Cost analysis — dev spend + projected at 100/1K/10K/100K runs (calls, not per-token×n) | not done | a `docs/COST_ANALYSIS.md` (or KEY_METRICS section) with the model + projections | 5th |
| F | Observability/dashboard completeness | built (report+HTML) | verify coverage-per-category, resilience-by-sha, findings, cost, agent-trace all render | quick verify |
| G | `KEY_METRICS.md` / `USERS.md` at the CTO-defensible bar | exist (41/50 lines) | re-read against the gate; fill gaps | quick verify |

Slices A and B first (David's instruction). Each slice: build → subagent review → verify → record here.

**Progress (2026-09-29 afternoon):**
- **A contracts — DONE + reviewed.** `contracts/v1/` (6 messages + typed errors), `test_contracts`
  validates real persisted records (self-describing via migration 0005), per-schema negative
  controls. Subagent review applied (schema_version was overstated; now honestly persisted).
- **B THREAT_MODEL.md — DONE.** All 6 dimensions, OWASP-mapped, grounded in verified live results.
- **F observability — VERIFIED.** `redteam report` + `dashboard.html` render coverage, pass/fail,
  resilience-by-sha, findings, honest cost, agent trace.
- **D vuln reports — DONE (3 distinct, live-verified).** David chose to hunt for new findings;
  the hunt yielded three genuinely distinct, reproducible impacts of the synthetic-context mint:
  F-831d4df407 (anonymous **read** token → confidentiality), F-24b44c5180 (anonymous **write**
  token → integrity), F-6ee92046fb (**no rate limiting** → enumeration/DoS). Reports +
  shared-root-cause index in `docs/findings/`. Hunt also produced strong negatives:
  **multi-turn N/A (composer is stateless)**, `/v1/conversations` is not an API (404),
  oversized-input DoS handled, token tampering rejected. Not fabricated — all three are
  live-verified facts under a shared root, reported separately by distinct impact/remediation.
- **C evals — DONE.** `evals/cases/` holds 5 declarative seed cases across ≥3 OWASP categories
  (LLM01 direct + indirect, LLM02, LLM06, API1), each with reproduce-command; `test_evals`
  asserts load + ≥3 categories. `evals/README.md` maps cases → OWASP → results.
- **E cost analysis — DONE.** `docs/COST_ANALYSIS.md`: unit = model calls (not per-token×n),
  measured dev spend (5 calls / 37 attempts — deterministic tracks are free), per-run model,
  projections at 100/1K/10K/100K, Governor circuit-breaker. Linked from KEY_METRICS #7.
- **G metrics/users — VERIFIED.** KEY_METRICS.md (8 metrics, CTO-defensible) + USERS.md (3
  users, why-automation, human-in-loop) meet the bar; #7 now links COST_ANALYSIS.md.

**All hard-gate deliverables now present.** Remaining human-only: demo video, portal submission.

**Refactor (GitHub #1) — DONE.** Unified the five attack-execution paths (`run_case`,
`run_authz_case`, `run_document_attack`, `run_mint_auth_probe`, `run_rate_limit_probe`) behind
one `drive()` driver (owns target-resolve + `TargetUnreachable`→INCONCLUSIVE + `finalize`) and a
`send_turns()` helper with the auth/body merge precedence as an explicit `body_wins` flag. Each
path is now a thin `produce` closure. `finalize` is called from exactly one place; the authz
observation reuses `build_observation`. 10 tiny commits, suite green at each; added the
previously-missing `TargetUnreachable`→INCONCLUSIVE test. `uv run pytest` = 115.

**Refactor (GitHub #2) — DONE.** Category routing policy consolidated into one low-level
`routing.py` (`AUTHZ_CATEGORIES`, `DOCUMENT_CATEGORIES`, `execution_kind`, `is_deterministic_only`);
dispatch dispatches on `execution_kind`, campaign refuses via `is_deterministic_only`, the
scattered category sets removed. 4 tiny commits, suite green.

## 2026-09-29 — six-role architecture review + remediation (all three tiers)

Six subagents reviewed each role (Orchestrator, Red Team, Judge, Documentation, Executor,
Regression) for full-featured + coherent + integrity. David chose to fix all three tiers.
Deterministic core is sound; the gaps cluster as fake-verdict/finding vectors + coverage gaps +
doc overclaims. Checklist (— = todo, ✓ = done):

**Tier 1 — integrity (fake verdict/finding), highest priority**
- [x] T1.1 Judge: a category with no applied *category-relevant* oracle → INCONCLUSIVE, never FAIL
  (StatusOracle NOT_APPLICABLE unless DoS is the criterion; Judge guard on uncovered categories).
- [x] T1.2 Red Team `run_case`: echo-strip the marker before judging (as the document path does).
- [x] T1.3 Red Team `mutate()`: re-force category/owasp, re-strip latency_budget, clear model auth.
- [x] T1.4 Red Team `generate()`: clear model-invented foreign_canaries for non-NEEDS_CANARY; clear auth.
- [x] T1.5 Documentation: gate fails CLOSED on unknown/malformed severity; refuse/gate no-evidence findings.
- [x] T1.6 Regression: faithful replay of the closure probes (mint ×2, rate-limit) — persist a
  probe/oracle kind in the frozen case and replay on it; treat frozen-critical INCONCLUSIVE /
  unreplayable as non-green.

**Tier 2 — honesty & hardening**
- [ ] T2.1 Executor: pin `follow_redirects=False`; validate `route` rooted-path; enforce or downgrade `scope`.
- [ ] T2.2 Judge: wire `provider_block` onto the target-response path; implement or remove `PARTIAL`.
- [ ] T2.3 Docs: derive report "Observed vs expected" from `expected_safe`; fix ARCHITECTURE/PLAN
  overclaims (rubric, drift, recon/SHA, regression-trigger, mid-campaign stop); refresh PLAN P0–P6.

**Tier 3 — features (some need human input — flag, don't fake)**
- [ ] T3.1 Oracles for excessive-agency, system-prompt-leakage, improper-output-handling.
- [ ] T3.2 LLM rubric tier (non-Qwen) for no-oracle categories — NEEDS a non-Qwen model key.
- [ ] T3.3 Judge-drift detection — NEEDS a human-labeled calibration set.
- [ ] T3.4 Multi-turn attacks — target is stateless (recon), so document as N/A vs build.
- [ ] T3.5 Recon/SHA-diff signal + Orchestrator regression trigger + CI regression gate.
- [ ] T3.6 DoS payload synthesis in the harness (size param, not model tokens); surface finish_reason.
- [ ] T3.7 Orchestrator prioritization: outcome-mix momentum, route-granular coverage, SHA/cost
  signals, is_deterministic_only candidate filter, Jev vendor-outage fallback, `--max-model-calls`.
- [ ] T3.8 Red Team: thread verdict/oracle-results + techniques into `mutate`; memory payload digest;
  provider-block handling + fallback.

**Refactor (GitHub #3) — DONE.** Uniform `Probe = (case, produce)` + `run_probe`; `mint_probe`,
`rate_limit_probe`, `turn_probe` builders separate construction from execution; the public
`run_*` functions are thin build-then-`run_probe` wrappers; `run_authz_probes` is now one flat
build-then-run loop. 4 tiny commits, suite green. `uv run pytest` = 118; live smoke re-confirmed
the 3 findings + BOLA-held against the deployed target after both refactors.
