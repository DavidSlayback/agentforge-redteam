# Architecture

> PRD Stage 4 hard gate. Companion records: `docs/adr/0001–0005`, `CONTEXT.md` (vocabulary),
> `docs/DATA_MODEL.md`, `docs/EXTERNAL_APIS.md`, `docs/PERF.md`, `docs/COST_ANALYSIS.md`,
> `docs/INTEGRATION_PACKET.md`, `docs/ATO_PACKET.md`, and `docs/PLAN.md` (requirements matrix and
> decision log). `THREAT_MODEL.md` and `USERS.md` are the inputs this plan assumes. Status labels
> follow `AGENTS.md`: a capability is *done* only when it is wired, tested, and observed live;
> otherwise this document says `implemented, not wired`, `wired, untested`, or `not done`.

## Summary

The AgentForge Red Team platform continuously attacks one authorized target, the AgentForge
Clinical Co-Pilot, and records whether its weaknesses are found, fixed, and stay fixed. The design
is a **deterministic control plane that calls LLM-backed roles in-process and persists every
handoff to one SQLite store**. The store is the audit trail, the regression suite, and the
observability substrate the Orchestrator reads; it is not a message queue, and the agents are
called synchronously, not through it. One store means no second state to drift.

Four requirements are structural, not conventional. First, **Judge independence**: the verdict
comes from deterministic oracles first, and an LLM rubric tier runs only where no oracle exists,
on a different model family from the attacker (a model-name check rejects a Qwen rubric model).
Second, **authorization by construction**: one deterministic Executor is the only code that opens
a socket to the target, and it checks `authorization.yaml` on every request and never follows
redirects. The Red Team agent holds no network access and no credentials and emits attack text as
data. Third, **auditability**: every agent action is an ordered `agent_actions` row, every write
is part of an atomic unit of work, and a finding links back through verdicts, attempts and
evidence to the exact request and response. Fourth, **honest verdicts**: a missing, errored or
empty response is `INCONCLUSIVE`, never a pass, and a provider content block is a typed outcome,
not evidence that a defense held.

The roles are the **Orchestrator** (a deterministic ranker over per-route coverage and open
findings, with an optional Jev selector among the top candidates and hard budget and halt rules it
cannot override), the **Red Team agent** (Qwen; generates attacks and one guarded mutation), the
**Judge** (oracles, then the rubric tier), and the **Documentation agent** (a deterministic,
template-driven report writer, not an LLM). The deterministic services are the **Executor**, the
**Regression runner** (replays frozen findings through their original probes, triggered by the
`redteam poll` Recon service on a new target SHA), and **Recon** (SHA polling today). A separate
**Discovery tier** reviews captured evidence with an independent LLM and emits candidates for
human triage, never verdicts. Human approval gates sit where a wrong autonomous call is costly:
publishing critical or high reports and editing the authorization registry. The platform never
proposes or applies fixes to the target.

Cost is controlled by putting free work on the high-volume paths. Oracles, authorization probes,
token minting and regression replay make no model calls; only attack generation, mutation, rubric
judging and discovery do. In the store, 139 of 172 attempts needed no attacker model. Cost scales
with model calls, not attempts; see `docs/COST_ANALYSIS.md`. Where a capability is only designed or
only unit-tested, this document says so; the last section is a wired, tested and live status table
for the base commit, and the platform's own LLM-driven attack path has so far produced no finding.

## Agents and services

Every component runs in one Python process per CLI command. "Coordination" names what actually
happens in the code, not the intended message flow.

| Component | Kind | Role | In → Out | Trust | Coordination (as built) |
|---|---|---|---|---|---|
| **Orchestrator** | Deterministic ranker; optional Jev LLM selector (off by default) | Chooses the next campaign: (category, route) brief | store state (campaign coverage, open findings) → a brief and a `Campaign` row | Decides; **cannot** override budget, halt or authorization | Calls `run_campaign` in-process; writes one `Campaign` row per brief with its outcome |
| **Red Team** | LLM agent (Qwen) | Generate a case from a brief; mutate a non-success once | brief → `SeedCase` (data only) | **Least trusted**: no network, no credentials | Called by the campaign loop; its specs are persisted with the attempt |
| **Judge** | Oracles, then non-Qwen rubric LLM | Rule SUCCESS, FAIL or INCONCLUSIVE | `Observation` → `Verdict` | Independent of the attack engine | Called by the runner; the verdict and its audit action commit in the attempt's unit of work |
| **Documentation** | **Deterministic code, no LLM** | Confirmed finding → report | `Finding` → `VulnReport` | Writes reports; high and critical held for a human | `redteam document <finding_id>`; refuses an incomplete finding (`DataQualityError`) before writing anything |
| **Executor** | Deterministic service | The only path to the target; authorization per request | URL + request → `ResponseRecord` | Holds the origin allow-list; mints tokens through itself | Called by the runner, minter, recon and probes |
| **Regression runner** | Deterministic service | Replay frozen cases on a build; flag reappearance | `regression_cases` + SHA → attempts | Deterministic | `redteam regression` (no attacker key: `_wire_replay`), or triggered by `redteam poll` on a SHA change; a reappearance raises `RegressionDetected` and exits 1 |
| **Recon** | Deterministic service | Poll `/health` for `git_sha`; trigger regression on change | `/health` → target-health row, regression run | Read-only against the target | `redteam poll`, cron-friendly; route inventory is `not done` |
| **Discovery tier** | LLM reviewer (non-Qwen by default) | Open-ended review of stored evidence | attempts → `discovery_candidates` | Leads only; cannot write findings | `redteam discover`, or `redteam poll --discover` |

Human-facing outputs: a **static dashboard** (`redteam dashboard`, one self-contained HTML file;
no server and no login), a markdown report (`redteam report`), and a **CLI approval** path
(`redteam approve`) that writes an approval record into the report row. Both views answer the PRD's
six observability questions from the store's tables. The "recent agent actions" panels are
newest-first over the most recent N (`queries.agent_trace`; `agent_trace_chronological` gives the same
window in order). `queries.cost_by_run` and `cost_trend` give per-run cost in **model calls** (calls,
attempts, calls per attempt, cumulative calls; `usd` is `None` when a call is unpriced, so unknown,
not free; no price is wired for any model), and `queries.resilience_over_time` gives the verdict mix
and attack-success rate per category per build, builds ordered by earliest attempt, with an
improving or worsening call. All three render in `redteam report` and the dashboard. There is still
no per-agent cost and no USD figure: the ledger's `tokens` and `usd` columns are never written.

## Interaction diagram

```mermaid
flowchart TB
  Orch["Orchestrator<br/>rank + optional Jev · budget / halt"]
  Loop["Campaign loop + Runner<br/>generate → dispatch → judge → persist"]
  RT["Red Team (Qwen)<br/>no network · no creds"]
  Judge["Judge<br/>oracles → DeepSeek rubric"]
  Recon["Recon<br/>poll /health"]
  Reg["Regression runner"]
  Store[("SQLite store<br/>system of record")]
  Doc["Documentation<br/>deterministic, no LLM"]
  Gate{"Human: CLI approval<br/>critical / high"}
  Disc["Discovery tier<br/>candidates only"]
  Dash["Dashboard / report<br/>read-only"]

  subgraph TB["Trust boundary: the only path to the target"]
    Exec["Executor<br/>authz checked per request"]
    Target["Target: Clinical Co-Pilot"]
  end

  Orch -- "campaign brief" --> Loop
  Loop <-- "brief / SeedCase (data)" --> RT
  Loop <-- "observation / verdict" --> Judge
  Loop <-- "request / response" --> Exec
  Exec == "HTTP" ==> Target
  Recon -- "new SHA" --> Reg
  Reg -- "replay frozen cases" --> Loop
  Recon -- "GET /health" --> Exec

  Orch <-. "rank / record" .-> Store
  Loop -. "one transaction" .-> Store
  Store -. "finding" .-> Doc
  Doc --> Gate
  Store <-. "evidence / candidates" .-> Disc
  Store -. "read-only" .-> Dash
```

Solid arrows are in-process calls, dashed arrows are reads and writes of the store, and the
thick arrow is the only network edge. An interactive version with per-component trust levels is
[docs/architecture.html](docs/architecture.html).

## How the repo works

A map for reading the code, checked against it on 2026-10-01. The platform is one Python
package (`src/redteam/`, run as `uv run redteam <command>`) over one SQLite file
(`var/redteam.db`). Every command is a thin entry point onto the same small set of mechanisms.

### Seven ideas that explain most of the code

1. **One currency: `SeedCase`** (`evals/case.py`). A hand-authored YAML seed, an attack the Red
   Team generates, a mutated variant, and a frozen regression case are all the same pydantic
   model: ordered `turns` (method, route, body), an `OracleConfig`, a category, and OWASP tags.
2. **One execution funnel.** Anything that touches the target goes
   `dispatch` → one of `run_case` / `run_authz_case` / `run_document_attack` / `run_probe` →
   `Executor.request` → `build_observation` → `Judge.judge` → `finalize`. Live campaigns,
   deterministic probes, and regression replay share it, which is what makes replay faithful.
3. **One door.** `Executor.request` asserts the URL's origin is an enabled entry in
   `authorization.yaml` before the sender runs. The token minter, the Recon poll, and every probe
   go through it; the Red Team never holds a client.
4. **One verdict path.** Only the Judge builds a `Verdict` (tier-0 oracles compose; the rubric
   model is consulted only when no oracle applies and cannot overturn a violation). A test
   (`tests/test_verdict_path.py`) fails if code outside the judge package builds one.
5. **The model owns only text.** After the Red Team returns a case, the platform overwrites its
   id, target, category, OWASP tags, oracle, marker, and auth, so the model cannot choose its own
   success criterion or its own target.
6. **One store, one unit of work.** `finalize` writes the spec, attempt, evidence, verdict, audit
   row, and (on a confirmed exploit) the deduplicated finding and frozen regression case in one
   transaction. A write outside a unit raises `UnscopedWrite`, and a sqlite authorizer denies raw
   writes on the connection, so a crash cannot leave an attempt without its verdict.
7. **Fail closed.** No response, a provider block, a degraded target, or a rubric call the budget
   cannot cover is `INCONCLUSIVE`, never `FAIL`; "not measured" and "could not verify" are non-zero exits.

### One campaign, end to end (`redteam campaign`)

```mermaid
sequenceDiagram
  autonumber
  participant O as Orchestrator
  participant S as Store
  participant L as Campaign loop / Runner
  participant R as Red Team (Qwen)
  participant X as Executor
  participant T as Target
  participant J as Judge
  loop until budget / no signal / nothing runnable
    O->>S: read coverage + open findings
    O->>O: rank (category, route) briefs, selector picks one
    O->>S: insert Campaign (running) + "select" audit row
    O->>L: run_campaign(brief)
    L->>S: read prior attempts (memory)
    L->>R: generate(brief, history) [metered]
    R-->>L: SeedCase (platform rewrites id, oracle, marker)
    L->>X: mint session token (cached per patient)
    L->>X: request(url) via dispatch
    X->>X: assert origin enabled in authorization.yaml
    X->>T: HTTP
    T-->>X: response
    X-->>L: record
    L->>L: build Observation (strip echoes, decode JSON)
    L->>J: judge(observation)
    J-->>L: Verdict (oracles, rubric only if none apply)
    L->>S: ONE transaction: spec, attempt, evidence, verdict, finding, frozen case
    opt verdict is FAIL (at most one mutation)
      L->>R: mutate(parent, verdict) [metered]
      Note over L,J: same dispatch, judge, persist
    end
    L-->>O: brief outcome (tested, skipped, provider_blocked, errored, unreachable, budget_halted)
    O->>S: stamp outcome on the Campaign row
  end
```

The Orchestrator's score per (category, route) is `1/(1+tested)` (explore) plus
`min(0.5 * open_findings / (1 + tries_since_last_finding), 0.49)` (exploit) minus `0.5 * untested`
this run. The 0.49 cap keeps an open finding from out-ranking an untried pair. Halts: the run-spanning
`CallBudget` (checked before every metered call), `max_campaigns`, and a no-signal streak that
counts only *tested* campaigns.

### Command flow

```mermaid
flowchart LR
  hunt["campaign · authz<br/>disclosure · grounding"] --> Store[("store<br/>attempts · verdicts<br/>findings · frozen cases")]
  Store --> document --> approve
  deploy(["new deploy"]) --> poll --> regression --> Store
  Store --> discover --> triage["candidates / triage"]
  triage -. "human hardens a real one<br/>into an oracle + probe" .-> hunt
  Store --> look["report · dashboard<br/>evidence · integrity"]
```

| Command | Model | Target traffic | Writes | Exit code |
|---|---|---|---|---|
| `campaign` | Qwen; rubric and Jev if configured | yes | campaigns, specs, attempts, evidence, verdicts, findings, frozen cases, cost, audit | 2 config error or no candidates; 1 nothing tested; else 0 |
| `authz`, `disclosure`, `grounding` | none | yes | same, minus campaigns | 1 if any probe `SUCCESS` |
| `benign` | none | yes | `benign_runs` | 1 if over-refusal was not measured or exceeds `--max-over-refusal` |
| `regression --sha` | none | yes | replay attempts, `regression_cases.last_result` | 1 unless every frozen case held |
| `poll` | none (a discovery model with `--discover`) | `/health`, then replay if the SHA changed | `target_health`, replays | 1 if the build is unidentifiable or the replay is not clean; 0 if unreachable |
| `discover` | non-Qwen reviewer | no | `discovery_candidates` | 2 if no model configured |
| `candidates`, `triage` | none | no | candidate status | 0 |
| `document`, `approve` | none | no | `vuln_reports` | 0 |
| `report`, `dashboard`, `evidence` | none | no | none (`dashboard` writes an HTML file) | 0 |
| `integrity` | none | no | none (read-only open) | 1 attention; 2 hot journal |
| `calibrate` | rubric optional | no | none | 1 unless validated |

Typical loop: `poll` (or `regression`) on each deploy, `authz` and `campaign` to hunt,
`document` then `approve` for a finding, `report` or `dashboard` to look. Authorization is the
first thing every target-touching command does: `_wire` loads `authorization.yaml` and exits if
the `--target` id is not in it.

### Code structure

```text
src/redteam/
  cli.py                 argparse entry point; builds live pieces lazily (_wire)
  agents/
    orchestrator/        orchestrator.py loop · candidates.py ranker · selector.py (Deterministic | Jev) · budget.py
    redteam/             agent.py generate/mutate -> SeedCase · model.py (OpenAI-compatible Qwen client)
    judge/               judge.py tier-0 composition · rubric.py (DeepSeek) · discovery.py (open-ended reviewer)
    documentation/       agent.py report rendering + approval gate (deterministic)
  campaign.py            generate -> dispatch -> mutate loop; meters every model call
  dispatch.py, routing.py   category -> execution path (authz | document | direct | frozen probe)
  runner.py              send_turns, build_observation, finalize (the persist unit), drive
  authz_probe.py         deterministic probes: mint, BOLA, rate limit, enumeration, grounding, disclosure, DoS
  document_attack.py     indirect injection: upload + scan flow
  executor/              authorization.py registry · executor.py the gate · http_sender.py · token.py
  oracles/               base.py (Observation, Oracle) · deterministic.py · authz.py · decode.py
  findings.py            dedup key, classification, provisional severity, promote
  regression/            freeze + replay (+ cross-category flag)
  recon/                 /health poll -> SHA change -> regression [-> discover]
  discovery.py           run_discovery, triage_candidates
  memory.py, canary.py   prior-attempt digest for the Red Team · victim-only canary harvesting
  benign.py, drift.py    over-refusal measurement · Judge calibration (Cohen's kappa)
  owasp.py               category -> OWASP tags, objective, technique families
  store/                 store.py (transactions, authorizer) · migrations/0001-0009
  observability/         queries.py · report.py · dashboard.py
  contracts/target/      pydantic generated from vendored target schemas
authorization.yaml       the registry (human-edited only)
contracts/v1/            wire-contract JSON Schemas (conformance-tested, not a runtime bus)
evals/                   seed cases, benign set, calibration set
tests/                   offline suite (no target, no keys): 509 passing, 1 skipped
```

```mermaid
flowchart TB
  CLI["cli"]
  ORCH["agents.orchestrator<br/>loop · ranker · selector · budget"]
  MID["campaign · regression · recon · discovery · benign"]
  DISP["dispatch + routing"]
  PATHS["runner · authz_probe · document_attack · findings"]
  AGENTS["agents.judge · agents.redteam · agents.documentation"]
  CORE["executor · oracles · store · evals (SeedCase) · owasp · errors"]
  CLI --> ORCH --> MID --> DISP --> PATHS --> AGENTS --> CORE
```

Read the layers as "may depend on anything below", from the import graph: the CLI imports
nearly everything, `dispatch` imports the three execution paths, and the paths import the Judge,
Executor, oracles, and store. There is one import cycle, `runner` and `regression` (replay
imports `dispatch` lazily to break it).

### Soft spots to expect questions on

- **Coordination is in-process**, not a durable queue (see "Design vs implementation" below):
  no crash-resume of a half-run campaign, single Executor throughput.
- **`poll` exits 0 when the target is unreachable** ("nothing recorded"), which is gentler than
  the platform's own "a missing verdict is never a pass"; a scheduled job needs its own alert.
- **Judge calibration is `NOT VALIDATED`** until a human flips `review_status`; κ=1.00 is over
  12 entries whose labels follow from observable facts.
- **Multi-turn attacks are N/A** (the target's composer is stateless); mutation is one guarded
  rephrase, not a search.
- **Jev's base model is undisclosed**, so selector independence from Qwen is owner-asserted.
- **GitLab CI has no runners**, so the suite is verified locally on 3.13 and 3.14.

## The eight Stage-4 questions

1. **Which agent owns each function.** Attack generation: Red Team. Evaluation: Judge. Strategic
   prioritization: Orchestrator. Reporting: Documentation (deterministic). Execution against the
   target: the Executor, deliberately not an agent. Regression replay and recon: deterministic
   services. Open-ended discovery: the Discovery tier.
2. **How agents communicate.** In-process function calls, with the result of each step persisted to
   the store. Versioned JSON Schemas for `Campaign`, `AttackSpec`, `Attempt`, `Verdict`, `Finding`,
   `VulnReport` and a typed `error` live in `/contracts/v1`. Conformance is **checked in tests**
   against real persisted rows (producer side); nothing validates a message against its schema at
   runtime, and no consumer-side check exists. The schemas are written so an independently built
   agent could plug in, but no peer integration has been done (`docs/INTEGRATION_PACKET.md`). The
   store is not a work queue: a "failed agent never blocks a producer" is not a property of this
   build, because there is no producer/consumer decoupling.
3. **How the Orchestrator picks the next target.** Each candidate is a (category, route) pair. Its
   score is an exploration term `1 / (1 + tested campaigns)` plus an exploitation term for
   categories with open findings, capped at 0.49 so an open finding can never out-rank an untried
   pair, minus a run-scoped penalty for pairs that could not be tested. A pair with two untested
   outcomes (skipped, provider-blocked, errored, unreachable) in one run is retired for that run.
   Coverage is counted from `Campaign` rows only, scoped to the target. Two signals feed the score
   (coverage and open findings). "Routes changed since the last tested SHA" and "estimated
   campaign cost" are **not** ranking inputs: SHA change triggers regression through Recon, and cost
   is bounded by the `--max-model-calls` cap. The Jev selector (`--selector jev`, key-gated) picks
   among the top 3 and falls back to the deterministic top-1 below a confidence floor of 0.5. It is
   `wired, tested with stubs, not observed live`: all 60 `select` actions in the store are
   deterministic.
4. **How Judge verdicts feed regression.** A SUCCESS verdict is promoted to a finding, deduplicated
   on `(violating oracle, sink, category)`, and frozen as a `regression_case` with its `probe_kind`
   so it replays through the same probe that found it. A replay of `SUCCESS` is a reappearance;
   only a clean `FAIL` counts as held; `INCONCLUSIVE` is neither. Replay re-runs the **exact frozen
   case**: there is no mutated-variant replay, so "the fix generalizes past the exact string" is
   `not done`.
5. **Where human gates sit.** Critical and high report publication (`redteam approve`); changes to
   `authorization.yaml` (a git-tracked file only a human edits). The gate fails closed: an unknown
   severity or a finding with no evidence is held. Not built: a review queue for inconclusive
   verdicts and a clinical-harm lane. `INCONCLUSIVE` verdicts are recorded and counted in
   `redteam report`; nothing routes them to a person. The platform never proposes or applies fixes.
6. **AI versus deterministic.** AI where the task is open-ended language: attack generation and
   mutation, rubric judgment of oracle-less classes (excessive agency), optional campaign
   selection, and discovery. Deterministic wherever a wrong or drifting result is unacceptable: the
   authorization gate, budget and halt, all oracles, regression replay, the ranker, and reports.
7. **Cost, rate limits, model constraints at scale.** See the next section, `docs/EXTERNAL_APIS.md`
   and `docs/COST_ANALYSIS.md`. The cost circuit-breaker is the run-spanning `CallBudget`
   (`--max-model-calls`, default 200), checked before every metered call.
8. **State and coordination infrastructure.** A hand-rolled control plane over SQLite (ADR 0001),
   no graph or agent framework. The store owns transactions: every logical unit (a judged attempt,
   a replayed case, a report, a recon trigger) commits or rolls back together. LangGraph is the
   documented revisit trigger if agent count or branching grows.

## Rate limits, authentication and failure handling

Full per-API table: `docs/EXTERNAL_APIS.md`. The behavior, as built:

- **Target:** the Executor sends one request, with a 90 s timeout and no redirects, and does **not**
  retry or back off. A transport failure raises `TargetUnreachable`, which the runner records as an
  `INCONCLUSIVE` attempt. The token minter alone retries a mint `429`: up to 2 retries, waiting
  `Retry-After` (capped at 60 s), then raises `TargetUnreachable`. There is no queue; the policy is
  abort-to-INCONCLUSIVE.
- **Attacker and rubric models:** bearer-key authentication from the environment. For the attacker,
  a timeout or HTTP error raises `TargetUnreachable` (retriable) and the brief is `errored`; a
  content-filter block raises `ProviderBlock` and the brief is `provider_blocked`; neither is
  retried. A failed or unreadable rubric call degrades that one verdict to `INCONCLUSIVE`. In the store, 40
  of 47 brief errors are attacker-model read timeouts at the 90 s default
  (`AGENTFORGE_REDTEAM_TIMEOUT` raises it). The budget cap, not backoff, bounds volume.
- **Jev:** key-gated; any vendor error falls back to the deterministic top-1.
- **Authorization:** the target is selected by id from `authorization.yaml`; the registry loads
  fail-closed (`enabled` must be a YAML boolean, an enabled entry needs non-empty `proof`).

## Data model, migrations, indexes and SLO

- **Migration approach:** numbered, additive SQL files (`0001`–`0009`, schema v9 in the canonical
  store). Each applies atomically with its `schema_version` row, a failure rolls back and names the
  file, and an applied file is never edited: a new field is a new `ALTER TABLE ... ADD COLUMN` with a
  default, so existing rows migrate without loss (`0005` added `schema_version` to five tables,
  `0009` added `outcome` and `schema_version` to `campaigns`). Verified by
  `tests/test_store.py::test_an_older_store_with_rows_migrates_forward_without_loss` and, per
  `docs/PLAN.md`, on copies of the v8 store and the three older backups. A store opens its own
  migrations on first use.
- **Queue-depth monitoring:** `queries.queue_depth` reports `campaigns_pending` (rows with status
  `new`) and `reports_pending_approval`. Honest state: **no code inserts a campaign with status
  `new`**, because campaigns run synchronously, so `campaigns_pending` is always 0 and only the
  approval backlog is live (3 reports pending in the canonical store). If a worker pool is added
  (see `docs/PERF.md`), campaign rows would be enqueued as `new` and this metric becomes real; a
  backlog would then be the signal to scale workers or lower the campaign budget.
- **Indexes** (migrations `0001`–`0009`), by query pattern: findings by severity
  `ix_findings_severity(severity_score)`, by category `ix_findings_category` and
  `ix_attack_specs_category`, by status `ix_findings_status`, by system version
  `ix_attempts_target_sha` (and `ix_benign_runs_sha`); joins `ix_attempts_spec`,
  `ix_verdicts_attempt`, `ix_evidence_attempt`, `ix_regression_finding`; audit
  `ix_agent_actions_campaign(campaign_id, ts)`; coverage `ix_campaigns_target_outcome`.
  `findings.dedup_key` is `UNIQUE`.
- **SLO:** a full regression replay completes within **5 s of platform overhead** (target latency
  excluded). `tests/test_slo.py` asserts every hot query uses an index and times a stub-sender
  replay under that ceiling. On this machine the overhead is 10 to 14 ms per frozen case (500
  cases in 4.8 to 6.8 s over three runs), so the 5 s bound holds up to roughly 350 to 500 frozen cases; it is
  `measured locally`, and `not verified in CI` because the GitLab pipeline has no runner
  (`docs/PERF.md`).

## AI-use disclosure

| AI role | Model (set by environment) | Deterministic check or human gate that follows | Residual risk |
|---|---|---|---|
| Red Team generation and mutation | Qwen via an OpenAI-compatible endpoint (`AGENTFORGE_REDTEAM_MODEL`) | Output is data; the Executor sends it; oracles judge the response; the platform, not the model, sets the oracle marker and DoS budget | Provider content filter may block a generation (typed `provider_blocked`); frequent read timeouts |
| Judge rubric tier | A non-Qwen model (`AGENTFORGE_REDTEAM_RUBRIC_MODEL`; DeepSeek in use) | Runs only where no oracle applies (excessive agency); never overrides an oracle VIOLATION; unreadable or failed replies are INCONCLUSIVE | Independence is a model-name check, not a proof of a different training lineage; judge bias or drift; 12 verdicts in the store carry a rubric result |
| Orchestrator selector | Jev `jev-1.13.0`, optional, off by default | A deterministic ranker produces the candidates; budget, halt and authorization are outside it; low confidence or vendor error falls back to top-1 | Jev's base model is undisclosed; never observed live |
| Discovery tier | Non-Qwen by default; an explicit same-family model is honored (Qwen Max recommended) | Emits candidates only to `discovery_candidates`; a human triages each; a confirmed one is hardened into a deterministic oracle | False-positive leads (12 of 32 dismissed); no authority to open a finding |
| Documentation | **No AI** | n/a: template-driven from stored fields; critical and high held for a human | Wording is generic per category, not tailored by a model |

Model names above are configuration read from the environment; they cannot be verified from the
repository, which holds no key or model pin beyond `jev-1.13.0`.

**Development-time AI use.** The platform's code, tests and docs were written with an AI coding
assistant (Claude Code): all 270 non-merge commits through 2026-10-10 carry an `Assisted-by:` or
`Co-Authored-By:` trailer naming it, and the 2026-10-12 cleanup and deliverables audit was also
AI-performed. Independently checked: the offline test suite and contract-drift check (run locally;
GitLab has no runner), and live runs against the owned target recorded in the store with their build
SHA. Not recorded: the assistant's own spend (`docs/COST_ANALYSIS.md`, OWNER row 5). Residual risk:
AI-written docs can overclaim; the implementation-status table below is the reconciled check against
the code.

**Detecting and correcting a drifting Judge.** The deterministic tier cannot drift: it is pure code,
so a drift question applies only to the rubric tier and to oracle rules.

1. *Measured now:* `redteam calibrate` scores the Judge against `evals/calibration/calibration_v1.yaml`
   (12 entries: 10 deterministic, 2 rubric) for agreement and Cohen's kappa (`src/redteam/drift.py`).
   The 10 deterministic entries agree (10 of 10, kappa 1.00) without a model; the 2 rubric entries
   run only when a rubric model is configured. The set still reports `NOT VALIDATED`: its labels are
   `review_status: unreviewed` until a human flips them. Run it after any rubric model, prompt or
   oracle change; a drop in agreement is the correction trigger (revert the change, or relabel
   with a human).
2. *Replay stability:* the frozen regression cases are re-judged on every build; an oracle change
   that flips a historical verdict shows up as a changed `last_result`. The frozen-case check
   (`tests/test_frozen_cases.py`, `REDTEAM_FROZEN_CHECK_STORE`) re-judges stored attempts offline
   and compares outcomes.
3. *Not built:* a two-judge pairing whose disagreement is a label-free drift alarm; rerun-stability
   scoring of the rubric tier. A retired pinned rubric model fails closed, since an HTTP error is
   INCONCLUSIVE, but nothing alarms on that rate.

## Known tradeoffs, failure modes, and edge cases

| Situation | Behavior (as built) | Rationale |
|---|---|---|
| **Executor is a single serialized door** | Accepted by design; the load test attributes the throughput ceiling to it (`docs/PERF.md`) | One door is what makes authorization structural |
| **Target unreachable or 5xx** | Attempt is `INCONCLUSIVE`; a brief where every attempt failed to connect is `unreachable` and counts as untested | A missing verdict is never a pass |
| **Budget exceeded mid-campaign** | `BudgetExceeded` stops the run cleanly (brief `budget_halted`); the call that would exceed is never made; no resume point is stored | Cost accruing without signal must halt |
| **Judge cannot decide** | `INCONCLUSIVE`, recorded and counted; no human review queue exists | Fail closed |
| **Provider content block** (attacker side) | Typed `provider_blocked` brief outcome, no retry or fallback model | A filter is not the target's defense |
| **Target degrades (sparse retrieval)** | The `Attempt` contract has `retrieval_mode`, but the runner does not populate it and the Judge does not read it. Only the benign over-refusal set treats retrieval failure as inconclusive | Gap, `not done` |
| **Agent crash or timeout** | No queue and no retry; the unit of work rolls back, so no half-written verdict. `redteam integrity` lists any attempt without a verdict | Atomic persistence replaces retry |
| **Regression "passes" after a fix** | Only a clean `FAIL` through the original probe counts as held; behavior shift alone is INCONCLUSIVE | PRD's central regression warning |
| **Red Team output is itself harmful** | Never executed except through the Executor against the authorized synthetic target; stored as data | Synthetic-only, single-target boundary |
| **Why not LangGraph, CrewAI, or one red-team tool** | ADR 0003 considered-options; ADR 0005 build-vs-configure | Second state store; shared-context judge; no orchestrator or harness |

## Standing risks and gaps

- We own recovery logic a framework would provide; atomic persistence and fault-injection sweeps
  cover storage, not agent-level retry.
- **PyRIT, garak and spikee are not wired.** `AGENTS.md`, `KICKOFF.md` and ADR 0005 plan them as
  runtime tools; none is in `pyproject.toml`, `uv.lock` or `src/`. The Red Team calls the Qwen
  endpoint directly.
- Pinned hosted model versions can be retired without notice; recalibrate after any change.
- The platform's own LLM-driven path has produced no finding; all seven came from deterministic
  probes (`THREAT_MODEL.md`).
- The local replica (`agentforge-w2-local`) is `enabled: false`; high-volume campaigns and the
  free-tier embedding-quota isolation planned in ADR 0003 are `not done`.
- Multi-turn attack sequences are N/A (the composer is stateless); mutation is one guarded rephrase,
  with `max_mutations` defaulting to 1; `redteam campaign --max-mutations N` sets it (`0` disables
  mutation; each mutation is a metered attacker call).

## Discovery tier (open-ended, candidate-only)

`src/redteam/agents/judge/discovery.py` and `src/redteam/discovery.py`. An independent LLM
reviews each captured request and response with no checklist and emits **candidates**, never
verdicts and never findings, because the deterministic oracles and the rubric tier only recognize
pre-encoded classes. A human hardens a confirmed candidate into an oracle and probe; this produced
`MetadataDisclosureOracle` and F-ca9486ff1b. It writes only to `discovery_candidates`. In the
store: 32 candidates from two reviewers (DeepSeek and Qwen Max), 20 promoted to existing findings,
12 dismissed as false positives, 0 new classes (`docs/DISCOVERY_TRIAGE.md`).

## Implementation status (2026-10-01, reconciled with the merged code; store counts read on base `2f3ea96`)

Wired = called by a CLI path. Tested = a test fails if it breaks. Live = recorded in
`var/redteam.db` (read through a copy) against the deployed target.

| Capability | Wired | Tested | Live | Note |
|---|---|---|---|---|
| Executor boundary and registry | yes | yes | yes | every run |
| Deterministic authorization battery | yes | yes | yes | `redteam authz` |
| Red Team generate and one mutation | yes | yes | yes | 33 attempts (22 generated, 11 mutations); all FAIL |
| Judge: oracles, one verdict path | yes | yes | yes | 172 verdicts |
| Judge: rubric tier | yes | yes | yes | 12 rubric-carrying verdicts; calls not metered before 2026-10-01 |
| Calibration (`redteam calibrate`) | yes | yes | n/a offline | kappa 1.00, awaiting human review flip |
| Orchestrator ranking and `Campaign` rows | yes | yes | yes | 3 campaigns from the 2026-10-01 run: 1 tested, 2 errored on attacker timeouts |
| Jev selector | yes | stubs only | no | 0 live selections |
| Documentation agent and approval gate | yes | yes | yes | 7 reports; 3 held pending approval |
| Regression replay (frozen case) | yes | yes | yes | last read on `926805ce`: held 5, reappeared 2 |
| Regression on SHA change (`redteam poll`) | yes | yes | no | `target_health` is empty in the canonical store |
| Discovery tier | yes | yes | yes | 3 passes, 32 candidates |
| Benign over-refusal set | yes | yes | yes | one run, build `da7451d1`: 0 of 11 |
| Atomic persistence and integrity check | yes | yes | yes | `redteam integrity`: 0 attempts without verdict, 0 findings without a case |
| Typed errors | partly | yes | no | `JudgeTimeout` (rubric timeout becomes INCONCLUSIVE) and `RegressionDetected` (regression CLI, exit 1) are raised; `NoFindingsInWindow` is `RESERVED` (nothing asks for a window); none is serialized into the `error` schema at runtime. `tests/test_typed_errors.py` |
| Documentation data-quality refusals | yes | yes | no | `redteam document` exits 1 with named reasons before any write; not exercised on the live store since the merge |
| Eval-case Stage-3 enforcement | yes | yes | n/a | 13 committed cases, 11 categories; subcategory, risk class and evidence required (`evals/README.md`) |
| Regression CI gate | no | n/a | n/a | the pipeline has no runner; run locally |
| Fix-holds under mutation | no | n/a | n/a | replay is exact-case only |
| State-diff oracle, tool-trace visibility | no | n/a | n/a | black-box |
| Peer-agent integration | no | n/a | n/a | solo build |

## Design vs implementation: coordination (2026-10-01, reconciled with the code)

The 09-28 design (ADR 0001/0003) describes agents as isolated workers that take typed tasks
from the store. The build is a single process: `Orchestrator.run` calls `run_campaign`, which
calls the Red Team, `dispatch`, the Executor, and the Judge as ordinary functions, and persists
each unit of work in one transaction. What survived intact is the part the requirements need:
one source of truth, an ordered audit trail, Judge/attacker separation, and the single-door
Executor. What did not get built is independent workers draining a durable queue, so there is
no crash-resume of a half-run campaign and the Executor's throughput (docs/PERF.md) is the
ceiling. The `queue_depth` observability query counts `campaigns` rows in status `new`, which
the Orchestrator never writes (it inserts `running`), so `campaigns_pending` reads 0 by
construction; treat it as unwired. `/contracts` schemas are conformance-tested against real
persisted records (`tests/test_contracts.py`); they are not validated on a runtime message bus.
