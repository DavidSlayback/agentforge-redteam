# Harness spec — AgentForge Red Team

Design spec for the platform harness (not a status doc; `docs/PLAN.md` stays the index).

> **Reconciliation note, 2026-10-01.** This is the 2026-09-28 *design*. Where it differs from the
> built platform, the code, `contracts/v1/`, the migrations and `ARCHITECTURE.md` win. Known
> differences, marked inline below: the shipped message shapes (for example `Campaign.budget` is
> `{max_campaigns, max_model_calls, max_no_signal}`, not `{usd, requests, model_calls, wall_s}`), the
> index list, the CLI surface, the test layout, and the unbuilt `drill` and `serve-dashboard`
> commands.
Draft 2026-09-28; five decisions (D1–D5) resolved same day, noted inline. Everything here is
structure — schemas, tables, layout, slices. Attack
*content* (eval seed text, threat-model findings) is authored separately; see
memory `claude-safety-blocks-w3`. Vocabulary: `CONTEXT.md`. Shape rationale: `ARCHITECTURE.md`.

## Two schema families (keep separate)

1. **Target message schemas** — the shapes the Co-Pilot's own routes accept/return, so the
   Executor builds valid requests. Generated from the target's Zod (`schemas.js`) → JSON
   Schema → pydantic, exactly as the prior `redteam/` scaffold already does.
   `D1 (resolved: yes):` port that generation chain (`tools/generate_contracts.py` + the drift
   test) into this repo — the one piece of the old scaffold worth carrying.
2. **Inter-agent contracts** — our own messages between components, authored here, versioned
   JSON Schema in `/contracts` (min `v1`). Below.

## Inter-agent contracts (`/contracts`, v1)

Field lists, not full JSON Schema yet. Every record carries `schema_version`. Content that
could be adversarial (attack turns, evidence) is stored by reference/hash, never inline in
a message that crosses a trust boundary.

| Message | Producer → Consumer | Key fields |
|---|---|---|
| `Campaign` | Orchestrator → Red Team | `campaign_id`, `target_id`, `target_sha`, `surface` (route/workflow), `category[]` (OWASP), `objective_ref`, `budget{usd,requests,model_calls,wall_s}`, `priority_inputs{coverage_gap,changed_since_sha,prior_findings,cost_est}`, `selector{jev_version,top_k,chosen,probabilities}`, `status` |
| `AttackSpec` | Red Team → Executor | `spec_id`, `campaign_id`, `parent_spec_id` (mutation ancestry), `mutation_op`, `category`, `target_route`, `turns[]{ordinal,input_ref}`, `oracle_ref`, `expected_safe_ref`, `budget_slice` |
| `Attempt` | Executor → Judge | `attempt_id`, `spec_id`, `target_id`, `target_sha`, `target_env`(local\|deployed), `retrieval_mode`(hybrid\|sparse_only\|no_rerank\|stub), `exchanges[]{request_hash,response_hash,status_code,latency_ms}`, `provider_events[]`, `cost{tokens,calls,usd}`, `evidence_ref` |
| `Verdict` | Judge → store | `verdict_id`, `attempt_id`, `outcome`(SUCCESS\|PARTIAL\|FAIL\|INCONCLUSIVE), `oracle_results[]{oracle,tier,pass}`, `rubric{model,prompt_version,booleans}?`, `evidence_ref`, `calibration_set_version`, `judged_at` |
| `Finding` | derived | `finding_id` (stable: scenario class + target identity), `title`, `taxonomy[]{scheme,version,id}` (OWASP/ATLAS/CWE), `severity{cvss_v4_vector,score,safety_supplemental}`, `clinical_axis` (separate from CVSS), `component`, `first_seen_sha`, `status`, `verdict_ids[]`, `dedup_key{oracle,sink,component}` |
| `VulnReport` | Documentation → gate | `report_id`, `finding_id`, `severity`, `description`, `clinical_impact`, `repro{minimal_spec_id,steps_ref}`, `observed_vs_expected`, `remediation`, `status`, `fix_validation{sha,result}`, `approval{required,approver,at}` |

**Typed errors** (also `/contracts`, per E6): `target_unreachable`, `authorization_denied`,
`budget_exceeded`, `judge_timeout`, `no_findings_in_window`, `regression_detected`,
`provider_block`. Each: `{code, message, context, retriable}`. A hard budget stop and a
provider block are outcomes, not crashes. As built: `JudgeTimeout` and `RegressionDetected` are raised
(rubric timeout becomes INCONCLUSIVE; the regression CLI exits 1), `NoFindingsInWindow` is
`RESERVED`, and no runtime path serializes an error into the contract (`tests/test_typed_errors.py`).

## Store schema (SQLite, single file)

`D2 (resolved: yes):` stdlib `sqlite3` + a `schema_version` table + numbered migration
scripts (satisfies E10 migration, E12 indexing) rather than an ORM — no dependency, easy to
reason about, and the store is the audited source of truth.

Tables mirror the messages plus: `agent_actions` (the ordered trace: `id, ts, agent,
action, campaign_id, refs, reason`), `cost_ledger`, `coverage` (created but never written),
`regression_cases`, `schema_version`, and later `evidence`, `target_health`, `benign_runs`,
`discovery_candidates`. **Indexes as built** (`ARCHITECTURE.md` lists them by query pattern):
`findings(severity_score)`, `findings(primary_category)`, `findings(status)`, `attempts(target_sha)`,
`attempts(spec_id)`, `verdicts(attempt_id)`, `agent_actions(campaign_id, ts)`,
`campaigns(target_id, outcome)`, among others; there is no `findings(taxonomy)` or
`attempts(campaign_id)` index. Regression full-scan SLO: asserted by `tests/test_slo.py`, run
locally (the CI pipeline has no runner; `docs/PERF.md`).

**Transaction rule.** All persistence for one logical unit commits or rolls back together; a
missing verdict is never left silently half-written. The store owns the transaction
(`autocommit=True`, explicit `BEGIN`/`COMMIT`/`ROLLBACK`) through `with store.transaction():`.
Units: a judged attempt (spec, attempt, evidence, verdict, actions, plus finding promotion and
regression freezing, in `runner.finalize`); a regression replay of one case with its
`last_result`; a report with its audit action; a recon SHA-change trigger with its baseline; a
discovery pass; a triage; a benign run; a single audit action (`store.record_action`). Nested
scopes flatten, and an inner failure dooms the whole unit (`TransactionAborted`, chained to the
cause).

A store write outside a scope raises `UnscopedWrite`, and a sqlite3 authorizer refuses
INSERT/UPDATE/DELETE/DDL on the raw connection whenever no scope or migration is running.
Each migration applies atomically with its `schema_version` row; a failed one rolls back and
names the file. `redteam integrity` reports existing half-written units read-only, and exits 2
without touching anything if a crashed write left a rollback journal that only a normal open may
recover. Concurrency (WAL, multi-process writers, busy timeouts) is out of scope.

## Authorization registry

`D3 (resolved: git file):` a **git-tracked `authorization.yaml`** at repo root, read-only to
the Executor, edited only by a human (Q15 gate) — **not** a DB row an agent could write. This
makes SA1 structural: proof lives in version control, and the Executor refuses any origin not
matching an `enabled` entry.

```yaml
targets:
  - id: agentforge-w2
    origin: https://dtstest.64.177.10.182.nip.io   # exact scheme+host, matched literally
    owner: david                                    # owned | written-permission
    proof: "owned; deployed by owner"
    scope: [briefings, source-documents, clinical-actions, observability]
    enabled: true
    added_by: david
    added_at: 2026-09-28
```

The Executor loads this once, and every outbound request asserts the target's origin is an
`enabled` entry or raises `authorization_denied`. No entry ⇒ no request is possible.

## Package layout (this repo)

```
agentforge-redteam/
  pyproject.toml            # uv; pydantic v2, httpx, pytest, (PyRIT later)
  authorization.yaml        # the registry
  contracts/                # JSON Schemas (our messages + typed errors), versioned
  evals/                    # seed cases, OWASP-mapped — CONTENT authored unfiltered
  tools/generate_contracts.py   # target Zod → pydantic (ported)
  src/redteam/
    store/                  # schema, migrations, dao
    contracts/              # generated pydantic (target + our messages)
    executor/               # the one network door + auth gate
    recon/                  # route/SHA inventory
    oracles/                # deterministic checks (canary, scope, write, marker, dos)
    agents/{orchestrator,redteam,judge,documentation}/
    regression/
    observability/          # read-only dashboard
    cli.py
  tests/{contracts,oracles,executor}/   # built as a flat tests/ directory, one file per area
```

## CLI surface

Designed:

- `redteam campaign --target <id> [--budget …] [--time …] [--category …]`
- `redteam regression --target <id> --sha <sha>`
- `redteam drill --target <id> --config <file>`   # bounded, resumable, real exit code
- `redteam report [--finding <id>] [--format md|sarif]`
- `redteam approve <report_id>`
- `redteam serve-dashboard`

**As built** (`uv run redteam --help`): `report`, `dashboard` (writes a static HTML file),
`approve`, `document`, `evidence`, `integrity`, `regression`, `poll`, `discover`, `candidates`,
`triage`, `disclosure`, `grounding`, `benign`, `calibrate`, `authz`, `campaign`. `campaign` takes
`--category`, `--route`, `--patient`, `--victim-patient`, `--max-campaigns`, `--max-no-signal`,
`--selector`, `--model`, `--max-model-calls`, `--max-mutations` (default 1; `0` disables mutation) and
`--target-sha` (no `--budget` or `--time`). `regression` needs no attacker key (`_wire_replay`).
`document` refuses an incomplete finding with `DataQualityError` (exit 1). **Not
built:** `drill`, `serve-dashboard`, and `report --finding` / `--format sarif`.

## Execution slices

Two cuts, in build order. `D4 (resolved: S0–S5):` the first cut adds a minimal
Red Team on top of Executor/oracles/Judge/seed-evals/dashboard — so two live agent roles
(Red Team + Judge) run against the target, not just the deterministic path. Orchestrator,
Documentation, and the regression harness land in the second cut. S3 and S5 are
interdependent: land the seed-eval runner first (S3) so the Red Team (S5) has
a working execute→judge loop to mutate into; keep S5 minimal (generate + one mutation op),
defer multi-turn and operator variety to the second cut.

| Slice | Cut | What | Done when | Reqs |
|---|---|---|---|---|
| S0 | 1 | Scaffold: uv package, layout, ported contract-gen, CI stub | repo installs, `pytest` + drift test pass | — |
| S1 | 1 | **Safety core**: `authorization.yaml` + Executor + store schema/migrations | a test proves the Executor refuses an unlisted origin | SA1, E10, E12 |
| S2 | 1 | Deterministic oracles + Judge emitting `Verdict` | oracles pass/fail on known-positive & clean cases; Judge live | P2, P6(trace) |
| S3 | 1 | Seed evals (≥3 OWASP categories, content authored unfiltered) run live via Executor | Attempts+Verdicts produced against the deployed SHA; reproducible | G3, E1 |
| S4 | 1 | Observability: dashboard reads the store | answers the 6 PRD questions from stored rows | P6 |
| S5 | 1 | **Minimal Red Team** (Qwen): generate + one mutation op, over the S3 loop | a partial success mutates into a live variant | P1 |
| S6 | 2 | Orchestrator: ranker + Jev selector + budget/halt | picks a campaign from state; halts on budget | P3 |
| S7 | 2 | Documentation agent + ≥3 reports + human gate | a report reproduces from its `minimal_spec_id` | P4, S3(reports) |
| S8 | 2 | Regression harness + regression-on-deploy; Red Team multi-turn + more operators | a fixed finding's case flips correctly across SHAs | P5, P1 |
| S9 | 2 | Drill mode, metrics, cost analysis, deploy | one-command bounded drill; cost at 100/1K/10K/100K | H, S4 |

`D5 (resolved: yes):` eval seed **content** (the actual case inputs) is authored by David or
an unfiltered model; this harness provides the case *schema*, loader, and runner.

## Decisions (all resolved 2026-09-28)

D1 port contract-gen ✓ · D2 sqlite+migrations ✓ · D3 auth as git-tracked YAML ✓ ·
D4 first cut = S0–S5 (Red Team + Judge both live) ✓ · D5 eval-content authoring split ✓.
Spec is decision-complete; ready for implementation handoff.
