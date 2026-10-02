# Data model, data quality, and access controls

Covers the optional engineering deliverables **E9** (exploit-DB data quality), **E10** (migration
support + queue-depth monitoring), and **E11** (data model + access controls + lineage). The store
is a single SQLite database (`var/redteam.db`, gitignored, schema v9) that is the audit trail, the
regression suite, and the observability substrate (see `ARCHITECTURE.md`). It is **not** a work queue
on this commit: agents are called in-process and persist results to it.

## Entities and lineage

Every record is linkable end-to-end, so any finding traces back to the exact bytes that produced it:

```
campaign ──< attack_spec ──< attempt ──< verdict ──> finding ──> vuln_report
                 │               └──> evidence (full request/response)        │
                 └── parent_spec (mutation ancestry)        regression_case <─┘ (frozen on confirmation)
agent_actions: an ordered, append-only trace of every agent decision (campaign_id + ts)
```

- `campaigns` → `attack_specs` (with `parent_spec_id` for mutation ancestry) → `attempts`
  (`target_sha`, exchanges) → `verdicts` (outcome, oracle_results) → `findings` (deduped) →
  `vuln_reports`. A confirmed finding freezes a `regression_case` (`case_json` + `probe_kind`) so it
  replays faithfully.
- `evidence` holds the full (synthetic-only) request/response per attempt; `attempts.evidence_ref`
  / `verdicts.evidence_ref` point to it.
- `agent_actions` is the ordered audit trail; `cost_ledger`, `target_health`, `benign_runs`,
  `discovery_candidates` are the observability/ancillary tables. The `coverage` table exists in the
  schema but nothing writes it (0 rows); coverage is computed from `campaigns` rows instead.
- **Lineage reach, honestly:** the Orchestrator has written one `campaigns` row per scheduled brief
  only since refactor #4, so in the canonical store 171 of 172 `attack_specs` have a NULL
  `campaign_id` (operator-run probes and pre-#4 campaigns). A finding walks back to its attempt,
  verdict and exact evidence in every case; it walks back to an Orchestrator decision only for
  campaign-origin attempts (`docs/INTEGRATION_PACKET.md` §6 traces one of each).

## E9 — data quality

- **Unique id:** every finding has `finding_id` (PK) derived from `target_id` + a deterministic
  `dedup_key`; every report/attempt/verdict/spec carries its own PK.
- **No duplicate attack sequences / findings:** `findings.dedup_key` is `UNIQUE` over
  `(violating_oracle, sink, category)` — the sink is stored in the `component` column, so the schema
  comment phrases the same tuple as `(oracle, sink, component)`. `findings.promote`
  (`src/redteam/findings.py`) inserts, and
  on `IntegrityError` **appends the new verdict to the existing finding** instead of creating a
  duplicate — so the same weakness found by N attempts is one finding with N linked verdicts, never
  N findings. Verified by `tests/test_store.py::test_dedup_key_is_unique` and
  `tests/test_data_quality.py`.
- **Required fields validated before write:** `DocumentationAgent.document()` refuses a
  finding, before any write, that lacks a unique identifier (`finding_id`, `dedup_key`), an attack
  category, a severity level, reproduction steps (no captured exchange), observed behavior (no oracle
  violation) or expected behavior (no `expected_safe`), or whose attack sequence duplicates another
  finding's report. It raises `DataQualityError` (a `ValueError`) with every named reason at once;
  `redteam document` prints them and exits 1. The approval gate still **fails closed**: high,
  critical or an unrecognised level is held for a human (a finding with no evidence is now refused,
  not held). Verified by `tests/test_documentation_data_quality.py`. The Red Team agent also rejects
  a generated case with a blank `expected_safe`. Inter-agent records
  are validated against the versioned JSON Schemas in `contracts/v1/` by `tests/test_contracts.py`
  (real persisted rows pass, malformed ones are rejected); nothing validates against the schemas at
  runtime. Referential integrity is enforced by SQLite foreign keys (`PRAGMA foreign_keys = ON`) and
  checked read-only by `redteam integrity` (attempts without a verdict, findings without a
  regression case).

## E10 — migrations and queue depth

- **Additive migrations, no data loss:** migrations are numbered `NNNN_name.sql`, applied in order,
  each recorded in `schema_version` (`src/redteam/store/store.py::migrate`). Applying is idempotent
  and each file is atomic with its version row (a failed one rolls back and names the file);
  **a new field is a new migration file, never an edit to an applied one**, so existing rows migrate
  without loss. Nine migrations are in place (0001–0009; the canonical store reads schema v9).
  Verified by `tests/test_store.py::test_migrations_are_idempotent`,
  `test_failed_migration_rolls_back_and_the_store_reopens` and
  `test_an_older_store_with_rows_migrates_forward_without_loss`. Adding a field to the vulnerability
  report: `ALTER TABLE vuln_reports ADD COLUMN ... DEFAULT ...` in a new file, as `0005` and `0009`
  did for `schema_version` and `outcome`.
- **Queue-depth monitoring:** `queries.queue_depth` reports `campaigns_pending` (status `new`) and
  `reports_pending_approval`, surfaced in `redteam report` under "Queue depth" and verified by
  `tests/test_data_quality.py`. **Honest state:** no code inserts a campaign with status `new`
  (campaigns run synchronously), so `campaigns_pending` is always 0 and only the approval backlog is
  live (3 pending in the canonical store). The metric becomes meaningful when a worker pool enqueues
  campaigns (`docs/PERF.md`); until then there is no queue to back up.

## E11 — access controls and lineage

- **Who writes / reads exploits:** the Documentation agent is the only writer of `vuln_reports`;
  findings are written only by `findings.promote` from a confirmed `SUCCESS` verdict. The read-only
  dashboard and `redteam report` read; they never write.
- **Approval before publish:** critical/high reports are created `pending_approval` and are published
  only by an operator running `redteam approve <report_id> --approver <name>`, which writes an
  approval record (`vuln_reports.approval`) into lineage (SA3). The gate **fails closed** on
  unknown/malformed severity and refuses no-evidence findings.
- **Auditable, attributable trace:** every agent decision is an ordered `agent_actions` row
  (agent, action, refs, reason, ts); an unattended run (`redteam poll`, campaigns) is fully
  reconstructable from it. Only operators with shell access to the host trigger runs; the dashboard
  is a static HTML file written by `redteam dashboard` (read-only by construction: no server, no
  login, so no basic auth exists to configure; Q15).
- **Reporting/lineage:** a report links `finding_id` → `verdict_ids` → attempts → evidence, so a
  reviewer can walk from a published report to the exact captured exchange.

See `ARCHITECTURE.md` (trust boundary, AI-use disclosure), `contracts/` (E5/E6), and the
requirements matrix in this plan for cross-references.
