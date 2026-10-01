# Data model, data quality, and access controls

Covers the optional engineering deliverables **E9** (exploit-DB data quality), **E10** (migration
support + queue-depth monitoring), and **E11** (data model + access controls + lineage). The store
is a single SQLite database (`var/redteam.db`, gitignored) that is simultaneously the work queue,
the audit trail, and the observability substrate (see `ARCHITECTURE.md`).

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
- `agent_actions` is the ordered audit trail; `cost_ledger`, `coverage`, `target_health`,
  `benign_runs`, `discovery_candidates` are the observability/ancillary tables.

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
- **Required fields validated before write:** the Documentation agent validates evidence/severity
  before writing a report and **fails closed** on unknown/malformed severity (role-review T1.5);
  inter-agent records are validated against the versioned JSON Schemas in `contracts/v1/`
  (`tests/test_contracts.py` validates real persisted records and rejects malformed ones).

## E10 — migrations and queue depth

- **Additive migrations, no data loss:** migrations are numbered `NNNN_name.sql`, applied in order,
  each recorded in `schema_version` (`src/redteam/store/store.py::migrate`). Applying is idempotent;
  **a new field is a new migration file, never an edit to an applied one**, so existing rows migrate
  without loss. Eight migrations are in place (0001–0008). Verified by
  `tests/test_store.py::test_migrations_are_idempotent`.
- **Queue-depth monitoring:** `queries.queue_depth` reports pending work — campaigns not yet run and
  reports awaiting approval — surfaced in `redteam report` under "Queue depth". A rising depth means
  work is accruing faster than it drains (the signal for an operator/autoscaler). Verified by
  `tests/test_data_quality.py`.

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
  is read-only behind basic auth (Q15).
- **Reporting/lineage:** a report links `finding_id` → `verdict_ids` → attempts → evidence, so a
  reviewer can walk from a published report to the exact captured exchange.

See `ARCHITECTURE.md` (trust boundary, AI-use disclosure), `contracts/` (E5/E6), and the
requirements matrix in this plan for cross-references.
