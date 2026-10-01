# /contracts — versioned inter-agent message schemas

Every message that crosses a trust boundary between components, and every typed error, has a
versioned JSON Schema here (Draft 2020-12, minimum `v1`). These are the **wire contracts**
between agents — distinct from the SQLite store's own migration-versioned schema
(`src/redteam/store/migrations/`). A message carries `schema_version`; the store versions
itself through numbered migrations.

## v1 schemas (`contracts/v1/`)

| Schema | Producer → Consumer |
|---|---|
| `campaign.schema.json` | Orchestrator → Red Team **(wired: yes — one Campaign row per scheduled brief)** |
| `attack_spec.schema.json` | Red Team → Executor |
| `attempt.schema.json` | Executor → Judge |
| `verdict.schema.json` | Judge → store |
| `finding.schema.json` | derived from SUCCESS verdicts |
| `vuln_report.schema.json` | Documentation → approval gate |
| `error.schema.json` | any component (typed errors, per HARNESS_SPEC E6) |

## Conformance

`tests/test_contracts.py` verifies both halves of each contract:

1. **Schema validity** — every file is a well-formed Draft 2020-12 schema.
2. **Producer conformance** — a *real* record produced by the code validates against its
   schema: a live `run_case`/authz attempt's AttackSpec, Attempt, Verdict, the promoted
   Finding, a rendered VulnReport, and a persisted Campaign row (written by the Orchestrator, one
   per scheduled brief), plus each typed error in `redteam.errors`. The record is assembled from
   the store row (JSON columns parsed back to arrays/objects) and its `schema_version` is read
   **off the row** — every such record now persists one (migrations 0005 and 0009), so nothing is
   hand-stamped. The Campaign's brief `outcome` (`tested` | `skipped` | `provider_blocked` |
   `errored`) is an added property allowed by `additionalProperties`; the status enum is
   unchanged, so this stays `v1`. All seven messages are now checked against real records.
3. **Negative control** — one deliberately malformed instance **per schema** is rejected, so
   every contract is shown able to fail (a contract that accepts everything tests nothing).

## Versioning policy

Additive, optional fields are a `v1` revision. A **breaking** change (removed/renamed field,
tightened type, new required field) needs a **new `contracts/v2/` file**, a migration note
here, and updated conformance tests — never an edit to a shipped version. `additionalProperties`
is permitted so a producer may carry extra columns (e.g. `created_at`) without breaking consumers.

## Two schema families (kept separate)

- **These** — our own inter-agent messages + typed errors, authored here.
- **Target message schemas** — the shapes the Co-Pilot's *own* routes accept/return, pinned in
  `vendor/agentforge-schemas/` (snapshot + provenance) so the Executor builds valid requests.
