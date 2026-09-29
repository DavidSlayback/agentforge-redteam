# /contracts — versioned inter-agent message schemas

Every message that crosses a trust boundary between components, and every typed error, has a
versioned JSON Schema here (Draft 2020-12, minimum `v1`). These are the **wire contracts**
between agents — distinct from the SQLite store's own migration-versioned schema
(`src/redteam/store/migrations/`). A message carries `schema_version`; the store versions
itself through numbered migrations.

## v1 schemas (`contracts/v1/`)

| Schema | Producer → Consumer |
|---|---|
| `campaign.schema.json` | Orchestrator → Red Team |
| `attack_spec.schema.json` | Red Team → Executor |
| `attempt.schema.json` | Executor → Judge |
| `verdict.schema.json` | Judge → store |
| `finding.schema.json` | derived from SUCCESS verdicts |
| `vuln_report.schema.json` | Documentation → approval gate |
| `error.schema.json` | any component (typed errors, per HARNESS_SPEC E6) |

## Conformance

`tests/test_contracts.py` verifies both halves of each contract:

1. **Schema validity** — every file is a well-formed Draft 2020-12 schema.
2. **Producer conformance** — a *real* record produced by the code (a live `run_case`/authz
   attempt's spec, attempt, verdict, and promoted finding; a rendered vuln report; each typed
   error in `redteam.errors`) validates against its schema. The test parses the JSON columns
   the store persists, so it checks the actual shapes, not hand-built stand-ins.
3. **Negative control** — a deliberately malformed record is rejected, so the schemas can
   actually fail (a contract that accepts everything tests nothing).

## Versioning policy

Additive, optional fields are a `v1` revision. A **breaking** change (removed/renamed field,
tightened type, new required field) needs a **new `contracts/v2/` file**, a migration note
here, and updated conformance tests — never an edit to a shipped version. `additionalProperties`
is permitted so a producer may carry extra columns (e.g. `created_at`) without breaking consumers.

## Two schema families (kept separate)

- **These** — our own inter-agent messages + typed errors, authored here.
- **Target message schemas** — the shapes the Co-Pilot's *own* routes accept/return, pinned in
  `vendor/agentforge-schemas/` (snapshot + provenance) so the Executor builds valid requests.
