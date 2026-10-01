---
status: accepted (recorded retroactively, 2026-10-01)
date: 2026-10-01
---

# Corrections to the v1 inter-agent contracts, and why none needed a version bump

This ADR records three corrections made to how the `contracts/v1` schemas are produced and checked.
They were decided in review rounds and landed with commit messages and `docs/PLAN.md` entries, but no
ADR was written at the time. It is written now so the PRD's "ADRs for any contract correction"
requirement has a first-class record. The schema files in `contracts/v1/` have not changed since
their first commit (`575af16`, 2026-09-29): every correction below changed a *producer*, a *store
column*, or a *test*, not a published schema.

## Corrections

| # | Date, commit | Defect found | Decision | Migration note |
|---|---|---|---|---|
| C1 | 2026-09-29, `f1dd5fe` | Every schema requires `schema_version`, but no producer wrote it; the conformance tests added it by hand and so overstated conformance | Persist `schema_version` on every inter-agent record and have the tests read it off the stored row | Migration `0005_schema_version.sql` adds `schema_version INTEGER NOT NULL DEFAULT 1` to `attack_specs`, `attempts`, `verdicts`, `findings`, `vuln_reports`; existing rows take version 1, no data loss |
| C2 | 2026-09-29, `f1dd5fe` | Only one negative control existed, so six of seven contracts were never shown able to reject | One deliberately malformed instance per schema, parametrized | none (tests only) |
| C3 | 2026-10-01, `8f34d2c` (GitLab #4) | `Campaign` had no persisting producer: the Orchestrator logged `agent_actions` but wrote no Campaign row, so the schema was exercised by a hand-built instance and marked `wired: no` | The Orchestrator writes one Campaign row per scheduled brief and stamps its outcome; the test validates the persisted row | Migration `0009_campaign_outcome.sql` adds `outcome TEXT` and `schema_version INTEGER NOT NULL DEFAULT 1` to `campaigns`; historical rows have `outcome` NULL and read as "not campaign coverage" |

## Why no `v2`

The versioning policy (`contracts/README.md`) reserves a new `contracts/v2/` file for a breaking
change: a removed or renamed field, a tightened type, a new required field. C1 and C3 add a column
and populate a field the v1 schemas already required (`schema_version`) or already permit
(`additionalProperties: true` admits `outcome`). No consumer that accepted a v1 record rejects any
record the corrected producers write, so these are v1 revisions.

## Known drift this ADR does not fix

- The `outcome` vocabulary in code is `tested`, `skipped`, `provider_blocked`, `errored`,
  `unreachable`, `budget_halted` (refactor #4). `contracts/README.md` now lists all six; `test_campaign_conforms`
  still builds its sample from the first four. The schema does not constrain `outcome`, so nothing breaks; the sample
  in the test is a follow-up for whoever owns `tests/`.
- Typed errors: `error.schema.json` enumerates seven codes and a test builds a conforming message
  from each exception class, but no runtime path serializes an error into that wire form; a caught
  error becomes an audit-action reason string. Update after the code merge: `JudgeTimeout` and
  `RegressionDetected` are now raised (rubric timeout handled into INCONCLUSIVE; the regression CLI);
  `NoFindingsInWindow` is explicitly `RESERVED` and `tests/test_typed_errors.py` enforces the split.

## Consequences

- A future breaking change to any message needs `contracts/v2/`, a migration note in this directory,
  and updated tests, per the policy.
- Peer integration (a different student's agent consuming these schemas) has not happened; see
  `docs/INTEGRATION_PACKET.md` for what that would additionally prove.
