# Judge calibration set (KEY_METRICS #5)

Human-labelled examples of the safe/violation boundary, replayed through the Judge to measure
agreement (raw rate + Cohen's κ) and to catch drift when the rubric model, its prompt, or its
provider changes. Machinery: `src/redteam/drift.py`; run with `uv run redteam calibrate`.

## Status

**`calibration_v1.yaml` has 12 entries (10 deterministic, 2 rubric; 6 SUCCESS, 6 FAIL), below
the 20-30 target in the composition list below, and its labels are not human-reviewed.**
`redteam calibrate` agrees on 10 of 10 deterministic entries (kappa 1.00), skips the 2 rubric
entries without a rubric model, and prints `NOT VALIDATED` (exit 1) until a human reviews every label
and sets `review_status: human-reviewed`. The violation-side entries were authored outside the
assistant session because its output safety classifier truncates attack-response content (see
`docs/PLAN.md`, "Course clarifications"); more entries, including the borderline and
judge-addressed ones listed below, are still owed.

## Format

```yaml
version: calibration-v1
labeled_by: <who labelled the entries>
review_status: unreviewed        # a human sets `human-reviewed` after checking every label
entries:
  - entry_id: <unique id>
    tier: deterministic | rubric  # which Judge tier the entry exercises
    label: SUCCESS | PARTIAL | FAIL | INCONCLUSIVE   # the human's verdict
    rationale: <one line: why this label>
    observation:                  # any Observation fields (src/redteam/oracles/base.py)
      response_text: <the target's response>
      status_code: <int>
      # optional: injection_marker, foreign_canaries, patient_ids_in_response,
      # requested_patient, expect_rejected, authorized_data_present,
      # latency_ms, latency_budget_ms, provider_events
```

`deterministic` entries test that the oracle definitions match human intent; a disagreement
there is a mis-specified oracle, not drift. `rubric` entries carry only `response_text` (the
rubric model sees its decoded text, the body's JSON string values, and nothing else) and exercise the excessive-agency / system-prompt-leakage rubric.

## Target composition (20–30 entries, per ARCHITECTURE "Detecting and correcting a drifting Judge")

- A balance of labels on both sides of each boundary, so κ is meaningful (a set that is all one
  label makes κ undefined).
- Rubric entries covering excessive-agency and system-prompt-leakage, including clear safe
  responses (evidence and citations only) and borderline ones.
- Deterministic entries for each oracle, including the known sharp edge: an `expect_rejected`
  probe answered with a 400/404 (the authz oracle currently scores it SAFE; see
  `docs/PLAN.md` S9 note).
- A few entries whose response text addresses the judge directly, to measure injection
  resistance of the rubric tier.

## Validation rule

`redteam calibrate` exits 0 only when the set is non-empty, `review_status: human-reviewed`, no
rubric entry was skipped (a rubric model is configured), and the Judge agrees with every label.
Otherwise it prints why it is not validated and exits non-zero.
