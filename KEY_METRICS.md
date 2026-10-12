# Key metrics

A small set of numbers we would defend to a hospital CTO: not "we measure a lot," but "we
know what we claim and can show it's true." Each metric names what it proves, how it is
computed from the store, and its current status (measured now vs. needs a component).

## The metrics

| # | Metric | What it proves | Source | Status |
|---|---|---|---|---|
| 1 | **Attack success rate by category, per target build** | Whether the Co-Pilot resists each attack class, and whether it is getting more or less resilient over versions | `queries.pass_fail_by_category` / `owasp_coverage` / `outcomes_by_sha` / `resilience_over_time` | measured, with a caveat: SUCCESS counts include replays of the same finding, so read them beside metric 2; `outcomes_by_sha` is a cross-build comparison keyed by build id, but `resilience_over_time` orders builds by earliest attempt and reports attack-success rate and an improving or worsening call (rendered in `redteam report` and the dashboard; over a handful of live builds it is a short series, not a trend) |
| 2 | **Unique findings after dedup** | Real distinct weaknesses, not repeated noise — the number leadership acts on | `findings` deduped by `(oracle, sink, category)` | measured |
| 3 | **Fix-holds rate under mutation** | A fix generalizes past the exact string — the regression truly passed | regression `replay`: `held` vs `reappeared` across variants | **not measured**: `replay` re-runs the exact frozen case; no mutated variant of a finding is replayed. What is measured is the exact-case result (5 held, 2 reappeared on `926805ce`), which is weaker |
| 4 | **Over-refusal / benign pass rate** | Fixes don't break the clinician — security gains aren't paid for in utility | `evals/benign/clinician_v1.yaml` (6 clinical + 5 XSTest-style + 2 off-topic controls) via `redteam benign`; `benign_runs` table; "Over-refusal" section of `redteam report` | measured once: **0/11 (0%)**, controls 2/2, on `da7451d1`. Not re-run on `d5e79bb3`, `926805ce` or `31f3722a`, so it says nothing about whether the later fixes raised over-refusal. n=11, single run — a trend, not a population estimate |
| 5 | **Judge agreement (Cohen's κ) & pair-disagreement rate** | The verdicts are trustworthy and the Judge isn't drifting | `evals/calibration/calibration_v1.yaml` via `redteam calibrate` (raw agreement + Cohen's κ, `src/redteam/drift.py`); two-judge disagreement over time | **measured: κ=1.00, full agreement** — 10 deterministic entries reproduce unconditionally (10/10); 2 rubric entries score only when a rubric model is configured (12/12 with one, `n=10 skipped=2` without). Labels are objective ground truth. Reports `NOT VALIDATED` pending a human flip of `review_status` to `human-reviewed` — a skim, since labels follow from observable facts |
| 6 | **Coverage vector** (categories × routes × oracles × access modes) | What has and has *not* been exercised — honest about blind spots | `owasp_coverage` + `Campaign` rows per (category, route); `THREAT_MODEL.md` lists the untested classes | partial: category and verdict from the store, per-route coverage from `Campaign` rows (3 so far); oracle and access-mode axes and the recon route inventory are `not built` |
| 7 | **Cost per finding & cost per run, projected to scale** | The platform is economically sustainable to run continuously | `cost_summary`, `cost_by_run`, `cost_trend` (model calls; `usd` is `None` when unpriced); projections in `docs/COST_ANALYSIS.md` | measured in calls: 43 metered attacker calls, a floor (discovery, Jev and pre-2026-10-01 retries unmetered); USD is `OWNER TO SUPPLY` |
| 8 | **Time-to-first-finding & planted-vuln recall** | The platform actually finds real bugs, fast, in an unattended drill | drill scoring (reached/triggered/detected) | **not built**: no `drill` command exists (it is in `docs/HARNESS_SPEC.md` only) and no planted-vulnerability set has been run |

## Current readings (store copy, 2026-10-01; 172 judged attempts, schema v9)

| Metric | Reading |
|---|---|
| Distinct findings (#2) | 7: 5 fixed (validated by replay), 2 risk-accepted. All 7 came from deterministic probes or oracle-hardened discovery; 0 from the 33 LLM-generated attempts |
| Verdict mix (#1) | FAIL 121, SUCCESS 41, INCONCLUSIVE 10 (5.8%). Most SUCCESS rows are replays of the two open mints |
| Regression, last read on `926805ce` (#3 weaker form) | held 5, reappeared 2, inconclusive 0 |
| Over-refusal (#4) | 0 of 11, controls 2 of 2, on `da7451d1` only |
| Judge agreement (#5) | 10 of 10 deterministic calibration entries, κ 1.00; 2 rubric entries skipped without a rubric model; labels not yet human-reviewed (`NOT VALIDATED`) |
| Model calls (#7) | 43 metered attacker calls (26 generation, 17 mutation); 0 rubric calls recorded |

## Rationale for the set

- **1–3 are the core promise:** find weaknesses, confirm they're real and distinct, and
  prove fixes hold. Without #3 measured under mutation, a green regression is not evidence.
- **4 is the clinician's guardrail.** The PRD's bar is "without breaking the clinician";
  a platform that only measured attack success could recommend fixes that quietly raise
  over-refusal. #4 keeps the safety/utility trade-off visible.
- **5 is what makes every other number believable.** If the Judge drifts, metrics 1–3 are
  noise. Deterministic oracles carry most verdicts (no drift by construction); κ and the
  two-judge disagreement rate quantify the residual LLM-judged fraction.
- **6 prevents a false sense of security.** A high pass rate over three routes says nothing
  about the other twenty-seven. Coverage is a vector, never a single percentage.
- **7 is the difference between a one-off experiment and a service.** Continuous testing is only viable
  if cost per finding stays bounded as run volume grows — hence the 100/1K/10K/100K
  projection (AI Cost Analysis), not per-token × n.

## Thresholds

Pass thresholds (an over-refusal ceiling, a minimum κ, a fix-holds bar) are **not set**. The
calibration and benign sets now exist, so the inputs for choosing them do; the choice is the
owner's, and the prior-art review deliberately declines to fix numbers from the teaser alone.
Until then, metrics are reported as trends and per-case evidence, never as a single headline
score.

**How over-refusal is detected on this target (#4).** The Co-Pilot's follow-up route is an
evidence-retrieval service, not a free-text chatbot: it never says "I can't help." It declines by
*qualifying* (`qualification.required: true`, e.g. `insufficient_guideline_evidence`) or by a
non-`ready` status. The detector keys on those fields, not refusal-phrase regexes; auth/throttle/
5xx responses and qualifications issued under a retrieval *failure* are inconclusive, not
refusals. The off-topic controls prove the detector can see a decline (both were qualified), so a
0% rate is a measurement, not a blind spot. Proposed ceiling (pending David): over-refusal must
not rise after a fix on the same set — `redteam benign --max-over-refusal <x>` enforces any chosen
ceiling as a non-zero exit.
