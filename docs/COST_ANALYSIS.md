# AI Cost Analysis

Actual dev spend and projected production cost at 100 / 1K / 10K / 100K runs, with the architecture
change each scale forces. The unit of work is a **run = one attack attempt** (one request judged to
one verdict), as the PRD uses it.

**What is real and what is not.** Call and attempt counts below come from the platform's own store
(a read-only copy of `var/redteam.db`, schema v9, read 2026-10-01) and are labelled *measured*.
Throughput numbers come from `docs/PERF.md`. **No USD figure appears anywhere in this document:**
the store records model calls, not tokens or dollars (`cost_ledger.tokens` and `usd` are NULL in
all 43 rows), and no price is wired. Every dollar input is in the `OWNER TO SUPPLY` section below.
Projections that depend on a design choice are labelled *design arithmetic*, not measurements.

## 1. Where the money goes (why per-token times N is wrong)

Most of the platform's work makes no model call:

- **Judging is free on most paths.** Tier-0 oracles (marker, canary, status, authorization, error
  leak, grounding, metadata disclosure, rate limit, enumeration, contradiction) are pure functions.
  The rubric tier is consulted only where no oracle applies (excessive agency and system-prompt
  leakage).
- **The authorization battery, token minting, canary discovery and regression replay are HTTP only.**
- **Only four things draw model calls:** Red Team generation, Red Team mutation, rubric judging, and
  the Discovery tier (plus the optional Jev selector, one call per campaign).

So cost scales with the **LLM share of runs**, not with runs, and with the retry rate of a flaky
attacker endpoint. A separate cost is borne by the *target*: every attempt that reaches an AI route
triggers the Co-Pilot's own embedding and LLM calls on the owner's accounts.

## 2. Actual dev spend (measured from the store)

| Quantity | Value | Source |
|---|---|---|
| Judged attempts | 172 (2026-09-29 to 2026-10-01) | `attempts`, `verdicts` |
| Attempts with a Red Team (LLM) origin | 33: 22 generated, 11 mutations | `attack_specs` (`rt-` ids) |
| Attempts needing no attacker model | 139 (authorization battery, grounding, disclosure, enumeration, data-integrity, DoS, replays) | same |
| Metered attacker calls | **43**: 26 generation, 17 mutation | `cost_ledger` |
| Metered rubric calls | **0 recorded** (rubric metering began 2026-10-01; no rubric run since); 12 verdicts carry a rubric result | `cost_ledger`, `verdicts.oracle_results` |
| Discovery-tier calls | **81 unmetered** (3 passes reviewed 29, 23 and 29 attempts; the first pass's 29 reviews returned reviewer errors per `docs/ATO_PACKET.md`; the store records only "no candidates from 29 reviewed", so an error total is not recoverable from it) | `agent_actions` (`discovery_pass`) |
| Jev selector calls | 0 (all 60 selections were deterministic) | `agent_actions` |
| Tokens, USD | **not recorded** | `cost_ledger.tokens`, `usd` all NULL |
| Attacker-model read timeouts (90 s default) | 40 of 47 brief errors | `agent_actions` (`brief_error`) |
| Findings produced | 7 distinct, all from deterministic probes or oracle-hardened discovery; 0 from the 33 LLM attempts | `findings` |
| Cost per finding, in model calls | 43 attacker calls produced 0 findings; the 7 findings cost 0 attacker calls | derived |

Caveats that make the call counts a floor, not a total: before 2026-10-01 only *successful*
generations and mutations were logged, so retries and the many 90 s timeouts are missing; the
2026-09-28 runs predate the store; rubric and discovery calls were not metered. The observed ratio of
43 calls to 33 LLM attempts (1.3) therefore understates the true cost per LLM attack.

### OWNER TO SUPPLY: actual USD dev spend

The owner has no billing export to supply and asked for a token-based estimate instead (section 2b). Rows below stay `OWNER` only where an estimate cannot stand in (plan fees, assistant spend, target-side spend, hosting). All of these are outside the repository.

| # | Number needed | Where to find it | Already known (from the store) | USD |
|---|---|---|---|---|
| 1 | Attacker model spend: input and output tokens and charge for `qwen3.8-flash` and `qwen3.8-max`, 2026-09-28 to 2026-10-01 | Alibaba Model Studio (Bailian) console, usage and billing, filtered by model and date | 43 metered calls (floor) | OWNER |
| 2 | Rubric and Discovery spend for `deepseek-v4-pro` (and Qwen Max when used for discovery) | Same console, filtered by model | 12 rubric-carrying verdicts; 81 discovery reviews | OWNER |
| 3 | Plan or subscription fee, prorated to the dev window, if the Qwen key bills through a plan | Bailian plan page; the plan notes say it bills in plan credits | n/a | OWNER |
| 4 | Jev (TypeSafe) usage, if any | TypeSafe dashboard | 0 selections | OWNER |
| 5 | AI-assisted development spend (the coding assistant used to build the platform) | Anthropic Console or Claude plan usage page | n/a | OWNER |
| 6 | Target-side AI spend triggered by platform runs: embedding and LLM calls the Co-Pilot made for platform traffic | The target's provider consoles (Gemini embedding quota and the LLM provider) for the same window | about 44 AI-route exchanges (`/v1/follow-up-evidence`) returned `200` at a median of about 4.4 s each, plus the 2026-09-28 pre-store runs | OWNER |
| 7 | Hosting: the deployed target's VM share, if charged to this project | Vultr billing; the platform itself runs on a dev machine | n/a | OWNER |
| 8 | Average tokens per attacker call (input, output) | Row 1 tokens divided by row 1 calls from the provider usage export | needed for every projection below | OWNER |

When rows 1 to 8 are filled, the projection formula in section 5 turns the call tables into dollars.

### 2b. ESTIMATE: dev spend and projections from tokens (not billed amounts)

Every figure here is an **estimate**. The ledger recorded no tokens (`cost_ledger.tokens` and `usd` are
NULL), so token counts per call are **assumptions**, not measurements. Prices are from Alibaba Cloud
Model Studio's published pricing, read 2026-10-01 (international/Singapore, input up to 32K tokens):
`qwen-max` $1.2 in / $6 out per million tokens (50% off for batch), `deepseek-v4-pro` $2.4 in / $4.8
out. The repo's model names (`qwen3.8-flash`, `qwen3.8-max`) are not on that page, so the attacker is
priced at `qwen-max`, which makes the attacker line an upper bound if a cheaper flash tier was used.

| Call type | Assumed tokens in / out | Model priced | USD per call |
|---|---|---|---|
| Attacker generation or mutation | 2,000 / 600 | `qwen-max` | 0.0060 |
| Rubric judge | 2,500 / 300 | `deepseek-v4-pro` | 0.0074 |
| Discovery review | 3,000 / 500 | `deepseek-v4-pro` | 0.0096 |

**Dev spend (estimate):** 43 attacker calls (about $0.26) + 12 rubric verdicts (about $0.09) + 81
discovery reviews (about $0.78) = **about $1.13**. Retries, timeouts and pre-store runs were not
metered, so the plausible range is **$1 to $4** (a 3x pad). It excludes the coding assistant, hosting
and target-side spend (rows 3, 5, 6 and 7), which this estimate does not cover.

**Projection (estimate), using section 3's call counts and discovery at 25% of runs (assumption):**

| Runs | 30% LLM-origin planning mix | 100% LLM-origin worst case |
|---|---|---|
| 100 | about $0.60 | about $1.30 |
| 1,000 | about $6 | about $13 |
| 10,000 | about $60 | about $130 |
| 100,000 | about $600 | about $1,300 |

Model spend is small at every scale, so cost is not what forces the architecture changes in section
4; wall-clock time, the 90 s attacker timeouts and the single Executor are. The levers that matter
at 100K are batch inference (50% off), running discovery on a sample, and deterministic-first
routing, which keeps about 80% of runs at zero model calls. To replace the assumptions with fact,
export tokens by model from the Bailian console (row 8) and rerun the arithmetic in section 5.

## 3. Per-run call model

Per LLM-origin attack: 1 generation call, plus up to `--max-mutations` mutation calls on a mutable
non-success (default 1; `0` removes them, and the ledger counts below were taken at 1), plus retry
overhead. Planning factor **1.7 calls per LLM attack** (design estimate: 1.5 plus 15% retries);
the ledger shows 1.3 as a floor (see caveats). A rubric-judged attack adds 1 judge call. Every call
is metered before it is made, so a retry or a timeout counts against `--max-model-calls` (default
200).

Mix of runs that are LLM-origin: **19% observed in dev** (33 of 172), **30% planning mix**, 100%
worst case. Rubric-carrying verdicts were **7% of attempts** (12 of 172) at the observed mix.

### Projected model calls (design arithmetic on the factors above)

| Runs | Attacker calls, 19% observed mix | Attacker calls, 30% planning mix | Attacker calls, 100% LLM | Rubric calls at the observed mix (about 7% of runs) |
|---|---|---|---|---|
| 100 | ~33 | ~51 | ~170 | ~7 |
| 1,000 | ~326 | ~510 | ~1,700 | ~70 |
| 10,000 | ~3,260 | ~5,100 | ~17,000 | ~700 |
| 100,000 | ~32,600 | ~51,000 | ~170,000 | ~7,000 |

Discovery adds up to one call per reviewed attempt (`--limit` bounds a pass; default 25); it was run
three times in dev. These counts are unaffected by the architecture changes below unless stated.

## 4. What breaks at each scale, and the change that fixes it

The right architecture changes at each order of magnitude because different constraints bind. Cost
per token is the least interesting term.

### 100 runs (the dev scale, close to what the store already holds)

*Binds:* nothing. One process, serial Executor, one SQLite file of about 1 MB.

*Architecture:* as built. Deterministic-first judging keeps this tier's model calls to a few dozen.
The one lever worth pulling now is **reliability**: 40 of 47 brief errors were 90 s attacker
timeouts, and each timed-out call is still a billed, metered call that produced no attempt. A faster
or more reliable attacker model, or a higher `AGENTFORGE_REDTEAM_TIMEOUT` for the slow one, lowers
cost per *usable* attack more than any caching would.

### 1,000 runs

*Binds:* wasted calls and prompt overhead; wall-clock is still minutes for deterministic runs
(about 3 minutes at the measured 5 cases/s) but about 75 minutes if every run reaches an AI route
(about 4.5 s each, serial).

*Changes:*
1. **Deterministic-first routing, made explicit.** Run every deterministic probe on every new build
   (they are free and are the regression suite); spend model calls only on (category, route) pairs
   the Orchestrator ranks highest. The Orchestrator already does this through its coverage term; the
   change is to *cap LLM campaigns per build per pair* so a clean pair is not re-attacked on the same
   build.
2. **Batch generation.** Ask the attacker for k cases per call, so the fixed prompt (system prompt,
   target context, brief) is paid once. With k = 5 the generation call count falls to a fifth;
   output tokens do not shrink, so dollars fall less than calls do. *Design arithmetic, not
   measured.* Mutation depends on the verdict, so it batches only across concurrent briefs.
3. **Prompt-cache the static prefix** where the provider supports it. The target context and
   strategy text are identical across calls. Whether the Bailian endpoint offers prefix caching, and
   its discount, are provider facts to confirm (OWNER TO SUPPLY item 8 covers the token side).
4. **Cheaper rubric tier after recalibration.** The rubric runs for about 7% of runs. Replace
   `deepseek-v4-pro` with a smaller non-Qwen model only if `redteam calibrate` still agrees with the
   labels (today 10 of 10 deterministic entries; the 2 rubric entries are model-dependent), and
   cache rubric verdicts by response hash so identical answers are judged once. The hit rate is not
   measured.
5. **Meter discovery and Jev.** Discovery (81 calls so far) and the selector are outside the budget
   cap today; at this scale an unmetered path can outspend the metered one.

### 10,000 runs

*Binds:* wall-clock and the target. Serial at the measured rate, 10K deterministic runs take about
33 minutes, but 10K AI-route runs take about 12.5 hours, and the target's own quota (its embedding
tier and its mint limit of 15 per 60 s per client) becomes the ceiling before the platform does.

*Changes:*
1. **Queue and worker split.** Introduce a real work queue: the Orchestrator writes `Campaign`
   rows with status `new`, N workers claim and run them, each worker calling the same
   `assert_authorized` gate so the single-door invariant holds (this is also what makes
   `queue_depth.campaigns_pending` mean something; today it is structurally 0). SQLite stays viable
   with WAL and a single writer, because the measured write cost is 6 to 12 ms per judged attempt:
   10K attempts is about 1 to 2 minutes of writing.
2. **Run volume against the local replica.** `agentforge-w2-local` exists in the registry but is
   disabled. Volume sweeps belong there, so the deployed target's quota and the owner's bill are not
   the throttle; re-confirm findings on the deployed SHA only.
3. **Sample the regression suite by severity** once the frozen set grows: critical findings every
   build, the rest on a rotation. Today the set is 7 cases and a full replay is seconds.
4. **Sample discovery.** Reviewing every attempt is one call per attempt. Review only attempts whose
   (route, status, response shape) has not been seen on this build.
5. **Evidence policy.** Keep full request and response for SUCCESS and INCONCLUSIVE attempts and a
   sample of FAIL, with hashes for the rest. Evidence is already 40% of the database bytes
   (measured: 414 KB of 1 MiB).

### 100,000 runs

*Binds:* storage, read-side queries, human triage, and the target's cost.

*Measured on a synthetic store (single run, not representative of production data):* 100K attempts
with 2 KB evidence bodies is a 455 MB database; the per-category pass/fail query takes about
550 ms, the build trend about 100 ms and the integrity check about 70 ms, against under 10 ms at 10K
rows. A dashboard render therefore costs about a second, rising linearly.

*Changes:*
1. **Roll up, do not recompute.** Maintain a summary table (counts by category, build, outcome)
   updated at finalize, so the dashboard and the Orchestrator read constant-time rows instead of
   scanning verdicts. Add the composite index the group-bys need, and move to Postgres with a
   replica if more than one host writes.
2. **Move evidence out of the hot database** (object storage by hash) and keep the store to rows and
   hashes. At 100K attempts evidence alone is hundreds of megabytes.
3. **Automate triage grouping.** At the observed 5.8% INCONCLUSIVE rate (10 of 172), 100K runs yields
   about 5,800 inconclusive verdicts and today nothing routes them to a person. Group by (oracle,
   route, reason) and surface clusters, not rows. The human-approval load scales with *distinct
   findings* (7 so far), not runs, because of dedup.
4. **Use a provider batch endpoint** for non-urgent generation and discovery, where one exists and
   its discount is confirmed; keep the interactive path for the Orchestrator's selected briefs.
5. **Per-build saturation stop.** The Governor's no-signal halt is per run. Make it per
   (build, pair) so a build with no change since the last clean campaign is not re-attacked at all;
   the SHA poller already detects change.
6. **Put the target's spend in the budget.** At this scale the owner's embedding and LLM bill from
   platform traffic can exceed the platform's own. A call cap should cover target-side calls too.

## 5. Projection formula (fill in after the OWNER TO SUPPLY section)

```
USD = attacker_calls × (in_tok × p_in + out_tok × p_out)        # per model, section 3 table
    + rubric_calls   × (in_tok × p_in + out_tok × p_out)        # rubric model
    + discovery_calls × (in_tok × p_in + out_tok × p_out)
    + jev_calls × p_jev
    + target_side_calls × p_target                              # owner's providers, not the platform
```

Token counts and prices are OWNER TO SUPPLY items 1, 2 and 8; the call counts are in section 3.
Each architecture change in section 4 acts on one term: batching and caching reduce `in_tok` per
call, a cheaper rubric lowers `p_in` and `p_out` for that term, sampling and saturation stops reduce
the call counts, and the queue and worker split changes wall-clock, not cost.

## 6. Controls at scale

- The model-call cap is a hard circuit breaker: one run-spanning `CallBudget`
  (`agents/orchestrator/budget.py`), checked before every metered call and at the top of the run
  loop, raising `BudgetExceeded`. A rubric call that would exceed it degrades to INCONCLUSIVE so a
  target exchange already made is kept.
- The Governor owns `--max-campaigns` and `--max-no-signal`; only *tested* campaigns move the
  no-signal streak.
- Per-run call attribution uses the run's own campaign ids, not table deltas, and is shown as per-run
  calls, calls per attempt and a cumulative trend by `queries.cost_by_run` and `cost_trend` (in
  `redteam report` and the dashboard). `usd` there is `None` (unpriced), never a made-up number.
- Not covered by any cap today: discovery calls, Jev calls, and target-side calls.

See `KEY_METRICS.md` for metric definitions, `docs/PERF.md` for the throughput numbers used above,
and `redteam report` for the live call count.
