# Cost Analysis

**Unit: model calls, not per-token.** The attacker model is Qwen (Alibaba MaaS), billed in
plan credits, so the platform meters **model calls** in the `cost_ledger` (per campaign, by
kind: generation / mutation). We deliberately do **not** report a per-token USD figure —
wiring one would invent a number the plan doesn't bill that way, and (below) most of the
platform's work costs *zero* model calls, so a per-token×N estimate would be badly wrong.

## The cost structure (why per-token × N overstates)

Three design choices make cost sublinear in "attacks run":

1. **Deterministic-oracles-first Judge.** Tier-0 oracles (marker, canary-leak, status,
   authorization, error-leak) are pure functions — **0 model calls** to judge an attempt.
   Judging, the step run on *every* attempt, is free.
2. **The authorization track is fully deterministic.** BOLA, missing/forged-token, mint-auth,
   and rate-limit probes are HTTP only — **0 model calls**. All three current findings were
   found at zero model cost.
3. **Token minting, canary discovery, regression replay** are HTTP/deterministic — 0 model calls.

So only **novel LLM attack generation** (and its bounded mutation) costs calls. Judging,
authz, regression, and replay do not.

## Measured dev spend (this store, `var/redteam.db`)

| Kind | Model calls |
|---|---|
| generation | 4 |
| mutation | 1 |
| **total (LLM)** | **5** |
| deterministic attempts (authz/probes) | 32 (of 37 total attempts) — **0 calls** |

37 attempts recorded; 5 model calls. The gap is the deterministic work (authz probes, judging,
minting). Earlier exploratory sessions spent more (aimed campaigns, `qwen3.8-max` runs, and
~14 flash timeouts during one hunt), but the steady-state per-attempt cost is what projects.

**Metering (since 2026-10-01).** Every attacker-model call (`generation`, `mutation`) and every
rubric-judge call (`rubric`; DeepSeek, one per attempt in oracle-less categories) is written to
`cost_ledger` *before* it is made, so a retry, an unparseable reply, or a provider block counts
against `--max-model-calls` (`campaign._MeteredModel` / `_MeteredRubric`). Before that, only
successful generations/mutations were logged and rubric calls not at all, so the historical
totals above undercount retries and rubric-judged runs; the per-run model below adds them.

## Per-run cost model

- **Deterministic run** (authz battery, regression replay, a re-judged attempt): **0 calls**.
- **One LLM attack** (generate + ≤1 mutation; judged by free oracles): **~1.5 calls** avg
  (1 generation always; a mutation only on a mutable non-success).
- **One rubric-judged attack** (oracle-less category): add **+1 judge call** per attempt
  (≈ +2 with a mutation) → **~3 calls**.
- Add retries for attacker-model timeouts (observed on `qwen3.8-flash` for long prompts):
  budget ~15% overhead at scale → **~1.7 calls/LLM-attack**.

## Projection

"Runs" = attack attempts. Deterministic runs stay free at any scale; only LLM attacks draw calls.

| Runs | If all LLM attacks (~1.7 calls/run) | Realistic mix (30% LLM, 70% deterministic) |
|---|---|---|
| 100 | ~170 calls | ~51 calls |
| 1,000 | ~1,700 calls | ~510 calls |
| 10,000 | ~17,000 calls | ~5,100 calls |
| 100,000 | ~170,000 calls | ~51,000 calls |

The "realistic mix" reflects that continuous red-teaming leans on the free deterministic
tracks (authz, regression, re-judging) and reserves the model for novel attack generation.

## Controls at scale

- Cost is a hard circuit-breaker, not a hope. Since GitLab #4 the `max_model_calls` cap is owned by
  a single run-spanning `CallBudget` (`agents/orchestrator/budget.py`), checked **before every
  metered call** (attacker generation, mutation, and rubric) and at the top of the run loop — not
  only between campaigns — so one campaign's retries can no longer overshoot it; reaching it raises
  the typed `BudgetExceeded` and stops the run cleanly, and a rubric call that would exceed it
  degrades to INCONCLUSIVE so the target exchange already made is not lost. The **Governor** owns
  the `max_campaigns` and `max_no_signal` halts (it no longer counts calls — one cap source, not
  two). `max_no_signal` counts only **tested** campaigns (skips / provider blocks / errors /
  unreachable are neither signal nor its absence), so a run that could test nothing exits non-zero
  whatever its halt reason. Per-run cost and new findings are attributed to the run's own campaign
  ids, not global ledger/table deltas. `--max-campaigns` / `--max-no-signal` bound a hunt.
- To convert to money: `calls × (plan credit cost per call)`. Not wired on purpose — see above.
- Cheapest reliable model for volume is `qwen3.8-flash`; `qwen3.8-max` is reserved for aimed
  runs (higher latency/timeout rate made it unsuitable for bulk).

See `KEY_METRICS.md` for the metric definitions and `redteam report` / `dashboard.html` for
the live per-run call count.
