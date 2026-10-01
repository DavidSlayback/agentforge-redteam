# Performance baseline & load profile (E13 / E14)

Measured by `scripts/bench.py` driving **100 consecutive real cases** (a missing-token
authorization probe — a genuine attack case that fails fast at the target's auth check, needs no
attacker model, and does not mint) through the full platform path **Executor → live target
(`agentforge-w2`) → oracle → store**, against a scratch store. This isolates the platform's per-case
cost from the target's model latency.

## Baseline (this run)

- **cases:** 100
- **total wall time:** 19.83 s
- **throughput:** 5.0 cases/s (serial, single Executor)
- **latency min / median / p95 / max:** 135 / 166 / 313 / 1203 ms
- **CPU time / wall (busy fraction):** 3.30 s / 19.83 s = 17%
- **peak Python memory:** 2.3 MB

## Reading it — bottleneck and the architectural fix

- **The bottleneck is the single serialized Executor door** (ADR 0002: one component may reach the
  target, so authorization is structural). Throughput is ~`1 / per-case latency` because cases run
  one at a time; per-case latency is dominated by the network round-trip to the target, not CPU
  (busy fraction above). This is the accepted correctness-over-throughput tradeoff documented in
  `ARCHITECTURE.md`.
- **The architectural fix to scale** is a bounded **worker pool behind the same authorization gate**:
  N Executors sharing one `AuthorizationRegistry` check, draining a work queue, so throughput scales
  ~linearly with workers until the target's own rate limit (the `429` on the mint, F-6ee) or model
  quota becomes the ceiling. The single-door *invariant* is preserved (every worker calls
  `assert_authorized`); only the serialization is relaxed. Cost at scale: `docs/COST_ANALYSIS.md`.
- Memory is flat per case (peak Python memory above is for the whole run), so the platform is
  CPU/IO-bound on the network, not memory-bound — a worker pool, not a bigger box, is the right lever.
