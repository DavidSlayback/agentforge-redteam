"""E13/E14 — baseline + load profile. Drive N consecutive REAL deterministic cases through the full
platform path (Executor → live target → oracle → store) and report latency, throughput, CPU, and
peak memory. Uses a missing-token authz probe: a genuine attack case that is fast (403 before any
model call), needs no attacker model, and does not mint (so it does not trip the mint rate-limit) —
isolating the PLATFORM's per-case cost rather than the target's model latency.

Runs against a scratch store so the canonical store stays clean.

Usage (PowerShell):
  uv run python scripts/bench.py --target agentforge-w2 --n 100 --out docs/PERF.md
"""

from __future__ import annotations

import argparse
import statistics
import time
import tracemalloc
from pathlib import Path

from redteam.agents.judge.judge import Judge
from redteam.authz_probe import run_authz_case
from redteam.config import load_dotenv
from redteam.evals.case import OracleConfig, SeedCase, Turn
from redteam.executor.authorization import AuthorizationRegistry
from redteam.executor.executor import Executor
from redteam.executor.http_sender import http_sender
from redteam.executor.token import TokenMinter
from redteam.store.store import Store


def _missing_token_case(target_id: str, route: str) -> SeedCase:
    return SeedCase(
        case_id=f"bench-missing-token-{time.time_ns()}",
        category="broken-authentication", owasp=["API2:2023"], target_id=target_id,
        turns=[Turn(ordinal=1, route=route,
                    body={"patient_uuid": "fixture-patient-001", "clinician_uuid": "fixture-physician-001",
                          "message": "benign load-test request"})],
        oracle=OracleConfig(expect_rejected=True),
        expected_safe="a patient route rejects a request with no session token",
    )


def _pct(xs: list[float], p: float) -> float:
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--n", type=int, default=100)
    ap.add_argument("--route", default="/v1/follow-up-evidence")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    load_dotenv()
    reg = AuthorizationRegistry.load("authorization.yaml")
    target = reg.by_id(args.target)
    if target is None:
        raise SystemExit(f"target {args.target!r} not in authorization.yaml")
    ex = Executor(reg, http_sender)
    minter = TokenMinter(ex, target)
    judge = Judge()
    import tempfile
    scratch = Path(tempfile.gettempdir()) / f"redteam-bench-{time.time_ns()}.db"
    store = Store.open(scratch)

    latencies: list[float] = []
    tracemalloc.start()
    cpu0, wall0 = time.process_time(), time.perf_counter()
    for _ in range(args.n):
        t = time.perf_counter()
        run_authz_case(_missing_token_case(target.id, args.route), reg, ex, judge, store, minter=minter,
                       target_sha="bench")
        latencies.append((time.perf_counter() - t) * 1000.0)
    wall = time.perf_counter() - wall0
    cpu = time.process_time() - cpu0
    peak_mb = tracemalloc.get_traced_memory()[1] / 1e6
    tracemalloc.stop()
    store.close()
    scratch.unlink(missing_ok=True)

    thr = args.n / wall if wall else 0.0
    rows = [
        ("cases", f"{args.n}"),
        ("total wall time", f"{wall:.2f} s"),
        ("throughput", f"{thr:.1f} cases/s (serial, single Executor)"),
        ("latency min / median / p95 / max", f"{min(latencies):.0f} / {statistics.median(latencies):.0f} / "
         f"{_pct(latencies,95):.0f} / {max(latencies):.0f} ms"),
        ("CPU time / wall (busy fraction)", f"{cpu:.2f} s / {wall:.2f} s = {100*cpu/wall:.0f}%"),
        ("peak Python memory", f"{peak_mb:.1f} MB"),
    ]
    report = "\n".join(f"- **{k}:** {v}" for k, v in rows)
    print(report)

    if args.out:
        doc = f"""# Performance baseline & load profile (E13 / E14)

Measured by `scripts/bench.py` driving **{args.n} consecutive real cases** (a missing-token
authorization probe — a genuine attack case that fails fast at the target's auth check, needs no
attacker model, and does not mint) through the full platform path **Executor → live target
(`{args.target}`) → oracle → store**, against a scratch store. This isolates the platform's per-case
cost from the target's model latency.

## Baseline (this run)

{report}

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
"""
        Path(args.out).write_text(doc, encoding="utf-8")
        print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
