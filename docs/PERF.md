# Performance baseline and load profile (E13 / E14)

This document names each platform-level metric, says how it is measured and by what command or test,
and marks every metric **measured**, **recorded earlier (not re-run)**, or **not measured**. An
unmeasured metric stays `not measured`; none is estimated.

> **Do not run `scripts/bench.py --out docs/PERF.md`.** That flag overwrites this file with the
> short baseline template. Run `scripts/bench.py` without `--out` and paste the numbers into the
> tables below.

Environment for every *measured here* number: Windows 11 (10.0.26200), 20 logical CPUs, Python
3.14.7, SQLite 3.53.1, default rollback journal with `synchronous=FULL`, store on a local disk. The
*offline* runs use a stub sender for the target and a fake attacker model, so they measure the
**platform's own overhead only** (Executor, oracles, Judge, store, Orchestrator): no network, no
model, no live target, scratch stores only. They are single runs on a developer laptop, not a
controlled benchmark; repeated runs differed by up to 2x (disk-sync timing), so read them as orders of
magnitude.

## Named metrics

| # | Metric | Definition | How it is measured | Command or test today | Status |
|---|---|---|---|---|---|
| M1 | **Orchestration latency** | Platform time per campaign excluding model and target: ranking, selection, `Campaign` row, case dispatch, judging, persistence | Wall time of `Orchestrator.run` with a fake model and stub target, divided by campaigns | Appendix B (no script in `scripts/` yet) | **measured, offline**: 30 to 36 ms per campaign |
| M2 | **Attacker-model call latency** | Wall time of one generation or mutation call | Needs a per-call timer; `cost_ledger` records only the call start (`ts`), not duration | none | **not measured**. Bound only: 40 of 47 brief errors in the store were 90 s read timeouts |
| M3 | **Target latency** | Per-exchange wall time from the Executor to the live target | `latency_ms` on every stored exchange | SQL over `attempts.exchanges`; `scripts/bench.py` for a controlled run | **measured, recorded from live runs** (below) |
| M4 | **Exploit-storage write throughput** | Judged attempts (spec, attempt, evidence, verdict, audit rows, in one transaction) committed per second | Serial `run_authz_case` calls into a scratch store | Appendix A | **measured, offline**: 76 to 176 attempts/s across runs |
| M5 | **Regression scan time vs SLO** | Platform time to replay every frozen case, target latency excluded; SLO is under 5 s | `replay()` over the real frozen cases, replicated to N, stub sender | `uv run pytest tests/test_slo.py`; Appendix A | **measured, offline**; live 7-case replay also read from the store |
| M6 | **CPU and memory baseline** | CPU busy fraction and process memory under a representative run | `time.process_time` over wall; peak working set | `scripts/bench.py` (CPU, Python heap); Appendix A (working set) | **measured**; live CPU recorded earlier, not re-run |
| M7 | **Observability query time at scale** | Time of the dashboard's group-by queries as the store grows | Synthetic stores of 1K, 10K, 100K attempts | Appendix C | **measured, synthetic** |
| M8 | **100-attack live load test** | 100 consecutive real cases through Executor, live target, oracle, store | `scripts/bench.py --target agentforge-w2 --n 100` | same | **recorded earlier, not re-run** (below) |
| M9 | **Full regression suite, live** | Wall time of replaying every frozen finding against the live target | Span of one build's regression attempts | `redteam regression --target agentforge-w2 --sha <sha>` | **measured, from the store** (below) |

## M8: 100-attack load test (recorded earlier, not re-run here)

`scripts/bench.py` drove 100 consecutive real cases through Executor, live target (`agentforge-w2`),
oracle and store, against a scratch store. The case is a missing-token authorization probe: a genuine
attack case that fails fast at the target's auth check, needs no attacker model, and does not mint.
It isolates the platform's per-case cost from the target's model latency. The earlier run's target
build and date are not recorded in this file; it is not an LLM-attack load test.

| Quantity | Value |
|---|---|
| cases | 100 |
| total wall time | 19.83 s |
| throughput | 5.0 cases/s (serial, single Executor) |
| latency min / median / p95 / max | 135 / 166 / 313 / 1203 ms |
| CPU time / wall | 3.30 s / 19.83 s = 17% busy |
| peak Python heap (tracemalloc) | 2.3 MB |

**Gap against the PRD:** the PRD asks for 100 consecutive attack cases with agent orchestration
latency, LLM call latency and exploit storage throughput. This run covers target-round-trip latency
and Executor throughput. A run that also covers M2 needs a live attacker model and per-call timing
(not instrumented), and is `not done`.

## M3: target latency, from the store (measured on live traffic)

Median and maximum `latency_ms` over the 178 exchanges in the canonical store, by what answered:

| Class (status) | Exchanges | Median | Max |
|---|---|---|---|
| Authorization rejects (`403`, `400`, `429`), battery probes | about 70 | 127 to 189 ms | 447 ms |
| Anonymous mint (`200`) | 29 | 134 ms | 447 ms |
| AI routes (`200`: follow-up evidence, grounding, disclosure, excessive agency, injection) | 39 | 4.4 to 4.8 s | 6.6 s |
| Document scan or upload (`200`) | 20 | 219 ms | 260 ms |

The two regimes are two orders of magnitude apart, which is why the cost and the wall-clock of a run
depend on how many attempts reach a model-backed route, not on the attempt count.

## M1, M4, M5, M6: platform overhead (measured offline, stub target)

| Measurement | n | Result |
|---|---|---|
| Orchestration, per campaign (1.5 attempts each) | 20 and 100 campaigns | 30.0 and 36.4 ms (35.3 ms on a repeat run) |
| Storage write, per judged attempt | 100 cases | 100 and 176 attempts/s (two runs); median 9.9 and 5.6 ms, max 20 and 10 ms |
| Storage write, per judged attempt | 1,000 cases | 76, 89 and 111 attempts/s (three runs); median 11.6, 9.5 and 7.6 ms; max 558, 451 and 323 ms |
| Store growth | 1,000 attempts | 2.5 MB (about 2.5 KB per attempt including evidence and indexes) |
| Regression scan, real frozen cases | 7 cases | 0.11 s (16 ms per case) |
| Regression scan, replicated cases | 100 / 500 cases | 0.97 to 1.29 s / 4.81 to 6.76 s over three runs (10 to 14 ms per case) |
| CPU busy fraction | 1,000 cases / 500-case replay | 19 to 35%: the remainder is commit and disk-sync wait |
| Process memory | whole offline run | working set 47 MB after loading the platform; peak 53 MB; flat at about 49 MB through 1,000 cases and a 500-case replay. Python heap peak under 1 MB (tracemalloc) |

**SLO.** A full regression replay completes within **5 s of platform overhead**, target latency
excluded, as asserted by `tests/test_slo.py::test_full_regression_replay_is_bounded` (a stub-sender
replay of a small frozen set, run in the normal `uv run pytest -q`). The same test asserts that the
hot query patterns use an index. At the measured 10 to 14 ms per case the bound holds to roughly 350 to
500 frozen cases; the test itself exercises far fewer, so it guards against a blow-up, not against slow growth.
`measured locally, not verified in CI`: the GitLab pipeline in `.gitlab-ci.yml` runs this test but has
no runner available, so no pipeline has executed it.

## M9: live regression, full suite (from the store)

The 7 attempts recorded against build `926805ce` span 14:43:18.6 to 14:43:35.3 on 2026-10-01, so a
live replay of all 7 frozen findings took about **17 s** wall, including the rate-limit probe's 20
rapid requests and the token mints. The platform overhead inside it is about 0.1 s (above); the rest
is target round-trip and the mint's `Retry-After` handling.

## M7: observability queries at scale (synthetic)

Synthetic rows shaped like real ones (2 KB evidence bodies), scratch stores, one run each, opened
read-only:

| Attempts | Store size | Pass/fail by category | Outcomes by build | Cases per category | Integrity check | Queue depth, cost, trace(100) |
|---|---|---|---|---|---|---|
| 1,000 | 4.7 MB | 2.0 ms | 0.5 ms | 0.1 ms | 0.3 ms | under 0.2 ms |
| 10,000 | 45 MB | 8.7 ms | 4.7 ms | 0.6 ms | 2.1 ms | under 0.2 ms |
| 100,000 | 455 MB | 551 ms | 96 ms | 109 ms | 73 ms | under 1 ms |

The three group-by queries scan the verdict table, so they grow linearly (the 10K to 100K jump
partly reflects a cold file). The point lookups stay flat.

## Bottleneck and the architectural change

- **Measured bottleneck: the serial run loop waiting on I/O.** The Executor is one door (ADR 0002)
  and the Orchestrator runs campaigns one at a time. CPU is 17 to 35% busy and memory is flat, so
  the process is not compute-bound. On the deterministic path the time is the target round trip
  (about 130 to 170 ms, 5 cases/s); on the model-backed path it is the 4.5 s target call plus the
  attacker call, which has no latency measurement but a 90 s timeout ceiling it often hits.
- **The store is not the bottleneck at this scale:** 6 to 12 ms of commit per attempt, under 10% of
  the cheapest live attempt's wall time (about 130 ms).
- **Architectural change:** a bounded worker pool behind the same authorization gate. N Executors
  share one `AuthorizationRegistry` check and drain a work queue of `Campaign` rows (status `new`
  today never occurs, so `queue_depth.campaigns_pending` is always 0); every worker still calls
  `assert_authorized`, so the single-door invariant holds and only the serialization relaxes.
  Throughput then scales roughly with workers until the target's limits bind (the mint's 15 per 60 s
  per client, the target's model quota) or the single SQLite writer does (6 to 12 ms per commit,
  enable WAL first). The cost consequences by scale are in `docs/COST_ANALYSIS.md`.
- Not yet verified: that the speedup is near-linear. It is an inference from the idle CPU and the
  I/O-bound profile, `not measured`.

## Queue-depth monitoring

`queries.queue_depth` (shown in `redteam report`) reports `campaigns_pending` and
`reports_pending_approval`. With no work queue it is the approval backlog that is live (3 in the
canonical store). When the worker pool lands, a rising `campaigns_pending` is the signal that
workers are saturated; the response is to add workers or lower `--max-campaigns`.

## Appendix: reproducing the offline measurements

These scripts are not in `scripts/` (this task owned documentation only). Save each to a scratch
file and run with `uv run python <file>` from the repo root. They use scratch stores and a stub
sender; `authorization.yaml` is read-only. Promote them to `scripts/` as a follow-up.

### A. Write throughput, regression scan, working set

```python
import json, shutil, sqlite3, statistics, sys, tempfile, time, uuid
from pathlib import Path
from redteam.agents.judge.judge import Judge
from redteam.authz_probe import run_authz_case
from redteam.evals.case import OracleConfig, SeedCase, Turn
from redteam.executor.authorization import AuthorizationRegistry
from redteam.executor.executor import Executor
from redteam.executor.http_sender import ResponseRecord
from redteam.executor.token import TokenMinter
from redteam.regression import replay
from redteam.store.store import Store

REG = AuthorizationRegistry.load("authorization.yaml"); TARGET = REG.by_id("agentforge-w2")

def sender(url, /, **kw):   # stub target: mints succeed, a body with no token gets 403
    if "demo-context" in url or "source-document-context" in url:
        return ResponseRecord(200, json.dumps({"demo_token": "x.y.z", "patient_uuid": "fixture-patient-001",
                              "clinician_uuid": "fixture-physician-001", "expires_in_seconds": 300}), 1.0)
    return ResponseRecord(200 if (kw.get("json") or {}).get("demo_token") else 403, '{"answer":"stub"}', 1.0)

EX = Executor(REG, sender); MINTER = TokenMinter(EX, TARGET)

def case():
    return SeedCase(case_id=f"bench-{time.time_ns()}", category="broken-authentication", owasp=["API2:2023"],
        target_id="agentforge-w2", oracle=OracleConfig(expect_rejected=True),
        turns=[Turn(ordinal=1, route="/v1/follow-up-evidence", body={"patient_uuid": "fixture-patient-001",
               "clinician_uuid": "fixture-physician-001", "message": "benign load-test request"})],
        expected_safe="a patient route rejects a request with no session token")

def write(n):
    store = Store.open(Path(tempfile.mkdtemp()) / "b.db"); lat = []; t0 = time.perf_counter()
    for _ in range(n):
        t = time.perf_counter()
        run_authz_case(case(), REG, EX, Judge(), store, minter=MINTER, target_sha="bench")
        lat.append((time.perf_counter() - t) * 1000)
    wall = time.perf_counter() - t0
    print(f"WRITE n={n} {n/wall:.0f}/s median {statistics.median(lat):.1f} ms max {max(lat):.0f} ms")

def scan(src_db, n):   # src_db: a COPY of the store; its frozen cases are replicated up to n
    p = Path(tempfile.mkdtemp()) / "r.db"; shutil.copy(src_db, p)
    c = sqlite3.connect(p); c.row_factory = sqlite3.Row
    base = [dict(r) for r in c.execute("select * from regression_cases")]; i = 0
    while c.execute("select count(*) from regression_cases").fetchone()[0] < n:
        b = dict(base[i % len(base)]); b["case_id"] = "reg-" + uuid.uuid4().hex[:10]
        c.execute(f"insert into regression_cases ({','.join(b)}) values ({','.join('?'*len(b))})", list(b.values())); i += 1
    c.commit(); c.close()
    store = Store.open(p); t0 = time.perf_counter()
    replay(store, REG, EX, Judge(), "bench-sha", minter=MINTER)
    print(f"REPLAY n={n} {time.perf_counter()-t0:.2f}s")

write(100); write(1000)
for n in (7, 100, 500): scan(sys.argv[1], n)   # argv[1] = path to a COPY of var/redteam.db
```

### B. Orchestration overhead (fake model, stub target)

```python
import tempfile, time
from dataclasses import dataclass
from pathlib import Path
from redteam.agents.judge.judge import Judge
from redteam.agents.orchestrator.budget import Budget
from redteam.agents.orchestrator.orchestrator import Orchestrator
from redteam.agents.redteam.agent import RedTeamAgent
from redteam.executor.authorization import AuthorizationRegistry
from redteam.executor.executor import Executor
from redteam.executor.http_sender import ResponseRecord
from redteam.store.store import Store

CANNED = ('{"case_id":"x","category":"prompt-injection","owasp":["LLM01"],"target_id":"good",'
          '"turns":[{"ordinal":1,"method":"POST","route":"/v1/x","body":{}}],'
          '"oracle":{"marker":"ZZ","foreign_canaries":[],"latency_budget_ms":null},"expected_safe":"refuses"}')
@dataclass
class FakeModel:
    def complete(self, system, user, **kw): return CANNED

d = Path(tempfile.mkdtemp())
(d / "auth.yaml").write_text("targets:\n  - id: good\n    origin: https://good.example\n    proof: test\n    enabled: true\n", encoding="utf-8")
reg = AuthorizationRegistry.load(d / "auth.yaml")
ex = Executor(reg, lambda url, /, **kw: ResponseRecord(200, '{"answer":"stub"}', 1.0))
store = Store.open(d / "o.db")
orch = Orchestrator(registry=reg, executor=ex, judge=Judge(), store=store,
                    agent=RedTeamAgent(target_context="t"), model=FakeModel())
t0 = time.perf_counter()
run = orch.run(target_id="good", surfaces=["/v1/x"], route_fields={"/v1/x": "message"},
               categories=[("prompt-injection", ["LLM01"]), ("denial-of-service", ["LLM10"])],
               budget=Budget(max_campaigns=100, max_model_calls=10000, max_no_signal=10000))
print(f"{(time.perf_counter()-t0)*1000/run.campaigns:.1f} ms per campaign")
```

### C. Observability query time at scale

Build a scratch store with `Store.open(path).close()` (applies the migrations), then bulk-insert
synthetic rows with plain `sqlite3` (`attack_specs(spec_id, category, created_at)`,
`attempts(attempt_id, spec_id, target_id, target_sha, started_at)`, `verdicts(verdict_id, attempt_id,
outcome, judged_at)`, `evidence(evidence_id, attempt_id, exchanges, created_at)` with a 2 KB body),
reopen with `Store.open_readonly(path)`, and time `queries.pass_fail_by_category`,
`queries.outcomes_by_sha`, `queries.cases_per_category`, `queries.cost_summary`,
`queries.queue_depth`, `queries.agent_trace(store, 100)` and `store.integrity()`.
