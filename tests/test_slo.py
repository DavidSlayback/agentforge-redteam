"""E12 — the common query paths are index-backed (not full scans), and a full regression replay is
bounded. Runs in CI via the normal pytest suite, so a regression that drops an index or turns a
hot query into a table scan fails the build.

The SLO is asserted structurally (EXPLAIN QUERY PLAN shows an index) rather than by wall-clock, so
it is deterministic in CI; a coarse timing ceiling guards the full-replay path against a blow-up.
"""

from __future__ import annotations

import time
from pathlib import Path

from redteam.agents.judge.judge import Judge
from redteam.executor.authorization import AuthorizationRegistry
from redteam.executor.executor import Executor
from redteam.executor.http_sender import ResponseRecord
from redteam.regression import replay
from redteam.store.store import Store

# The common filtered queries the observability layer and regression harness run, each paired with
# the index that must serve it (migration 0001 / 0002). EXPLAIN QUERY PLAN must show an index search.
_INDEXED_QUERIES = [
    "SELECT * FROM attempts WHERE target_sha = 'x'",            # ix_attempts_target_sha (resilience-by-SHA)
    "SELECT * FROM attempts WHERE spec_id = 'x'",               # ix_attempts_spec
    "SELECT * FROM verdicts WHERE attempt_id = 'x'",            # ix_verdicts_attempt
    "SELECT * FROM findings WHERE status = 'new'",              # ix_findings_status
    "SELECT * FROM findings WHERE severity_score > 7.0",        # ix_findings_severity
    "SELECT * FROM findings WHERE primary_category = 'x'",      # ix_findings_category
    "SELECT * FROM regression_cases WHERE finding_id = 'x'",    # ix_regression_finding
    "SELECT * FROM evidence WHERE attempt_id = 'x'",            # ix_evidence_attempt
]


def test_common_queries_are_index_backed(tmp_path: Path) -> None:
    store = Store.open(tmp_path / "s.db")
    for sql in _INDEXED_QUERIES:
        plan = " ".join(str(r[-1]) for r in store.conn.execute("EXPLAIN QUERY PLAN " + sql))
        assert "USING INDEX" in plan.upper() or "USING COVERING INDEX" in plan.upper(), \
            f"query is not index-backed (full scan): {sql}\nplan: {plan}"
    store.close()


def _registry(tmp_path: Path) -> AuthorizationRegistry:
    p = tmp_path / "auth.yaml"
    p.write_text("targets:\n  - id: good\n    origin: https://good.example\n    proof: test fixture\n    enabled: true\n", encoding="utf-8")
    return AuthorizationRegistry.load(p)


def test_full_regression_replay_is_bounded(tmp_path: Path) -> None:
    # Freeze a batch of mint findings, then time a full replay against a fast stub executor. The
    # ceiling is generous (store/dispatch overhead only; no real network) and only catches a blow-up.
    from redteam.authz_probe import mint_probe, run_probe

    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    target = reg.by_id("good")
    issues_token = lambda u, **k: ResponseRecord(200, '{"demo_token":"x","patient_uuid":"p"}', 1.0)  # noqa: E731
    ex = Executor(reg, issues_token)
    for i in range(12):
        run_probe(mint_probe(ex, Judge(), target, f"fixture-patient-{i:03d}"), store, reg)
    assert store.count("regression_cases") >= 1

    t0 = time.perf_counter()
    replay(store, reg, ex, Judge(), target_sha="slo-build")
    elapsed = time.perf_counter() - t0
    assert elapsed < 5.0, f"full regression replay took {elapsed:.2f}s (> 5s SLO) — investigate"
    store.close()
