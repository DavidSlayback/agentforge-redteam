"""E9 (exploit-DB data quality) + E10 (queue-depth monitoring).

The same weakness found by many attempts must be ONE finding with many linked verdicts — never a
duplicate finding/sequence. Queue-depth reports pending work from the store's queues.
"""

from __future__ import annotations

import json
from pathlib import Path

from redteam.agents.judge.judge import Verdict, VerdictOutcome
from redteam.evals.case import SeedCase, Turn
from redteam.findings import promote
from redteam.observability import queries
from redteam.oracles.base import OracleOutcome, OracleResult
from redteam.store.store import Store


def _case() -> SeedCase:
    return SeedCase(case_id="c1", category="prompt-injection", owasp=["LLM01"], target_id="t",
                    turns=[Turn(ordinal=1, route="/v1/x", body={})], expected_safe="refuses")


def _success() -> Verdict:
    return Verdict(VerdictOutcome.SUCCESS, (OracleResult("marker", 0, OracleOutcome.VIOLATION, "echoed"),), "hit")


def test_same_weakness_dedups_to_one_finding_with_many_verdicts(tmp_path: Path) -> None:
    store = Store.open(tmp_path / "s.db")
    with store.transaction():   # promote runs inside finalize's unit in production
        fid1, new1 = promote(store, _case(), _success(), "ver-1")
    with store.transaction():
        fid2, new2 = promote(store, _case(), _success(), "ver-2")   # same (oracle, sink, category)
    assert new1 is True and new2 is False and fid1 == fid2
    assert store.count("findings") == 1                          # no duplicate finding/sequence
    verdict_ids = json.loads(store.conn.execute(
        "SELECT verdict_ids FROM findings WHERE finding_id = ?", (fid1,)).fetchone()["verdict_ids"])
    assert verdict_ids == ["ver-1", "ver-2"]                     # both attempts linked to the one finding
    store.close()


def test_distinct_weaknesses_are_separate_findings(tmp_path: Path) -> None:
    store = Store.open(tmp_path / "s.db")
    with store.transaction():
        promote(store, _case(), _success(), "ver-1")
    other = SeedCase(case_id="c2", category="denial-of-service", owasp=["LLM10"], target_id="t",
                     turns=[Turn(ordinal=1, route="/v1/y", body={})], expected_safe="holds")
    dos = Verdict(VerdictOutcome.SUCCESS, (OracleResult("status", 0, OracleOutcome.VIOLATION, "500"),), "5xx")
    with store.transaction():
        promote(store, other, dos, "ver-2")
    assert store.count("findings") == 2
    store.close()


def test_queue_depth_counts_pending_work(tmp_path: Path) -> None:
    store = Store.open(tmp_path / "s.db")
    with store.transaction():
        store.insert("campaigns", {"campaign_id": "cam-1", "target_id": "t", "status": "new", "created_at": "2026-09-30"})
        store.insert("campaigns", {"campaign_id": "cam-2", "target_id": "t", "status": "done", "created_at": "2026-09-30"})
        store.insert("findings", {"finding_id": "F-1", "title": "t", "primary_category": "x",
                                  "dedup_key": "k", "status": "new", "updated_at": "2026-09-30"})
        store.insert("vuln_reports", {"report_id": "R-1", "finding_id": "F-1", "status": "pending_approval",
                                      "created_at": "2026-09-30"})
        store.insert("vuln_reports", {"report_id": "R-2", "finding_id": "F-1", "status": "published",
                                      "created_at": "2026-09-30"})
    q = queries.queue_depth(store)
    assert q == {"campaigns_pending": 1, "reports_pending_approval": 1}
    store.close()
