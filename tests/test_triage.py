"""Discovery-candidate triage: dispositions are recorded durably, by id or by vuln_class."""

from __future__ import annotations

from pathlib import Path

import pytest

from redteam.discovery import list_candidates, triage_candidates
from redteam.store.store import Store


def _seed(store: Store) -> None:
    for cid, vc in [("cand-1", "grounding"), ("cand-2", "grounding"), ("cand-3", "mint")]:
        store.insert("discovery_candidates", {
            "candidate_id": cid, "target_sha": "s", "vuln_class": vc,
            "severity": "medium", "confidence": 0.9, "why": "x", "route": "/r",
            "status": "new", "created_at": "2026-09-30"})


def test_triage_by_class_sets_all(tmp_path: Path) -> None:
    store = Store.open(tmp_path / "s.db"); _seed(store)
    n = triage_candidates(store, "dismissed", vuln_class="grounding", note="known: F-990")
    assert n == 2
    assert {c["candidate_id"] for c in list_candidates(store, status="new")} == {"cand-3"}
    store.close()


def test_triage_by_id(tmp_path: Path) -> None:
    store = Store.open(tmp_path / "s.db"); _seed(store)
    assert triage_candidates(store, "confirmed", candidate_id="cand-3") == 1
    assert list_candidates(store, status="confirmed")[0]["candidate_id"] == "cand-3"
    store.close()


def test_triage_wont_demote_promoted(tmp_path: Path) -> None:
    store = Store.open(tmp_path / "s.db"); _seed(store)
    triage_candidates(store, "promoted", candidate_id="cand-1")
    # a later bulk dismiss must not clobber a promoted candidate
    triage_candidates(store, "dismissed", vuln_class="grounding")
    assert list_candidates(store, status="promoted")[0]["candidate_id"] == "cand-1"
    store.close()


def test_triage_validates_args(tmp_path: Path) -> None:
    store = Store.open(tmp_path / "s.db")
    with pytest.raises(ValueError):
        triage_candidates(store, "bogus", candidate_id="x")
    with pytest.raises(ValueError):
        triage_candidates(store, "dismissed")
    store.close()


# --- atomic persistence: a disposition and its audit action are one unit (issue #1) ----------

import sqlite3  # noqa: E402

class _FaultyStore(Store):
    """A real store that raises on its Nth write, the way a lock timeout or a crash would."""

    fail_on: int | None = None
    writes = 0

    def _tick(self) -> None:
        self.writes += 1
        if self.writes == self.fail_on:
            raise sqlite3.OperationalError(f"injected fault at write {self.writes}")

    def insert(self, table, row):
        self._tick()
        return super().insert(table, row)

    def execute(self, sql, params=()):
        self._tick()
        return super().execute(sql, params)

def test_a_fault_while_triaging_leaves_statuses_and_actions_unchanged(tmp_path: Path) -> None:
    total = 2   # the status update and the candidate_triage action
    for n in range(1, total + 1):
        db = tmp_path / f"fault-{n}.db"
        seed = Store.open(db)
        _seed(seed)
        seed.close()

        store = _FaultyStore.open(db)
        store.fail_on = n
        with pytest.raises(sqlite3.OperationalError, match="injected fault"):
            triage_candidates(store, "dismissed", vuln_class="grounding", note="known")
        assert store.writes == n
        store.close()

        after = Store.open(db)
        assert {c["candidate_id"] for c in list_candidates(after, status="new")} == {"cand-1", "cand-2", "cand-3"}, \
            f"fault at write {n}/{total} changed a status"
        assert after.count("agent_actions") == 0, f"fault at write {n}/{total} left the action"
        after.close()