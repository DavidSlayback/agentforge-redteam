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
