"""The discovery tier — open-ended candidate discovery over captured evidence.

The judge is independent (non-Qwen) and only ever proposes CANDIDATES; a candidate is never a
finding, so nothing here writes to `findings`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from redteam.agents.judge.discovery import DiscoveryJudge, DiscoveryResult
from redteam.discovery import list_candidates, run_discovery
from redteam.store.store import Store


# --- independence gate --------------------------------------------------------------------

def test_available_requires_a_configured_non_qwen_model() -> None:
    assert DiscoveryJudge(base_url="u", api_key="k", model="deepseek-v4-pro").available is True
    assert DiscoveryJudge(base_url="u", api_key="k", model="qwen3.8-max").available is False  # attacker family
    assert DiscoveryJudge(base_url=None, api_key="k", model="deepseek-v4-pro").available is False


def test_explicit_same_family_model_is_honored_for_discovery() -> None:
    # candidates are leads, not verdicts, so an operator's explicit qwen choice is allowed
    assert DiscoveryJudge(base_url="u", api_key="k", model="qwen3.8-max", allow_same_family=True).available is True


def test_review_unavailable_is_never_a_candidate() -> None:
    r = DiscoveryJudge().review("req", "resp")
    assert r.suspected is False and r.error is not None


# --- the pass over evidence (injected fake judge; no network) -----------------------------

@dataclass
class _FakeJudge:
    """Flags responses containing the word 'LEAK'; everything else is clean."""
    def review(self, request_summary: str, response_text: str) -> DiscoveryResult:
        if "LEAK" in response_text:
            return DiscoveryResult(True, vuln_class="data-leak", why="response contains LEAK",
                                   severity="high", confidence=0.9)
        if "MAYBE" in response_text:
            return DiscoveryResult(True, vuln_class="weak", why="low conf", severity="low", confidence=0.2)
        return DiscoveryResult(False, confidence=0.0)


def _seed_attempt(store: Store, attempt_id: str, sha: str, response: str) -> None:
    store.insert("attempts", {"attempt_id": attempt_id, "target_id": "t", "target_sha": sha,
                              "started_at": "2026-09-30T00:00:00+00:00"})
    store.insert("evidence", {"evidence_id": "ev-" + attempt_id, "attempt_id": attempt_id,
                              "exchanges": json.dumps([{"ordinal": 1, "route": "/v1/x", "method": "POST",
                                                        "request": {"message": "q"}, "status_code": 200,
                                                        "response": response}]),
                              "created_at": "2026-09-30T00:00:00+00:00"})


def test_pass_logs_high_confidence_candidates_only(tmp_path: Path) -> None:
    store = Store.open(tmp_path / "s.db")
    _seed_attempt(store, "att-1", "sha1", '{"answer": "here is patient LEAK data"}')
    _seed_attempt(store, "att-2", "sha1", '{"answer": "all fine"}')
    _seed_attempt(store, "att-3", "sha1", '{"answer": "MAYBE something"}')  # below min_confidence
    s = run_discovery(store, _FakeJudge(), target_sha="sha1", limit=10, min_confidence=0.5)
    assert s.reviewed == 3 and len(s.candidates) == 1
    assert s.candidates[0]["vuln_class"] == "data-leak"
    # candidate persisted; NOT a finding
    assert store.count("discovery_candidates") == 1 and store.count("findings") == 0
    assert list_candidates(store)[0]["confidence"] == 0.9
    # the pass is audited
    act = store.conn.execute("SELECT reason FROM agent_actions WHERE action='discovery_pass'").fetchone()
    assert "1 candidate" in act["reason"]
    store.close()


def test_errors_do_not_create_candidates(tmp_path: Path) -> None:
    store = Store.open(tmp_path / "s.db")
    _seed_attempt(store, "att-1", "sha1", "resp")

    class _Erroring:
        def review(self, *_):
            return DiscoveryResult(False, error="boom")

    s = run_discovery(store, _Erroring(), target_sha="sha1")
    assert s.reviewed == 1 and s.errors == 1 and len(s.candidates) == 0
    assert store.count("discovery_candidates") == 0
    store.close()
