"""The discovery pass — sweep captured evidence with the open-ended DiscoveryJudge and log
candidates. Decoupled from the campaign so it fits the scheduled job: run it after a campaign or
on a new build to surface what the deterministic oracles missed.

A candidate is a *lead*, never a finding. Confirming a candidate and hardening it into a
deterministic oracle+probe is a human step (see docs/PLAN.md) — that is what keeps verdicts
trustworthy while still letting a less-safeguarded LLM find the unknown-unknowns.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from redteam.agents.judge.discovery import DiscoveryJudge
from redteam.store.store import Store


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class DiscoverySummary:
    reviewed: int = 0
    candidates: list[dict] = field(default_factory=list)
    skipped_no_evidence: int = 0
    errors: int = 0


def _exchange_summary(exchanges: list[dict]) -> tuple[str, str, str]:
    """Compact (request_summary, response_text, route) from an evidence row's exchanges."""
    if not exchanges:
        return "", "", ""
    ex = exchanges[-1]   # the decisive exchange
    req = ex.get("request")
    req_s = json.dumps(req) if not isinstance(req, str) else req
    return (f"{ex.get('method')} {ex.get('route')} {req_s}", str(ex.get("response") or ""),
            str(ex.get("route") or ""))


def run_discovery(store: Store, judge: DiscoveryJudge, *, target_sha: str | None = None,
                  limit: int = 25, min_confidence: float = 0.5) -> DiscoverySummary:
    """Review the most recent attempts' evidence and log candidates above a confidence floor."""
    summary = DiscoverySummary()
    where = "WHERE a.target_sha = ?" if target_sha else ""
    params: tuple = (target_sha,) if target_sha else ()
    evidence = store.conn.execute(
        f"SELECT a.attempt_id, a.target_sha, e.exchanges FROM attempts a "
        f"JOIN evidence e ON e.attempt_id = a.attempt_id {where} "
        f"ORDER BY a.started_at DESC LIMIT ?", (*params, limit)).fetchall()
    pending: list[dict] = []   # candidate rows, written in one unit after the review loop
    for row in evidence:
        try:
            exchanges = json.loads(row["exchanges"]) if row["exchanges"] else []
        except ValueError:
            summary.skipped_no_evidence += 1
            continue
        req_s, resp, route = _exchange_summary(exchanges)
        if not resp:
            summary.skipped_no_evidence += 1
            continue
        summary.reviewed += 1
        result = judge.review(req_s, resp)
        if result.error is not None:
            summary.errors += 1
            continue
        if result.suspected and result.confidence >= min_confidence:
            cid = "cand-" + uuid.uuid4().hex[:10]
            pending.append({
                "candidate_id": cid, "attempt_id": row["attempt_id"], "target_sha": row["target_sha"],
                "vuln_class": result.vuln_class, "severity": result.severity,
                "confidence": result.confidence, "why": result.why, "route": route,
                "status": "new", "created_at": _now(),
            })
            summary.candidates.append({"candidate_id": cid, "vuln_class": result.vuln_class,
                                       "severity": result.severity, "confidence": result.confidence,
                                       "why": result.why, "route": route})
    # The pass is one unit, written after the model calls so no write lock is held during them:
    # its candidates and its audit action land together or not at all.
    with store.transaction():
        for candidate in pending:
            store.insert("discovery_candidates", candidate)
        store.insert("agent_actions", {
            "ts": _now(), "agent": "discovery", "action": "discovery_pass",
            "refs": json.dumps({"sha": target_sha, "reviewed": summary.reviewed,
                                "candidates": len(summary.candidates), "errors": summary.errors}),
            "reason": (f"{len(summary.candidates)} candidate(s) from {summary.reviewed} reviewed"
                       if summary.candidates else f"no candidates from {summary.reviewed} reviewed"),
        })
    return summary


_STATUSES = ("new", "confirmed", "dismissed", "promoted")


def triage_candidates(store: Store, status: str, *, candidate_id: str | None = None,
                      vuln_class: str | None = None, note: str | None = None) -> int:
    """Set the triage status of one candidate (by id) or all candidates of a vuln_class. Returns the
    number updated. `status` ∈ new|confirmed|dismissed|promoted; a confirmed candidate is one a human
    verified and will harden into a deterministic probe, promoted means a finding already exists,
    dismissed is a false positive or a known/duplicate class."""
    if status not in _STATUSES:
        raise ValueError(f"status must be one of {_STATUSES}")
    if not (candidate_id or vuln_class):
        raise ValueError("pass candidate_id or vuln_class")
    where = "candidate_id = ?" if candidate_id else "vuln_class = ?"
    param = candidate_id or vuln_class
    note_sql = ", why = why || ' [triage: ' || ? || ']'" if note else ""
    params: tuple = (status, note, param) if note else (status, param)
    with store.transaction():   # the disposition and its audit action land together
        cur = store.execute(
            f"UPDATE discovery_candidates SET status = ?{note_sql} WHERE {where} AND status != 'promoted'",
            params)
        store.insert("agent_actions", {
            "ts": _now(), "agent": "triage", "action": "candidate_triage",
            "refs": json.dumps({"by": "id" if candidate_id else "class", "key": param, "status": status}),
            "reason": f"{cur.rowcount} candidate(s) -> {status}" + (f": {note}" if note else ""),
        })
    return cur.rowcount


def list_candidates(store: Store, status: str | None = "new") -> list[dict]:
    where = "WHERE status = ?" if status else ""
    params: tuple = (status,) if status else ()
    return [dict(r) for r in store.conn.execute(
        f"SELECT candidate_id, attempt_id, target_sha, vuln_class, severity, confidence, why, route, status "
        f"FROM discovery_candidates {where} ORDER BY confidence DESC", params).fetchall()]
