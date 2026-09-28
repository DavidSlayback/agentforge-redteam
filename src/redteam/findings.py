"""Promote a confirmed exploit (a SUCCESS verdict) into a deduplicated Finding.

A Finding is the distinct weakness; the Attempts+Verdicts are its evidence (CONTEXT.md).
Dedup is by `(violating oracle, sink, category)` so many attempts that exploit the same
weakness collapse to one Finding (E9: no duplicate finding for the same attack sequence).
Severity here is **provisional** — a placeholder pending a CVSS v4 assessment; it exists
only to route the human approval gate, never as a final score.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone

from redteam.agents.judge.judge import Verdict
from redteam.evals.case import SeedCase
from redteam.oracles.base import OracleOutcome

# Provisional severity by category, only to gate human approval. Confirm with CVSS v4.
_PROVISIONAL = {
    "prompt-injection": ("high", 8.1),
    "sensitive-info-disclosure": ("critical", 9.1),
    "excessive-agency": ("high", 8.5),
    "improper-output-handling": ("high", 8.0),
    "denial-of-service": ("medium", 5.3),
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def dedup_key(oracle: str, sink: str, category: str) -> str:
    return f"{oracle}:{sink}:{category}"


def provisional_severity(category: str) -> tuple[str, float]:
    return _PROVISIONAL.get(category, ("medium", 5.0))


def promote(store, case: SeedCase, verdict: Verdict, verdict_id: str) -> tuple[str, bool]:
    """Create or update a Finding from a SUCCESS verdict. Returns (finding_id, is_new)."""
    violating = next(
        (r.oracle for r in verdict.oracle_results if r.outcome is OracleOutcome.VIOLATION),
        "unknown",
    )
    sink = case.turns[0].route if case.turns else "unknown"
    key = dedup_key(violating, sink, case.category)
    finding_id = "F-" + hashlib.sha1(f"{case.target_id}:{key}".encode()).hexdigest()[:10]
    level, score = provisional_severity(case.category)

    try:
        store.insert("findings", {
            "finding_id": finding_id,
            "title": f"{case.category} via {sink}",
            "taxonomy": json.dumps([{"scheme": "OWASP-LLM", "version": "2025", "id": t} for t in case.owasp]),
            "primary_category": case.category,
            "severity": json.dumps({"provisional_level": level, "note": "provisional; confirm with CVSS v4"}),
            "severity_score": score,
            "component": sink,
            "status": "new",
            "verdict_ids": json.dumps([verdict_id]),
            "dedup_key": key,
            "updated_at": _now(),
        })
        return finding_id, True
    except sqlite3.IntegrityError:
        # Same weakness already found: append this verdict to its evidence.
        row = store.conn.execute("SELECT finding_id, verdict_ids FROM findings WHERE dedup_key = ?", (key,)).fetchone()
        ids = json.loads(row["verdict_ids"] or "[]")
        if verdict_id not in ids:
            ids.append(verdict_id)
        store.conn.execute(
            "UPDATE findings SET verdict_ids = ?, updated_at = ? WHERE finding_id = ?",
            (json.dumps(ids), _now(), row["finding_id"]),
        )
        store.conn.commit()
        return row["finding_id"], False
