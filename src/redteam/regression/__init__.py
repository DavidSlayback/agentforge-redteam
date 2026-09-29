"""The regression harness — confirmed exploits become frozen, replayable cases.

`freeze` stores a confirmed Finding's full case definition. `replay` re-runs every frozen
case against a target build and classifies each: a case that SUCCEEDS again is a
**reappearance** (the vulnerability is back — a regression), a FAIL means the fix holds, and
an INCONCLUSIVE (degraded retrieval, provider block, missing evidence) is never counted as a
pass. A test that "passes" only because behavior shifted is worse than none, so the same
oracle must re-fire on the same seed for a reappearance to be called.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from redteam.agents.judge.judge import Judge, VerdictOutcome
from redteam.evals.case import SeedCase
from redteam.executor.authorization import AuthorizationRegistry
from redteam.executor.executor import Executor
from redteam.store.store import Store


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def freeze(store: Store, finding_id: str, case: SeedCase) -> str:
    """Freeze a confirmed Finding's case as a regression case. Idempotent per finding."""
    existing = store.conn.execute(
        "SELECT case_id FROM regression_cases WHERE finding_id = ?", (finding_id,)
    ).fetchone()
    if existing is not None:
        return existing["case_id"]
    case_id = "reg-" + uuid.uuid4().hex[:10]
    store.insert("regression_cases", {
        "case_id": case_id,
        "finding_id": finding_id,
        "spec_id": case.case_id,
        "oracle_ref": case.oracle.model_dump_json(),
        "case_json": case.model_dump_json(),
        "frozen_at": _now(),
    })
    return case_id


@dataclass
class RegressionReport:
    target_sha: str
    held: list[str] = field(default_factory=list)
    reappeared: list[dict] = field(default_factory=list)   # {case_id, category} — regressions
    inconclusive: list[str] = field(default_factory=list)
    unreplayable: list[str] = field(default_factory=list)  # frozen before case_json existed

    @property
    def ok(self) -> bool:
        return not self.reappeared


def replay(
    store: Store,
    registry: AuthorizationRegistry,
    executor: Executor,
    judge: Judge,
    target_sha: str,
    minter: object | None = None,
) -> RegressionReport:
    """Re-run every frozen case against the target and classify each.

    Side effects: this is not read-only — each replay runs the case, so it writes an
    attempt+verdict (and, only if a replay surfaces a genuinely *different* weakness, a new
    finding). A reappearance of an already-known finding hits dedup and freezes nothing new.
    """
    from redteam.dispatch import dispatch  # local import avoids a runner<->regression cycle

    report = RegressionReport(target_sha=target_sha)
    rows = store.conn.execute("SELECT case_id, case_json FROM regression_cases").fetchall()
    for row in rows:
        if row["case_json"] is None:
            # A case frozen before migration 0003 cannot be replayed — surface it as a
            # coverage gap rather than silently dropping it.
            report.unreplayable.append(row["case_id"])
            continue
        case = SeedCase.model_validate_json(row["case_json"])
        # a fresh spec id per replay so it never collides with the frozen spec
        replay_case = case.model_copy(update={"case_id": f"{case.case_id}-rt{uuid.uuid4().hex[:6]}"})
        # Route by category so an authz/document finding replays through the same path that
        # produced it — not run_case, which would re-scope a BOLA probe or flatten a document
        # attack into a plain message and falsely report the fix as holding.
        result = dispatch(replay_case, registry, executor, judge, store, minter, target_sha=target_sha)
        outcome = result.verdict.outcome
        if outcome is VerdictOutcome.SUCCESS:
            report.reappeared.append({"case_id": row["case_id"], "category": case.category})
        elif outcome is VerdictOutcome.FAIL:
            report.held.append(row["case_id"])          # only a clean FAIL is "the fix holds"
        else:
            report.inconclusive.append(row["case_id"])  # PARTIAL / INCONCLUSIVE -> never a pass
        store.conn.execute(
            "UPDATE regression_cases SET last_result = ?, last_sha = ? WHERE case_id = ?",
            (str(outcome), target_sha, row["case_id"]),
        )
        store.conn.commit()
    return report
