"""The regression harness — confirmed exploits become frozen, replayable cases.

`freeze` stores a confirmed Finding's full case definition. `replay` re-runs every frozen
case against a target build and classifies each: a case that SUCCEEDS again is a
**reappearance** (the vulnerability is back — a regression), a FAIL means the fix holds, and
an INCONCLUSIVE (degraded retrieval, provider block, missing evidence) is never counted as a
pass. A test that "passes" only because behavior shifted is worse than none, so the same
oracle must re-fire on the same seed for a reappearance to be called.
"""

from __future__ import annotations

import json
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


# Probe kinds that deliberately spend the mint's per-client rate-limit window (the rate-limit
# and DoS probes prove the F-6ee control by hammering the mint). Replayed before a
# mint-dependent probe, they starve its token mint, so that sibling is scored INCONCLUSIVE —
# a false "could not verify" on a fix that actually holds. They must replay LAST.
_MINT_EXHAUSTING_KINDS = frozenset({"rate_limit", "dos"})


def _mint_exhausting(case_json: str | None) -> bool:
    """True if the frozen case is a mint-rate-limit-exhausting probe (replay it after the
    mint-dependent probes so it cannot starve their token mint). Unparseable/absent -> False."""
    try:
        return bool(case_json) and json.loads(case_json).get("probe_kind") in _MINT_EXHAUSTING_KINDS
    except (ValueError, TypeError):
        return False


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
    # Transitions vs each case's previous recorded replay (P5). A regression that only *stays*
    # open is already in `reappeared`; these two track what CHANGED on this build.
    newly_regressed: list[dict] = field(default_factory=list)  # {case_id, category, prior_sha}: held -> reappeared
    newly_fixed: list[dict] = field(default_factory=list)      # {case_id, category, prior_sha}: reappeared -> held

    @property
    def ok(self) -> bool:
        # Green only when every frozen case actually HELD. A reappearance is a regression; an
        # INCONCLUSIVE or unreplayable frozen finding means a known (often critical) vuln could
        # not be verified as fixed — that must not read as green (role-review T1.6).
        return not (self.reappeared or self.inconclusive or self.unreplayable)

    @property
    def regressed_categories(self) -> set[str]:
        return {d["category"] for d in self.newly_regressed}

    @property
    def fixed_categories(self) -> set[str]:
        return {d["category"] for d in self.newly_fixed}

    @property
    def cross_category_regression(self) -> bool:
        """A fix landed for one OWASP category while a finding in a DIFFERENT category reopened on
        the same build — the PRD's "fixing one category regresses another". Distinct from a plain
        reappearance (which `ok` already fails on): this flags the causal, cross-cutting case a
        reviewer must look at, because the change that fixed X is the prime suspect for breaking Y."""
        return bool(self.fixed_categories) and bool(self.regressed_categories - self.fixed_categories)


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
    rows = store.conn.execute(
        "SELECT case_id, case_json, last_result, last_sha FROM regression_cases"
    ).fetchall()
    # Stable sort: mint-exhausting probes (rate-limit/DoS) replay last so they do not starve
    # the token mint of mint-dependent siblings and score them a false INCONCLUSIVE.
    rows = sorted(rows, key=lambda r: _mint_exhausting(r["case_json"]))
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
        # The replay's attempt and this case's last_result are one unit: a fault leaves neither, so
        # the case's recorded result never refers to an attempt the store does not hold. (BEGIN is
        # deferred and the execution path reads nothing, so no lock is held during target I/O —
        # pinned by test_a_replay_unit_touches_the_store_only_from_finalize_on.)
        with store.transaction():
            result = dispatch(replay_case, registry, executor, judge, store, minter, target_sha=target_sha)
            store.execute(
                "UPDATE regression_cases SET last_result = ?, last_sha = ? WHERE case_id = ?",
                (str(result.verdict.outcome), target_sha, row["case_id"]),
            )
        outcome = result.verdict.outcome
        prior = row["last_result"]   # the previous replay's verdict for this same frozen case
        if outcome is VerdictOutcome.SUCCESS:
            report.reappeared.append({"case_id": row["case_id"], "category": case.category})
            if prior is not None and prior.endswith("FAIL"):
                # held on the previous build, open on this one — a genuine regression this deploy
                report.newly_regressed.append(
                    {"case_id": row["case_id"], "category": case.category, "prior_sha": row["last_sha"]})
        elif outcome is VerdictOutcome.FAIL:
            report.held.append(row["case_id"])          # only a clean FAIL is "the fix holds"
            if prior is not None and prior.endswith("SUCCESS"):
                report.newly_fixed.append(
                    {"case_id": row["case_id"], "category": case.category, "prior_sha": row["last_sha"]})
        else:
            report.inconclusive.append(row["case_id"])  # PARTIAL / INCONCLUSIVE -> never a pass
    return report
