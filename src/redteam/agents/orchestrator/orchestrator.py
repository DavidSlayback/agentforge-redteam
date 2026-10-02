"""The Orchestrator — reads state, selects the next campaign, halts on budget/no-signal.

The top-level loop: build candidates from the store, select one, run that campaign through
the Red Team + Executor + Judge, and record the decision (its score inputs, choice, and
rationale) as an ordered agent action. It owns the budget governor; the selector chooses
among candidates but cannot touch the hard limits.
"""

from __future__ import annotations

import json
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone

from redteam.agents.judge.judge import Judge
from redteam.agents.orchestrator.budget import Budget, CallBudget, Governor
from redteam.agents.orchestrator.candidates import build_candidates
from redteam.agents.orchestrator.selector import DeterministicSelector, Selector
from redteam.agents.redteam.agent import RedTeamAgent
from redteam.agents.redteam.model import ModelClient
from redteam.campaign import run_campaign
from redteam.executor.authorization import AuthorizationRegistry
from redteam.executor.executor import Executor
from redteam.store.store import Store

# After this many untested outcomes (skip / provider block / error / unreachable) in one run, a
# brief is retired for the rest of the run so it cannot keep winning the top slot (decision 3).
_EXCLUDE_AFTER_UNTESTED = 2
# Brief outcomes that mean "no test happened" (penalised within the run and counted toward
# retirement). `tested` is signal; `budget_halted` just stops the run and is neither.
_UNTESTED_OUTCOMES = frozenset({"skipped", "provider_blocked", "errored", "unreachable"})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class OrchestratorRun:
    campaigns: int = 0
    tested: int = 0
    findings_opened: int = 0
    model_calls: int = 0
    halt_reason: str = ""
    decisions: list[dict] = field(default_factory=list)
    run_id: str = ""
    campaign_ids: list[str] = field(default_factory=list)


@dataclass
class Orchestrator:
    registry: AuthorizationRegistry
    executor: Executor
    judge: Judge
    store: Store
    agent: RedTeamAgent
    model: ModelClient
    selector: Selector = field(default_factory=DeterministicSelector)
    minter: object | None = None

    def _record(self, action: str, refs: dict, reason: str, campaign_id: str | None = None) -> None:
        self.store.record_action("orchestrator", action, refs, reason, campaign_id=campaign_id)

    def _campaign_findings(self, campaign_id: str) -> int:
        """New findings this campaign produced, by its campaign id (the 'finding' audit action
        the runner stamps on promotion) rather than a global findings-count delta that two
        overlapping runs would mis-attribute."""
        r = self.store.conn.execute(
            "SELECT COUNT(*) AS c FROM agent_actions WHERE action = 'finding' AND campaign_id = ?",
            (campaign_id,)).fetchone()
        return int(r["c"])

    def _run_findings(self, campaign_ids: list[str]) -> int:
        if not campaign_ids:
            return 0
        placeholders = ",".join("?" * len(campaign_ids))
        r = self.store.conn.execute(
            f"SELECT COUNT(*) AS c FROM agent_actions WHERE action = 'finding' "
            f"AND campaign_id IN ({placeholders})", campaign_ids).fetchone()
        return int(r["c"])

    def _run_calls(self, campaign_ids: list[str]) -> int:
        if not campaign_ids:
            return 0
        placeholders = ",".join("?" * len(campaign_ids))
        r = self.store.conn.execute(
            f"SELECT COALESCE(SUM(calls), 0) AS c FROM cost_ledger "
            f"WHERE campaign_id IN ({placeholders})", campaign_ids).fetchone()
        return int(r["c"])

    def _begin_campaign(self, campaign_id: str, brief: dict, budget: Budget, meta: dict,
                        target_sha: str | None) -> None:
        """Write the Campaign row (status running) before the campaign runs, so the attempt
        specs it produces satisfy the campaigns foreign key. Filled to the v1 Campaign contract;
        the outcome is stamped on when the campaign finishes (GitLab #4)."""
        with self.store.transaction():
            self.store.insert("campaigns", {
                "campaign_id": campaign_id,
                "target_id": brief["target_id"],
                "target_sha": target_sha,
                "surface": brief.get("route"),
                "categories": json.dumps([brief["category"]]),
                "budget": json.dumps({"max_campaigns": budget.max_campaigns,
                                      "max_model_calls": budget.max_model_calls,
                                      "max_no_signal": budget.max_no_signal}),
                "priority_inputs": json.dumps(meta.get("inputs")),
                "selector": json.dumps(meta.get("selector")),
                "status": "running",
                "created_at": _now(),
            })

    def _finish_campaign(self, campaign_id: str, outcome: str) -> None:
        """Stamp the scheduled brief's outcome (tested | skipped | provider_blocked | errored) and
        mark the Campaign done. The outcome is an added property on the v1 contract."""
        with self.store.transaction():
            self.store.execute("UPDATE campaigns SET outcome = ?, status = 'done' WHERE campaign_id = ?",
                              (outcome, campaign_id))

    def run(
        self,
        *,
        target_id: str,
        surfaces: list[str],
        categories: list[tuple[str, list[str]]],
        budget: Budget,
        patient_uuid: str | None = None,
        route_fields: dict[str, str] | None = None,
        canaries: list[str] | None = None,
        target_sha: str | None = None,
        max_mutations: int = 1,
    ) -> OrchestratorRun:
        gov = Governor(budget)
        run = OrchestratorRun(run_id=uuid.uuid4().hex[:8])
        call_budget = CallBudget(budget.max_model_calls)   # spans the run; caps every metered call
        seq = 0
        excluded: set[tuple[str, str]] = set()   # briefs retired this run after repeated untested
        untested_counts: Counter = Counter()     # per (category, route), THIS run only
        offered_any = False

        while not gov.should_halt() and call_budget.has_room:
            candidates = build_candidates(self.store, target_id, surfaces, categories, patient_uuid,
                                          route_fields, excluded=excluded, canaries=canaries,
                                          untested_in_run=dict(untested_counts))
            if not candidates:
                # No runnable brief at all is a configuration problem ("no candidates"); losing the
                # last one to repeated untested outcomes mid-run is a distinct, recorded halt.
                run.halt_reason = "nothing runnable" if offered_any else "no candidates"
                break
            offered_any = True
            chosen, meta = self.selector.select(candidates)
            seq += 1
            campaign_id = f"orch-{run.run_id}-{seq}"   # unique per run+brief; cost rows attributable
            run.campaign_ids.append(campaign_id)
            self._record(
                "select",
                {"brief": chosen.brief, "score": chosen.score, "inputs": chosen.inputs},
                f"score={chosen.score:.3f} {chosen.inputs} {meta}",
                campaign_id=campaign_id,
            )
            self._begin_campaign(campaign_id, chosen.brief, budget,
                                 {"inputs": chosen.inputs, "selector": meta}, target_sha)

            summary = run_campaign(
                [chosen.brief], registry=self.registry, executor=self.executor, judge=self.judge,
                store=self.store, agent=self.agent, model=self.model, minter=self.minter,
                campaign_id=campaign_id, max_mutations=max_mutations, canaries=canaries,
                target_sha=target_sha, call_budget=call_budget,
            )
            outcome = summary.brief_outcome()
            self._finish_campaign(campaign_id, outcome)
            if outcome == "tested":
                run.tested += 1
            elif outcome in _UNTESTED_OUTCOMES:
                pair = (chosen.brief["category"], chosen.brief["route"])
                untested_counts[pair] += 1
                if untested_counts[pair] >= _EXCLUDE_AFTER_UNTESTED and pair not in excluded:
                    excluded.add(pair)
                    self._record("exclude_brief", {"brief": chosen.brief},
                                 f"retired for this run after {untested_counts[pair]} untested outcomes "
                                 f"(last: {outcome})", campaign_id=campaign_id)
            # outcome == "budget_halted": no test, but not the brief's fault — neither penalised
            # nor retired; the run stops below.
            # Signal is attributed to THIS campaign's id, not a global table delta, so a finding
            # from an overlapping run is never miscounted here (commit 9).
            produced = self._campaign_findings(campaign_id) > 0
            gov.record(outcome=outcome, produced_finding=produced)
            run.decisions.append({"brief": chosen.brief, "outcome": outcome,
                                  "outcomes": dict(summary.outcomes), "new_finding": produced})
            if summary.budget_halted:
                run.halt_reason = f"model-call budget reached ({call_budget.used}/{call_budget.max_calls})"
                break

        run.campaigns = gov.campaigns
        run.findings_opened = self._run_findings(run.campaign_ids)
        run.model_calls = self._run_calls(run.campaign_ids)
        if not run.halt_reason and not call_budget.has_room:
            # The cap was reached exactly between campaigns (no mid-brief halt), so the loop guard
            # stopped us before starting a doomed campaign — report it as the model-call budget.
            run.halt_reason = f"model-call budget reached ({call_budget.used}/{call_budget.max_calls})"
        run.halt_reason = run.halt_reason or gov.halt_reason() or "unknown"
        self._record(
            "halt",
            {"campaigns": run.campaigns, "tested": run.tested, "findings_opened": run.findings_opened,
             "model_calls": run.model_calls},
            run.halt_reason,
        )
        return run
