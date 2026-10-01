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

# After this many untested outcomes (skip / provider block / error) in one run, a brief is
# retired for the rest of the run so it cannot keep winning the top slot (owner decision 3).
_EXCLUDE_AFTER_UNTESTED = 2

from redteam.agents.judge.judge import Judge
from redteam.agents.orchestrator.budget import Budget, Governor
from redteam.agents.orchestrator.candidates import build_candidates
from redteam.agents.orchestrator.selector import DeterministicSelector, Selector
from redteam.agents.redteam.agent import RedTeamAgent
from redteam.agents.redteam.model import ModelClient
from redteam.campaign import run_campaign
from redteam.executor.authorization import AuthorizationRegistry
from redteam.executor.executor import Executor
from redteam.observability.queries import cost_summary
from redteam.store.store import Store


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class OrchestratorRun:
    campaigns: int = 0
    tested: int = 0
    findings_opened: int = 0
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
    ) -> OrchestratorRun:
        gov = Governor(budget)
        run = OrchestratorRun(run_id=uuid.uuid4().hex[:8])
        findings_start = self.store.count("findings")
        seq = 0
        excluded: set[tuple[str, str]] = set()   # briefs retired this run after repeated untested
        untested_streak: Counter = Counter()

        while not gov.should_halt():
            candidates = build_candidates(self.store, target_id, surfaces, categories, patient_uuid,
                                          route_fields, excluded=excluded, canaries=canaries)
            if not candidates:
                run.halt_reason = "no candidates"
                break
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

            before_findings = self.store.count("findings")
            before_calls = cost_summary(self.store)["calls"]
            summary = run_campaign(
                [chosen.brief], registry=self.registry, executor=self.executor, judge=self.judge,
                store=self.store, agent=self.agent, model=self.model, minter=self.minter,
                campaign_id=campaign_id, max_mutations=1, canaries=canaries,
                target_sha=target_sha,
            )
            outcome = summary.brief_outcome()
            self._finish_campaign(campaign_id, outcome)
            if outcome == "tested":
                run.tested += 1
            else:
                pair = (chosen.brief["category"], chosen.brief["route"])
                untested_streak[pair] += 1
                if untested_streak[pair] >= _EXCLUDE_AFTER_UNTESTED and pair not in excluded:
                    excluded.add(pair)
                    self._record("exclude_brief", {"brief": chosen.brief},
                                 f"retired for this run after {untested_streak[pair]} untested outcomes "
                                 f"(last: {outcome})", campaign_id=campaign_id)
            produced = self.store.count("findings") > before_findings
            # Cost is real model calls from the ledger (generation + mutation + rubric).
            calls_delta = cost_summary(self.store)["calls"] - before_calls
            gov.record(produced_finding=produced, model_calls=calls_delta)
            run.decisions.append({"brief": chosen.brief, "outcome": outcome,
                                  "outcomes": dict(summary.outcomes), "new_finding": produced})

        run.campaigns = gov.campaigns
        run.findings_opened = self.store.count("findings") - findings_start
        run.halt_reason = run.halt_reason or gov.halt_reason() or "unknown"
        self._record(
            "halt",
            {"campaigns": run.campaigns, "tested": run.tested, "findings_opened": run.findings_opened},
            run.halt_reason,
        )
        return run
