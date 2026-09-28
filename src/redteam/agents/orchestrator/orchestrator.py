"""The Orchestrator — reads state, selects the next campaign, halts on budget/no-signal.

The top-level loop: build candidates from the store, select one, run that campaign through
the Red Team + Executor + Judge, and record the decision (its score inputs, choice, and
rationale) as an ordered agent action. It owns the budget governor; the selector chooses
among candidates but cannot touch the hard limits.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

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
    findings_opened: int = 0
    halt_reason: str = ""
    decisions: list[dict] = field(default_factory=list)


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

    def _record(self, action: str, refs: dict, reason: str) -> None:
        self.store.insert("agent_actions", {
            "ts": _now(), "agent": "orchestrator", "action": action,
            "refs": json.dumps(refs), "reason": reason,
        })

    def run(
        self,
        *,
        target_id: str,
        surfaces: list[str],
        categories: list[tuple[str, list[str]]],
        budget: Budget,
        patient_uuid: str | None = None,
    ) -> OrchestratorRun:
        gov = Governor(budget)
        run = OrchestratorRun()
        findings_start = self.store.count("findings")

        while not gov.should_halt():
            candidates = build_candidates(self.store, target_id, surfaces, categories, patient_uuid)
            if not candidates:
                run.halt_reason = "no candidates"
                break
            chosen, meta = self.selector.select(candidates)
            self._record(
                "select",
                {"brief": chosen.brief, "score": chosen.score, "inputs": chosen.inputs},
                f"score={chosen.score:.3f} {chosen.inputs} {meta}",
            )

            before_findings = self.store.count("findings")
            before_spend = cost_summary(self.store)["usd"]
            summary = run_campaign(
                [chosen.brief], registry=self.registry, executor=self.executor, judge=self.judge,
                store=self.store, agent=self.agent, model=self.model, minter=self.minter,
                campaign_id=f"orch-{gov.campaigns + 1}", max_mutations=1,
            )
            produced = self.store.count("findings") > before_findings
            # Real spend from the cost ledger. usd is 0 until model pricing is wired (S9),
            # so the spend cap is live-but-inactive until then; campaigns/no-signal still bound it.
            spend_delta = cost_summary(self.store)["usd"] - before_spend
            gov.record(produced_finding=produced, spend_usd=spend_delta)
            run.decisions.append({"brief": chosen.brief, "outcomes": dict(summary.outcomes), "new_finding": produced})

        run.campaigns = gov.campaigns
        run.findings_opened = self.store.count("findings") - findings_start
        run.halt_reason = run.halt_reason or gov.halt_reason() or "unknown"
        self._record(
            "halt",
            {"campaigns": run.campaigns, "findings_opened": run.findings_opened},
            run.halt_reason,
        )
        return run
