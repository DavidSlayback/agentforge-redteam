"""The campaign loop: generate -> execute -> judge -> mutate on non-success (S5).

For each brief the Red Team generates a case, the runner executes and judges it, and a
case that did not succeed is mutated into one variant and re-run (bounded by
`max_mutations`). Every model interaction is logged to the cost ledger by call count. This
is the smallest loop that satisfies "mutate a partially-successful attack to probe for
bypasses" — the Orchestrator (S6) later chooses the briefs and the budget.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone

from redteam.agents.judge.judge import Judge, VerdictOutcome
from redteam.agents.redteam.agent import RedTeamAgent
from redteam.agents.redteam.model import ModelClient
from redteam.executor.authorization import AuthorizationRegistry
from redteam.executor.executor import Executor
from redteam.memory import history_brief
from redteam.runner import RunResult, run_case

# Outcomes worth spending a mutation on: the attack did not clearly succeed, but the
# target was reached (so a variant might get through). INCONCLUSIVE is not mutated —
# it means we could not tell, which is a wiring problem, not a bypass opportunity.
_MUTATE_ON = frozenset({VerdictOutcome.FAIL, VerdictOutcome.PARTIAL})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _log_calls(store, campaign_id: str, kind: str, calls: int) -> None:
    store.insert("cost_ledger", {"ts": _now(), "campaign_id": campaign_id, "kind": kind, "calls": calls})


@dataclass
class CampaignSummary:
    campaign_id: str
    generated: int = 0
    variants: int = 0
    outcomes: Counter = field(default_factory=Counter)
    results: list[RunResult] = field(default_factory=list)


def run_campaign(
    briefs: list[dict],
    *,
    registry: AuthorizationRegistry,
    executor: Executor,
    judge: Judge,
    store,
    agent: RedTeamAgent,
    model: ModelClient,
    campaign_id: str = "adhoc",
    max_mutations: int = 1,
) -> CampaignSummary:
    summary = CampaignSummary(campaign_id=campaign_id)
    for brief in briefs:
        # Read what has already been tried here so the Red Team varies, not repeats.
        history = history_brief(store, brief["target_id"], brief["category"])
        case = agent.generate(brief, model, history=history)
        _log_calls(store, campaign_id, "generation", 1)
        result = run_case(case, registry, executor, judge, store)
        summary.generated += 1
        summary.outcomes[str(result.verdict.outcome)] += 1
        summary.results.append(result)

        parent, last, muts = case, result, 0
        while last.verdict.outcome in _MUTATE_ON and muts < max_mutations:
            variant = agent.mutate(parent, model)
            _log_calls(store, campaign_id, "mutation", 1)
            last = run_case(variant, registry, executor, judge, store)
            summary.variants += 1
            summary.outcomes[str(last.verdict.outcome)] += 1
            summary.results.append(last)
            parent, muts = variant, muts + 1
    return summary
