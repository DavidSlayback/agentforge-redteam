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
from redteam.dispatch import dispatch as _dispatch
from redteam.errors import ProviderBlock
from redteam.evals.case import AuthContext
from redteam.executor.authorization import AuthorizationRegistry
from redteam.executor.executor import Executor
from redteam.memory import history_brief
from redteam.owasp import NEEDS_CANARY
from redteam.routing import is_deterministic_only
from redteam.runner import RunResult

# Outcomes worth spending a mutation on: the attack did not clearly succeed, but the target
# was reached (so a variant might get through). INCONCLUSIVE is not mutated — it means we could
# not tell, which is a wiring problem, not a bypass opportunity. PARTIAL is reserved for the
# deferred rubric tier and never produced by the deterministic Judge, so it is not listed (T2.2).
_MUTATE_ON = frozenset({VerdictOutcome.FAIL})


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
    minter=None,
    canaries: list[str] | None = None,
    target_sha: str | None = None,
) -> CampaignSummary:
    summary = CampaignSummary(campaign_id=campaign_id)
    for brief in briefs:
        try:
            # Authorization categories are model-free deterministic probes that need a
            # tampered request (expect_rejected / harness canaries) the campaign path does not
            # build. Routing one through here would exercise only StatusOracle and score a real
            # BOLA as FAIL ("defense held") — a fake pass. Refuse; they run via the `authz` command.
            if is_deterministic_only(brief["category"]):
                summary.outcomes["SKIPPED"] += 1
                store.insert("agent_actions", {
                    "ts": _now(), "agent": "campaign", "action": "skipped",
                    "refs": json.dumps({"category": brief["category"], "route": brief.get("route")}),
                    "reason": "authorization category must run via `redteam authz`, not campaign (would be a fake pass)",
                })
                continue
            # A canary-gated category with no canary cannot be scored — running it anyway
            # would let StatusOracle score a 200 as SAFE and report a defense that was never
            # tested. Skip it loudly rather than manufacture a pass.
            if brief["category"] in NEEDS_CANARY and not canaries:
                summary.outcomes["SKIPPED"] += 1
                store.insert("agent_actions", {
                    "ts": _now(), "agent": "campaign", "action": "skipped",
                    "refs": json.dumps({"category": brief["category"], "route": brief.get("route")}),
                    "reason": "no canary available for a canary-gated category; not tested (would be a fake pass)",
                })
                continue
            # Read what has already been tried here so the Red Team varies, not repeats.
            history = history_brief(store, brief["target_id"], brief["category"])
            case = agent.generate(brief, model, history=history)
            # For canary-gated categories, set the oracle's foreign canaries — the attacker
            # cannot know them, so the harness supplies them (else the verdict is INCONCLUSIVE).
            if canaries and brief["category"] in NEEDS_CANARY:
                case = case.model_copy(update={"oracle": case.oracle.model_copy(update={"foreign_canaries": list(canaries)})})
            # Run as a synthetic patient when the brief names one (so attempts reach the AI).
            if brief.get("patient_uuid"):
                case = case.model_copy(update={"auth": AuthContext(patient_uuid=brief["patient_uuid"])})
            _log_calls(store, campaign_id, "generation", 1)
            result = _dispatch(case, registry, executor, judge, store, minter, target_sha=target_sha)
            summary.generated += 1
            summary.outcomes[str(result.verdict.outcome)] += 1
            summary.results.append(result)

            parent, last, muts = case, result, 0
            while last.verdict.outcome in _MUTATE_ON and muts < max_mutations:
                variant = agent.mutate(parent, model, verdict=last.verdict)  # aim at what blocked it
                _log_calls(store, campaign_id, "mutation", 1)
                last = _dispatch(variant, registry, executor, judge, store, minter, target_sha=target_sha)
                summary.variants += 1
                summary.outcomes[str(last.verdict.outcome)] += 1
                summary.results.append(last)
                parent, muts = variant, muts + 1
        except ProviderBlock as exc:
            # The attacker model's own content filter is a distinct, typed outcome — not a
            # generic error and never evidence about the target (role-review T3.8).
            summary.outcomes["PROVIDER_BLOCK"] += 1
            store.insert("agent_actions", {
                "ts": _now(), "agent": "campaign", "action": "provider_block",
                "refs": json.dumps({"category": brief.get("category"), "route": brief.get("route")}),
                "reason": f"attacker-model provider block: {exc}"[:300],
            })
        except Exception as exc:  # one bad brief must not end an unattended campaign
            summary.outcomes["ERROR"] += 1
            store.insert("agent_actions", {
                "ts": _now(), "agent": "campaign", "action": "brief_error",
                "refs": json.dumps({"category": brief.get("category"), "route": brief.get("route")}),
                "reason": f"{type(exc).__name__}: {exc}"[:300],
            })
    return summary
