"""`redteam` command-line surface.

Read-only / safe commands (`report`, `approve`) construct nothing live. Attack commands
(`campaign`, `regression`) build the executor, minter, and attacker model lazily, so the
safe commands run without a key or network. Approvals go through the CLI on purpose: the
dashboard stays read-only (Q15).
"""

from __future__ import annotations

import argparse
import sys

from redteam.store.store import Store

_OWASP = {
    "prompt-injection": ["LLM01"],
    "sensitive-info-disclosure": ["LLM02"],
    "improper-output-handling": ["LLM05"],
    "excessive-agency": ["LLM06"],
    "denial-of-service": ["LLM10"],
}
_DEFAULT_STORE = "var/redteam.db"

# Target-specific: which request field carries the attack payload per route (from recon).
# Routes not listed here send the model's body as-is.
_ROUTE_FIELDS = {
    "/v1/follow-up-evidence": "message",
    "/v1/scan-supervisor": "message",
    "/v1/conversations/messages": "message",
}


def _wire(target_id: str):
    """Build the live pieces for an attack command (import-heavy; done lazily)."""
    from redteam.agents.judge.judge import Judge
    from redteam.agents.redteam.agent import RedTeamAgent
    from redteam.agents.redteam.model import QwenClient
    from redteam.config import load_dotenv
    from redteam.executor.authorization import AuthorizationRegistry
    from redteam.executor.executor import Executor
    from redteam.executor.http_sender import http_sender
    from redteam.executor.token import TokenMinter

    load_dotenv()
    registry = AuthorizationRegistry.load("authorization.yaml")
    target = registry.by_id(target_id)
    if target is None:
        raise SystemExit(f"target '{target_id}' is not in authorization.yaml")
    executor = Executor(registry, http_sender)
    return registry, target, executor, TokenMinter(executor, target), Judge(), RedTeamAgent(), QwenClient.from_env()


def cmd_report(args: argparse.Namespace) -> int:
    from redteam.observability import report

    store = Store.open(args.store)
    print(report.render_markdown(store))
    store.close()
    return 0


def cmd_dashboard(args: argparse.Namespace) -> int:
    from pathlib import Path

    from redteam.observability import dashboard

    store = Store.open(args.store)
    Path(args.out).write_text(dashboard.render_html(store), encoding="utf-8")
    store.close()
    print(f"wrote {args.out}")
    return 0


def cmd_approve(args: argparse.Namespace) -> int:
    from redteam.agents.documentation.agent import DocumentationAgent

    store = Store.open(args.store)
    DocumentationAgent().approve(store, args.report_id, approver=args.approver)
    print(f"approved {args.report_id}")
    store.close()
    return 0


def cmd_regression(args: argparse.Namespace) -> int:
    from redteam.regression import replay

    registry, _target, executor, minter, judge, _agent, _model = _wire(args.target)
    store = Store.open(args.store)
    r = replay(store, registry, executor, judge, args.sha, minter=minter)
    print(f"regression @ {args.sha}: held={len(r.held)} reappeared={len(r.reappeared)} "
          f"inconclusive={len(r.inconclusive)} unreplayable={len(r.unreplayable)}")
    store.close()
    return 1 if r.reappeared else 0


def cmd_campaign(args: argparse.Namespace) -> int:
    from redteam.agents.orchestrator.budget import Budget
    from redteam.agents.orchestrator.orchestrator import Orchestrator
    from redteam.agents.orchestrator.selector import DeterministicSelector, JevSelector

    registry, _target, executor, minter, judge, agent, model = _wire(args.target)
    store = Store.open(args.store)
    categories = [(c, _OWASP.get(c, [])) for c in args.category]
    selector = JevSelector() if args.selector == "jev" else DeterministicSelector()
    orch = Orchestrator(registry=registry, executor=executor, judge=judge, store=store,
                        agent=agent, model=model, minter=minter, selector=selector)
    run = orch.run(target_id=args.target, surfaces=args.route, categories=categories,
                   budget=Budget(max_campaigns=args.max_campaigns), patient_uuid=args.patient,
                   route_fields=_ROUTE_FIELDS)
    print(f"campaign done: campaigns={run.campaigns} findings_opened={run.findings_opened} "
          f"halt={run.halt_reason!r}")
    store.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="redteam", description="AgentForge red-team platform")
    parser.add_argument("--store", default=_DEFAULT_STORE, help=f"store path (default {_DEFAULT_STORE})")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("report", help="print the observability dashboard").set_defaults(func=cmd_report)

    db = sub.add_parser("dashboard", help="write a self-contained HTML dashboard")
    db.add_argument("--out", default="dashboard.html")
    db.set_defaults(func=cmd_dashboard)

    ap = sub.add_parser("approve", help="approve a held critical/high report")
    ap.add_argument("report_id")
    ap.add_argument("--approver", default="operator")
    ap.set_defaults(func=cmd_approve)

    rg = sub.add_parser("regression", help="replay the regression suite against a build")
    rg.add_argument("--target", required=True)
    rg.add_argument("--sha", required=True)
    rg.set_defaults(func=cmd_regression)

    cp = sub.add_parser("campaign", help="run the orchestrator against the target")
    cp.add_argument("--target", required=True)
    cp.add_argument("--category", action="append", default=[], help="repeatable; e.g. prompt-injection")
    cp.add_argument("--route", action="append", default=[], help="repeatable target route")
    cp.add_argument("--patient", default=None, help="synthetic patient to run as")
    cp.add_argument("--max-campaigns", type=int, default=5, dest="max_campaigns")
    cp.add_argument("--selector", choices=["deterministic", "jev"], default="deterministic")
    cp.set_defaults(func=cmd_campaign)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
