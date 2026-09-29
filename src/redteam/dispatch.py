"""One place that maps a case's category to the execution path that can run it.

Different attack modalities need different plumbing: an indirect injection is an upload+scan
flow, an authorization probe deliberately mismatches credentials and target, and everything
else is a direct authenticated turn. Both the live campaign *and* regression replay must make
the same choice — otherwise a frozen finding replays through the wrong path and reads as
"fixed" when it was never actually re-tested. Centralizing that choice here is what keeps
replay faithful (see the 2026-09-29 self-audit in docs/PLAN.md).
"""

from __future__ import annotations

from redteam.authz_probe import reconstruct_probe, run_authz_case, run_probe
from redteam.document_attack import run_document_attack
from redteam.errors import AuthorizationDenied
from redteam.routing import execution_kind
from redteam.runner import RunResult, run_case


def dispatch(case, registry, executor, judge, store, minter, target_sha: str | None = None) -> RunResult:
    """Route a case to the execution path its category requires (per redteam.routing)."""
    # A closure-based probe (mint / rate-limit) can't be reproduced from turns/oracle alone, so a
    # frozen one is rebuilt from its probe_kind and run through the SAME probe — never a generic
    # path that would fake a regression green (role-review T1.6).
    if case.probe_kind:
        target = registry.by_id(case.target_id)
        if target is None:
            raise AuthorizationDenied(case.target_id)
        return run_probe(reconstruct_probe(case, executor, judge, target, minter), store, registry, target_sha=target_sha)
    kind = execution_kind(case.category)
    if kind == "authz":
        return run_authz_case(case, registry, executor, judge, store, minter=minter, target_sha=target_sha)
    if kind == "document":
        return run_document_attack(case, registry, executor, judge, store, minter, target_sha=target_sha)
    return run_case(case, registry, executor, judge, store, minter=minter, target_sha=target_sha)
