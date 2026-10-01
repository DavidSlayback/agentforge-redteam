"""The seed-case format: the authored eval unit the runner compiles into live requests.

The *content* of a case (turn bodies, markers, expected behavior) is authored separately
(see memory `claude-safety-blocks-w3`); this module defines only the container and its
validation. Every case names an OWASP category so the eval dataset maps to the taxonomy
(E1). `oracle` declares which deterministic checks apply and with what parameters.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class Turn(BaseModel):
    ordinal: int
    method: str = "POST"
    route: str
    body: dict | None = None


class OracleConfig(BaseModel):
    marker: str | None = None
    foreign_canaries: list[str] = Field(default_factory=list)
    latency_budget_ms: float | None = None
    # Authorization probes: the request should have been denied (missing/forged/mismatched
    # credentials). Persisted in the frozen case so a regression replay judges it identically.
    expect_rejected: bool = False


class AuthContext(BaseModel):
    """Which synthetic patient the attempt runs as. When set, the runner mints a token and
    injects it into each turn body so the request is authorized and reaches the AI."""

    patient_uuid: str
    clinician_uuid: str = "fixture-physician-001"


class CaseResult(BaseModel):
    """The recorded outcome of a committed seed case (PRD Stage 3 fields). `observed` is from the
    target's side: `pass` = the expected safe behavior held, `fail` = the attack succeeded,
    `partial` = some but not all of the safe behavior held, `not_run` = no live evidence yet.
    The platform's own verdicts are attack-side (a Judge FAIL is an observed `pass`)."""

    observed: Literal["pass", "fail", "partial", "not_run"]
    observed_detail: str
    severity: Literal["critical", "high", "medium", "low", "info"]   # impact if the attack succeeds
    exploitability: str      # how easy to exploit on the live target, and why
    target_sha: str | None = None
    run_date: str | None = None
    evidence: str | None = None    # finding id / attempt counts / where the proof lives


class SeedCase(BaseModel):
    case_id: str
    category: str            # human-readable category (e.g. "prompt-injection")
    subcategory: str | None = None
    owasp: list[str]         # OWASP tags, e.g. ["LLM01", "A01"]
    target_id: str           # must resolve in the authorization registry
    turns: list[Turn]
    oracle: OracleConfig = Field(default_factory=OracleConfig)
    expected_safe: str       # the safe behavior, in words
    regression: bool = False
    auth: AuthContext | None = None   # synthetic patient to run as (token is minted at run time)
    parent_id: str | None = None   # set on a Red Team variant: the case it was derived from
    mutation_op: str | None = None
    # For closure-based deterministic probes (mint, rate-limit) whose execution + oracle are not
    # expressible in `turns`/`oracle` alone: names the builder so a frozen finding replays through
    # the SAME probe instead of a generic path (which would fake a green). See role-review T1.6.
    probe_kind: str | None = None
    # Set on committed eval cases only; generated variants leave these None. Required for committed
    # files by `loader.validate_committed_case`, not by this model (variants never carry them).
    result: CaseResult | None = None
    # What the case defends: a trust `boundary`, an `invariant` the target must preserve, or a
    # `regression` risk (a fixed exploit that must stay fixed).
    risk_class: Literal["boundary", "invariant", "regression"] | None = None
