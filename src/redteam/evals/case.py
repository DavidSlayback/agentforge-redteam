"""The seed-case format: the authored eval unit the runner compiles into live requests.

The *content* of a case (turn bodies, markers, expected behavior) is authored separately
(see memory `claude-safety-blocks-w3`); this module defines only the container and its
validation. Every case names an OWASP category so the eval dataset maps to the taxonomy
(E1). `oracle` declares which deterministic checks apply and with what parameters.
"""

from __future__ import annotations

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


class AuthContext(BaseModel):
    """Which synthetic patient the attempt runs as. When set, the runner mints a token and
    injects it into each turn body so the request is authorized and reaches the AI."""

    patient_uuid: str
    clinician_uuid: str = "fixture-physician-001"


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
