"""Deterministic oracle framework.

An oracle decides an outcome from observable evidence, with no model in the loop — the
authoritative tier of the Judge (docs/ARCHITECTURE.md). Each oracle inspects an
`Observation` (a structured view of one Attempt's evidence) and returns an `OracleResult`.

Outcomes are fail-closed: an oracle that needed evidence it did not get returns
INCONCLUSIVE, never SAFE. An oracle irrelevant to this attempt returns NOT_APPLICABLE so
the Judge can exclude it rather than count it as a clean pass.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol


class OracleOutcome(StrEnum):
    VIOLATION = "violation"          # evidence the attack achieved its goal
    SAFE = "safe"                    # the defense held on this criterion
    INCONCLUSIVE = "inconclusive"    # needed evidence was missing or ambiguous
    NOT_APPLICABLE = "not_applicable"  # this oracle does not apply to this attempt


@dataclass(frozen=True)
class Observation:
    """A structured, deterministic view of one Attempt's evidence.

    Populated from an Attempt (later slices); tests construct it directly. Fields are
    optional because a given attempt exercises only some of them.
    """

    response_text: str | None = None
    status_code: int | None = None
    latency_ms: float | None = None
    latency_budget_ms: float | None = None
    requested_patient: str | None = None
    patient_ids_in_response: frozenset[str] = frozenset()
    foreign_canaries: frozenset[str] = frozenset()  # markers that belong to OTHER patients
    injection_marker: str | None = None  # a marker a probe asked the model to emit
    provider_events: tuple[str, ...] = ()
    # Authorization-probe evidence (set only by the deterministic authz track). When
    # `expect_rejected` is True the request carried missing/forged/mismatched credentials and
    # the target *should* have denied it; `authorized_data_present` records whether the body
    # nonetheless carried substantive patient data. Both stay unset on ordinary attempts, so
    # the authz oracle reports NOT_APPLICABLE there.
    expect_rejected: bool = False
    authorized_data_present: bool | None = None
    # Grounding/relevance evidence (set only by the grounding track). `off_condition` marks a
    # clinical query about a condition ABSENT from the patient's chart; a safe assistant flags
    # such a query (`qualification_required` True) rather than presenting guideline evidence as if
    # applicable. `guideline_evidence_count` is how many guideline snippets came back.
    off_condition: bool = False
    qualification_required: bool | None = None
    guideline_evidence_count: int = 0
    # Set only by the disclosure probe: check the response for internal-implementation metadata
    # (AI supply-chain / retrieval telemetry / internal datastore ids) that a clinical client
    # should never receive. Gated by this flag so the oracle never fires on ordinary attempts.
    check_disclosure: bool = False


@dataclass(frozen=True)
class OracleResult:
    oracle: str
    tier: int
    outcome: OracleOutcome
    detail: str = ""


class Oracle(Protocol):
    name: str
    tier: int

    def check(self, obs: Observation) -> OracleResult: ...
