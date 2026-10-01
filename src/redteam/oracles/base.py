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

from redteam.oracles.decode import DecodedValues, decoded_values, joined, normalize


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

    # The response body as the target sent it (on the attack paths, with verbatim echoes of the
    # attack payload removed).
    response_text: str | None = None
    # The body's decoded string values with their JSON paths (oracles/decode.py), verbatim, with
    # verbatim echoes removed value by value. The rubric model reads these. Left unset, it is the
    # decoding of `response_text`, so an observation built from a raw body alone (calibration
    # entries, unit tests) needs nothing more.
    decoded: DecodedValues | None = None
    # The same values in the one normalized form every matching check reads (decode.normalize),
    # with echoes removed in that form, so a re-cased echo cannot survive the strip and every
    # value is compared the same way whether or not an echo was in it. Left unset, it is the
    # normalization of `decoded`.
    normalized: DecodedValues | None = None
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
    # Statuses that ARE the defense under test answering. The Judge's evidence gate reads this
    # set instead of special-casing each probe: the authz track sets the denial codes (only 403
    # when the request carried our own live token, since a 401 there is that token failing),
    # enumeration its uniform refusal (400), rate limit its throttle (429). Anywhere else a
    # non-2xx is no evidence. `expect_rejected` always adds 401/403 (see judge._no_answer).
    defense_statuses: frozenset[int] = frozenset()
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
    # Set only by the contradiction probe: parse the chart's `patient_facts` out of the response
    # body and check that a field with several values marks which one is current.
    check_contradiction: bool = False
    # Set only by the enumeration probe: whether the anonymous mint issued a session credential
    # for `requested_patient`, an id it has no reason to recognize. None = not that probe.
    credential_issued: bool | None = None
    # Aggregate (multi-request) mode. The observation summarizes a burst of requests rather than
    # one exchange: `status_code`/`response_text` stay unset and `burst_statuses` holds every
    # request's status in order. The Judge gates an aggregate observation on the burst, not on
    # a single response. Set only by the rate-limit probe.
    aggregate: bool = False
    burst_statuses: tuple[int, ...] = ()

    def __post_init__(self) -> None:
        if self.decoded is None and self.response_text is not None:
            object.__setattr__(self, "decoded", decoded_values(self.response_text))
        if self.normalized is None and self.decoded is not None:
            object.__setattr__(self, "normalized", tuple((p, normalize(v)) for p, v in self.decoded))

    @property
    def decoded_text(self) -> str | None:
        """The verbatim decoded values joined in document order; None when no response was captured."""
        return None if self.decoded is None else joined(self.decoded)

    @property
    def normalized_text(self) -> str | None:
        """The normalized values joined in document order: what the matching checks read."""
        return None if self.normalized is None else joined(self.normalized)


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
