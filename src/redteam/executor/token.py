"""Target session tokens, minted through the target's own synthetic-context endpoint.

An attacker probing the live site discovers `/v1/demo-context?patient_uuid=<fixture>` and
uses it to obtain a short-lived, patient-scoped `demo_token` that patient routes require in
their body. This mirrors that: it mints (and caches) a token per synthetic patient, so
attempts actually reach the AI instead of bouncing at request validation.

Minting goes through the Executor like any other target request, so it too passes the
authorization gate — the single-door invariant holds (ADR 0002).
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from redteam.errors import TargetUnreachable
from redteam.executor.authorization import Target
from redteam.executor.executor import Executor


@dataclass(frozen=True)
class MintedToken:
    demo_token: str
    clinician_uuid: str
    patient_uuid: str
    expires_at: float


@dataclass
class TokenMinter:
    executor: Executor
    target: Target
    _cache: dict[str, MintedToken] = field(default_factory=dict)
    # The target rate-limits its mints per client (429 + Retry-After; W3 fix F-6ee92046fb,
    # 15 per 60 s by default). A 429 is a wait, not an unreachable target: sleep for
    # Retry-After (capped) and mint again, up to `max_rate_limit_retries` times.
    sleep: Callable[[float], None] = time.sleep
    max_rate_limit_retries: int = 2
    max_rate_limit_wait_s: float = 60.0

    def _mint(self, endpoint: str, patient_uuid: str) -> MintedToken:
        key = f"{endpoint}:{patient_uuid}"
        cached = self._cache.get(key)
        if cached is not None and cached.expires_at - time.time() > 15:
            return cached
        url = f"{self.target.origin}{self.target.base_path}{endpoint}"
        record = self.executor.request(url, method="GET", params={"patient_uuid": patient_uuid})
        for _ in range(self.max_rate_limit_retries):
            if record.status_code != 429:
                break
            wait = record.retry_after if record.retry_after is not None else self.max_rate_limit_wait_s
            self.sleep(min(wait, self.max_rate_limit_wait_s))
            record = self.executor.request(url, method="GET", params={"patient_uuid": patient_uuid})
        if record.status_code == 429:
            raise TargetUnreachable(f"mint {endpoint} still rate-limited (429) after {self.max_rate_limit_retries} retries")
        if record.status_code != 200:
            raise TargetUnreachable(f"mint {endpoint} failed ({record.status_code}): {record.text[:120]}")
        data = json.loads(record.text)
        token = MintedToken(
            demo_token=data["demo_token"],
            clinician_uuid=data.get("clinician_uuid", "fixture-physician-001"),
            patient_uuid=data.get("patient_uuid", patient_uuid),
            expires_at=time.time() + float(data.get("expires_in_seconds", 300)),
        )
        self._cache[key] = token
        return token

    def mint(self, patient_uuid: str) -> MintedToken:
        return self._mint("/v1/demo-context", patient_uuid)

    def mint_write(self, patient_uuid: str) -> MintedToken:
        """A write-scoped token for uploading source documents."""
        return self._mint("/v1/source-document-context", patient_uuid)

    def auth_fields(self, patient_uuid: str) -> dict[str, str]:
        """The fields a patient route needs in its body: token, clinician, patient."""
        return self._fields(self.mint(patient_uuid))

    def write_fields(self, patient_uuid: str) -> dict[str, str]:
        return self._fields(self.mint_write(patient_uuid))

    @staticmethod
    def _fields(token: MintedToken) -> dict[str, str]:
        return {
            "patient_uuid": token.patient_uuid,
            "clinician_uuid": token.clinician_uuid,
            "demo_token": token.demo_token,
        }
