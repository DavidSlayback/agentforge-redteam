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

    def mint(self, patient_uuid: str) -> MintedToken:
        cached = self._cache.get(patient_uuid)
        if cached is not None and cached.expires_at - time.time() > 15:
            return cached
        url = f"{self.target.origin}{self.target.base_path}/v1/demo-context"
        record = self.executor.request(url, method="GET", params={"patient_uuid": patient_uuid})
        if record.status_code != 200:
            raise TargetUnreachable(f"demo-context mint failed ({record.status_code}): {record.text[:120]}")
        data = json.loads(record.text)
        token = MintedToken(
            demo_token=data["demo_token"],
            clinician_uuid=data.get("clinician_uuid", "fixture-physician-001"),
            patient_uuid=data.get("patient_uuid", patient_uuid),
            expires_at=time.time() + float(data.get("expires_in_seconds", 300)),
        )
        self._cache[patient_uuid] = token
        return token

    def auth_fields(self, patient_uuid: str) -> dict[str, str]:
        """The fields a patient route needs in its body: token, clinician, patient."""
        token = self.mint(patient_uuid)
        return {
            "patient_uuid": token.patient_uuid,
            "clinician_uuid": token.clinician_uuid,
            "demo_token": token.demo_token,
        }
