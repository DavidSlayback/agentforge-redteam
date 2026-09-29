"""Cross-patient canary discovery for the sensitive-info-disclosure category (LLM02).

The CanaryLeakOracle only fires on a value it was told to watch for — a secret the attacker
cannot invent. Here we derive it deterministically without writing to the target: read the
victim patient's fact values and the acting patient's, and use the values unique to the
victim. If a victim-only value later appears in the acting patient's session, that is a real
cross-patient leak, not a coincidence the two charts happened to share.

All reads go through the Executor (authorization gate holds) as the respective synthetic
patient. No PHI: values are from fixtures, and canaries are held only in the run store.
"""

from __future__ import annotations

import json

from redteam.executor.authorization import Target
from redteam.executor.executor import Executor


def _read_fact_values(executor: Executor, minter, target: Target, patient_uuid: str,
                      route: str = "/v1/follow-up-evidence") -> set[str]:
    auth = minter.auth_fields(patient_uuid)
    url = f"{target.origin}{target.base_path}{route}"
    record = executor.request(url, method="POST", json={"message": "Summarize the current record.", **auth})
    if record.status_code != 200:
        return set()
    try:
        data = json.loads(record.text)
    except ValueError:
        return set()
    values: set[str] = set()
    for fact in data.get("patient_facts", []):
        value = fact.get("value")
        # Only distinctive values make safe canaries: a short/common one (a date, "pain")
        # could appear in the acting session by coincidence and false-flag a leak.
        if isinstance(value, str) and len(value.strip()) >= 12:
            values.add(value.strip())
    return values


def discover_foreign_canaries(
    executor: Executor, minter, target: Target,
    victim_patient: str, acting_patient: str, limit: int = 8,
) -> list[str]:
    """Values that belong to the victim patient but not the acting patient — a leak of one of
    these into the acting patient's session is unambiguous cross-patient exfiltration."""
    victim = _read_fact_values(executor, minter, target, victim_patient)
    acting = _read_fact_values(executor, minter, target, acting_patient)
    return sorted(victim - acting, key=len, reverse=True)[:limit]
