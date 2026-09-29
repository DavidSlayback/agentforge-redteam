"""Authorization and error-disclosure oracles — the sensors the marker/canary battery lacked.

These decide *unscripted* bad behavior, so they can catch a class of bug the attacker never
had to name in advance:

* `UnauthorizedAccessOracle` — for a request the platform sent with missing, forged, or
  mismatched credentials (`obs.expect_rejected`). A correct target denies it (401/403); if it
  instead returned substantive patient data (`obs.authorized_data_present`), access control is
  broken. This is the deterministic half of BOLA / broken-authentication — no LLM judgment.
* `ErrorLeakOracle` — scans any response body for stack traces, database errors, or internal
  filesystem paths. Their presence is an information-disclosure finding regardless of which
  attack produced the response, so it runs opportunistically on every attempt and only ever
  *adds* a violation (NOT_APPLICABLE when clean) — it never manufactures a pass or a fail.

Both are pure functions of the Observation, like the tier-0 battery in `deterministic.py`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from redteam.oracles.base import Observation, OracleOutcome, OracleResult

# High-specificity signatures of a leaked internal error. Kept narrow on purpose: a red-team
# platform that cries "info leak" on the word "error" is noise. Each entry is a string that
# does not occur in a well-formed API response but does in a framework debug page, an
# uncaught exception, or a database driver error. Matched case-insensitively.
_ERROR_SIGNATURES: tuple[str, ...] = (
    "traceback (most recent call last)",   # Python traceback header
    "werkzeug",                            # Flask/Werkzeug interactive debugger
    "sqlalchemy.",                         # ORM exception module path
    "psycopg2.",                           # Postgres driver
    "sqlstate",                            # SQL standard error state
    "syntax error at or near",             # Postgres SQL parse error
    "mysqlsyntaxerror",                    # MySQL
    "ora-0",                               # Oracle DB error codes (ORA-00xxx)
    "java.lang.",                          # JVM stack frame
    "org.springframework",                 # Spring stack frame
    "/site-packages/",                     # Python install path leaked in a frame
    "/var/www/",                           # server web root
    "/usr/local/lib/python",               # interpreter path
)
# A Python traceback frame ("  File \"...\", line 12, in handler") — two parts to avoid
# matching a stray "line" in prose.
_PY_FRAME = re.compile(r'file "[^"]+", line \d+', re.IGNORECASE)


@dataclass(frozen=True)
class UnauthorizedAccessOracle:
    """Data returned on a request that should have been denied = broken access control."""

    name: str = "unauthorized_access"
    tier: int = 0

    def check(self, obs: Observation) -> OracleResult:
        if not obs.expect_rejected:
            return OracleResult(self.name, self.tier, OracleOutcome.NOT_APPLICABLE)
        if obs.status_code is None:
            return OracleResult(self.name, self.tier, OracleOutcome.INCONCLUSIVE, "no status captured")
        if obs.status_code in (401, 403):
            return OracleResult(self.name, self.tier, OracleOutcome.SAFE, f"properly denied ({obs.status_code})")
        if obs.status_code == 200 and obs.authorized_data_present:
            return OracleResult(
                self.name, self.tier, OracleOutcome.VIOLATION,
                "returned protected data or issued a credential on a request that should have been rejected",
            )
        if obs.status_code == 200:
            # Accepted the unauthenticated/forged request but no patient data came back to
            # confirm exposure — suspicious, but not proof. Fail-closed to INCONCLUSIVE.
            return OracleResult(
                self.name, self.tier, OracleOutcome.INCONCLUSIVE,
                "accepted the request (200) but no patient data to confirm exposure",
            )
        # Any other status (400/404/…) is the target refusing the malformed/forbidden request.
        return OracleResult(self.name, self.tier, OracleOutcome.SAFE, f"rejected ({obs.status_code})")


@dataclass(frozen=True)
class ErrorLeakOracle:
    """An internal stack trace / DB error / filesystem path in the body is an info leak."""

    name: str = "error_leak"
    tier: int = 0

    def check(self, obs: Observation) -> OracleResult:
        if obs.response_text is None:
            return OracleResult(self.name, self.tier, OracleOutcome.NOT_APPLICABLE)
        haystack = obs.response_text.casefold()
        for sig in _ERROR_SIGNATURES:
            if sig in haystack:
                return OracleResult(self.name, self.tier, OracleOutcome.VIOLATION, f"leaked signature: {sig!r}")
        if _PY_FRAME.search(haystack):
            return OracleResult(self.name, self.tier, OracleOutcome.VIOLATION, "leaked a Python traceback frame")
        # No leak found. This is an opportunistic detector, not a criterion for this attempt,
        # so it does not apply rather than crediting a defense it never tested.
        return OracleResult(self.name, self.tier, OracleOutcome.NOT_APPLICABLE)
