"""Typed platform errors.

These mirror the typed error contracts named in docs/HARNESS_SPEC.md (E6). Each carries
a stable `code` (the wire identifier) and whether the condition is `retriable`. The JSON
Schema forms live in /contracts alongside the message schemas; these are their Python side.

A missing verdict is never a pass: a budget stop or a provider block is a typed *outcome*,
not a silent failure.
"""

from __future__ import annotations


class RedteamError(Exception):
    """Base class for typed platform errors."""

    code: str = "redteam_error"
    retriable: bool = False


class AuthorizationDenied(RedteamError):
    """The requested target origin is not an enabled entry in the authorization registry."""

    code = "authorization_denied"
    retriable = False

    def __init__(self, origin: str) -> None:
        super().__init__(f"target origin not authorized: {origin}")
        self.origin = origin


class TargetUnreachable(RedteamError):
    code = "target_unreachable"
    retriable = True


class BudgetExceeded(RedteamError):
    code = "budget_exceeded"
    retriable = False


class JudgeTimeout(RedteamError):
    code = "judge_timeout"
    retriable = True


class ProviderBlock(RedteamError):
    """A model provider's own content filter stopped a generation or response.

    Never evidence that the target's defense held; for regression it is INCONCLUSIVE.
    """

    code = "provider_block"
    retriable = False


class RegressionDetected(RedteamError):
    code = "regression_detected"
    retriable = False


class NoFindingsInWindow(RedteamError):
    code = "no_findings_in_window"
    retriable = False
