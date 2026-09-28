"""The Executor — the one component allowed to reach a target (ADR 0002).

Every outbound request passes the authorization gate first. An unlisted or disabled origin
raises AuthorizationDenied *before* the sender is ever called, so no request leaves the
process for a target the registry does not permit. The sender is injected: the real one
speaks HTTP (added when attempts are recorded); tests pass a spy to prove the gate holds.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from redteam.executor.authorization import AuthorizationRegistry


class Sender(Protocol):
    def __call__(self, url: str, /, **kwargs: Any) -> Any: ...


@dataclass
class Executor:
    registry: AuthorizationRegistry
    sender: Sender

    def request(self, url: str, /, **kwargs: Any) -> Any:
        """Authorize ``url``'s origin, then delegate to the sender.

        Raises AuthorizationDenied before the sender is touched if the origin is not an
        enabled registry entry.
        """
        self.registry.assert_authorized(url)
        return self.sender(url, **kwargs)
