"""The authorization registry — the structural boundary that keeps the platform aimed
only at targets it is allowed to attack (SA1, ADR 0002).

The registry is a human-edited, git-tracked YAML file. Nothing else grants a target. The
Executor asks this module before every request; an origin absent or disabled here cannot
be reached. Matching is by exact origin (scheme + host + port), never by path.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from redteam.errors import AuthorizationDenied


def normalize_origin(url: str) -> str:
    """Reduce a URL to its origin: ``scheme://host[:port]``, lowercased, no path.

    Raises ValueError if scheme or host is missing, so a malformed target can never be
    silently treated as some default origin.
    """
    parts = urlsplit(url if "//" in url else "//" + url)
    scheme = (parts.scheme or "").lower()
    host = (parts.hostname or "").lower()
    if not scheme or not host:
        raise ValueError(f"cannot parse an origin from {url!r}")
    netloc = host if parts.port is None else f"{host}:{parts.port}"
    return f"{scheme}://{netloc}"


@dataclass(frozen=True)
class Target:
    id: str
    origin: str
    owner: str
    proof: str
    scope: tuple[str, ...]
    enabled: bool
    base_path: str = ""  # path prefix the app is served under, e.g. "/agentforge-w2"


@dataclass
class AuthorizationRegistry:
    """Enabled targets, keyed by normalized origin."""

    targets: dict[str, Target]

    @classmethod
    def load(cls, path: str | Path) -> "AuthorizationRegistry":
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        targets: dict[str, Target] = {}
        for entry in data.get("targets", []):
            origin = normalize_origin(entry["origin"])
            targets[origin] = Target(
                id=entry["id"],
                origin=origin,
                owner=entry.get("owner", ""),
                proof=entry.get("proof", ""),
                scope=tuple(entry.get("scope", [])),
                enabled=bool(entry.get("enabled", False)),
                base_path=entry.get("base_path", "").rstrip("/"),
            )
        return cls(targets)

    def by_id(self, target_id: str) -> Target | None:
        for target in self.targets.values():
            if target.id == target_id:
                return target
        return None

    def authorized(self, url: str) -> bool:
        try:
            origin = normalize_origin(url)
        except ValueError:
            return False
        target = self.targets.get(origin)
        return bool(target and target.enabled)

    def assert_authorized(self, url: str) -> Target:
        """Return the enabled Target for ``url``'s origin, or raise AuthorizationDenied."""
        try:
            origin = normalize_origin(url)
        except ValueError as exc:
            raise AuthorizationDenied(url) from exc
        target = self.targets.get(origin)
        if target is None or not target.enabled:
            raise AuthorizationDenied(origin)
        return target
