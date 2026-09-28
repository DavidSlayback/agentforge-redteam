"""The authorization registry: only enabled, listed origins are authorized."""

from __future__ import annotations

from pathlib import Path

import pytest

from redteam.errors import AuthorizationDenied
from redteam.executor.authorization import AuthorizationRegistry, normalize_origin

REPO_ROOT = Path(__file__).resolve().parents[1]
REAL_REGISTRY = REPO_ROOT / "authorization.yaml"


@pytest.mark.parametrize(
    ("url", "origin"),
    [
        ("https://dtstest.64.177.10.182.nip.io/agentforge-w2/health", "https://dtstest.64.177.10.182.nip.io"),
        ("https://Example.COM:8443/x?y=1", "https://example.com:8443"),
        ("http://localhost:8080", "http://localhost:8080"),
    ],
)
def test_normalize_origin_strips_to_scheme_host_port(url: str, origin: str) -> None:
    assert normalize_origin(url) == origin


@pytest.mark.parametrize("bad", ["", "not a url", "/just/a/path", "ftp:///"])
def test_normalize_origin_rejects_malformed(bad: str) -> None:
    with pytest.raises(ValueError):
        normalize_origin(bad)


def test_real_registry_authorizes_only_the_enabled_target() -> None:
    reg = AuthorizationRegistry.load(REAL_REGISTRY)
    # agentforge-w2 is enabled; a path under its origin is still authorized.
    assert reg.authorized("https://dtstest.64.177.10.182.nip.io/agentforge-w2/health")
    # the local replica is present but disabled.
    assert not reg.authorized("http://localhost:8080/v1/briefings")
    # an origin absent from the file is never authorized.
    assert not reg.authorized("https://example.org")


def test_assert_authorized_returns_target_or_raises(tmp_path: Path) -> None:
    registry = tmp_path / "auth.yaml"
    registry.write_text(
        "targets:\n"
        "  - id: ok\n"
        "    origin: https://good.example\n"
        "    enabled: true\n"
        "  - id: off\n"
        "    origin: https://disabled.example\n"
        "    enabled: false\n",
        encoding="utf-8",
    )
    reg = AuthorizationRegistry.load(registry)
    assert reg.assert_authorized("https://good.example/attack").id == "ok"
    with pytest.raises(AuthorizationDenied):
        reg.assert_authorized("https://disabled.example/x")
    with pytest.raises(AuthorizationDenied):
        reg.assert_authorized("https://unknown.example")
