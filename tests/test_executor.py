"""The Executor gate: no request leaves the process for an unauthorized origin.

This is the S1 headline behavior — authorization is structural, not a policy a caller
might forget (ADR 0002). The sender is a spy, so a leak would show up as a recorded call.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from redteam.errors import AuthorizationDenied
from redteam.executor.authorization import AuthorizationRegistry
from redteam.executor.executor import Executor


@pytest.fixture
def registry(tmp_path: Path) -> AuthorizationRegistry:
    path = tmp_path / "auth.yaml"
    path.write_text(
        "targets:\n"
        "  - id: ok\n"
        "    origin: https://good.example\n"
        "    enabled: true\n"
        "  - id: off\n"
        "    origin: https://disabled.example\n"
        "    enabled: false\n",
        encoding="utf-8",
    )
    return AuthorizationRegistry.load(path)


def test_executor_sends_to_an_authorized_origin(registry: AuthorizationRegistry) -> None:
    calls: list[str] = []
    executor = Executor(registry, sender=lambda url, **kw: calls.append(url) or "ok")
    result = executor.request("https://good.example/v1/briefings")
    assert result == "ok"
    assert calls == ["https://good.example/v1/briefings"]


@pytest.mark.parametrize("url", ["https://disabled.example/x", "https://unknown.example/y", "not-a-url"])
def test_executor_refuses_unlisted_origin_without_calling_sender(
    registry: AuthorizationRegistry, url: str
) -> None:
    calls: list[str] = []

    def spy(u: str, **kw: object) -> object:
        calls.append(u)
        return "leaked"

    executor = Executor(registry, sender=spy)
    with pytest.raises(AuthorizationDenied):
        executor.request(url)
    assert calls == [], "sender was called for an unauthorized origin — the gate leaked"


def test_http_sender_hard_pins_no_redirects(monkeypatch: pytest.MonkeyPatch) -> None:
    # T2.1: a 3xx must never be followed off the authorized origin, and a caller cannot re-enable it.
    import httpx

    from redteam.executor.http_sender import http_sender

    captured: dict = {}

    class _Resp:
        status_code = 200
        text = "ok"
        headers: dict[str, str] = {}

    def fake_request(method: str, url: str, **kw: object) -> _Resp:
        captured.update(kw)
        return _Resp()

    monkeypatch.setattr(httpx, "request", fake_request)
    http_sender("https://good.example/x", method="GET", follow_redirects=True)   # caller tries to enable
    assert captured["follow_redirects"] is False


@pytest.mark.parametrize("route", ["//evil.example/x", "http://evil.example/x", "/ok/@evil", "relative", "\\evil"])
def test_send_turns_rejects_a_non_rooted_route(registry: AuthorizationRegistry, route: str) -> None:
    # T2.1: a model-supplied route cannot relocate the origin.
    from redteam.evals.case import Turn
    from redteam.executor.http_sender import ResponseRecord
    from redteam.runner import send_turns

    target = registry.by_id("ok")
    calls: list[str] = []
    ex = Executor(registry, sender=lambda u, **kw: calls.append(u) or ResponseRecord(200, "ok", 1.0))
    with pytest.raises(AuthorizationDenied):
        send_turns(target, ex, [Turn(ordinal=1, route=route)], [])
    assert calls == [], "a non-rooted route reached the sender"
