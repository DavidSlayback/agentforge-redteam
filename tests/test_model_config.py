"""QwenClient: env wiring (including the configurable timeout) and how a reply is classified."""

from __future__ import annotations

import httpx
import pytest

from redteam.agents.redteam.model import QwenClient
from redteam.errors import ProviderBlock, TargetUnreachable

_REQUIRED = {
    "AGENTFORGE_REDTEAM_BASE_URL": "https://api.example/v1",
    "AGENTFORGE_REDTEAM_API_KEY": "k",
    "AGENTFORGE_REDTEAM_MODEL": "qwen3.8-flash",
}


def _set(monkeypatch):
    for k, v in _REQUIRED.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("AGENTFORGE_REDTEAM_TIMEOUT", raising=False)


def test_defaults_to_90s_timeout(monkeypatch) -> None:
    _set(monkeypatch)
    assert QwenClient.from_env().timeout == 90.0


def test_timeout_is_env_configurable(monkeypatch) -> None:
    _set(monkeypatch)
    monkeypatch.setenv("AGENTFORGE_REDTEAM_TIMEOUT", "300")
    c = QwenClient.from_env()
    assert c.timeout == 300.0 and c.base_url == "https://api.example/v1" and c.model == "qwen3.8-flash"


def test_missing_key_is_actionable(monkeypatch) -> None:
    for k in _REQUIRED:
        monkeypatch.delenv(k, raising=False)
    with pytest.raises(RuntimeError, match="attacker model not configured"):
        QwenClient.from_env()


# A provider content filter must surface as ProviderBlock (its own brief outcome), never as an
# outage or a crash; any other failure is TargetUnreachable; a truncated reply is an actionable error.
def _client(monkeypatch, outcome) -> QwenClient:
    def post(*_a, **_k):
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr("redteam.agents.redteam.model.httpx.post", post)
    return QwenClient(base_url="https://api.example/v1", api_key="k", model="qwen3.8-flash")


def _reply(content: str, finish_reason: str = "stop") -> httpx.Response:
    return httpx.Response(200, json={"choices": [{"message": {"content": content}, "finish_reason": finish_reason}]})


@pytest.mark.parametrize(("outcome", "error"), [
    (httpx.Response(400, text='{"code":"DataInspectionFailed","message":"data_inspection_failed"}'), ProviderBlock),
    (httpx.Response(400, text='{"error":"bad request"}'), TargetUnreachable),
    (httpx.Response(503, text="overloaded"), TargetUnreachable),
    (httpx.ReadTimeout("slow"), TargetUnreachable),
    (httpx.Response(200, json={"error": "no choices"}), TargetUnreachable),
    (_reply('{"cases": [', finish_reason="length"), ValueError),
], ids=["content-filter", "other-400", "5xx", "timeout", "bad-shape", "truncated"])
def test_complete_classifies_each_failure(monkeypatch, outcome, error) -> None:
    with pytest.raises(error):
        _client(monkeypatch, outcome).complete("sys", "user")


def test_complete_returns_the_reply_content(monkeypatch) -> None:
    assert _client(monkeypatch, _reply('{"cases": []}')).complete("sys", "user") == '{"cases": []}'
