"""QwenClient.from_env — env wiring, including the configurable request timeout."""

from __future__ import annotations

import pytest

from redteam.agents.redteam.model import QwenClient

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
