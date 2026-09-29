"""The attacker model client (OpenAI-compatible chat).

The Red Team Agent generates and mutates attack specs through this; it is the only place
that calls the attacker model. A provider content filter (Alibaba `DataInspectionFailed`)
is a typed outcome, not a crash — it surfaces as ProviderBlock so the platform records a
block distinctly and never counts it as a defense holding.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Protocol

import httpx

from redteam.errors import ProviderBlock, TargetUnreachable


class ModelClient(Protocol):
    def complete(self, system: str, user: str, *, max_tokens: int = 800, temperature: float = 0.9) -> str: ...


@dataclass
class QwenClient:
    """Calls a Qwen model over the OpenAI-compatible /chat/completions wire."""

    base_url: str
    api_key: str
    model: str
    timeout: float = 90.0   # aimed prompts make the model reason longer

    @classmethod
    def from_env(cls) -> "QwenClient":
        try:
            return cls(
                base_url=os.environ["AGENTFORGE_REDTEAM_BASE_URL"].rstrip("/"),
                api_key=os.environ["AGENTFORGE_REDTEAM_API_KEY"],
                model=os.environ["AGENTFORGE_REDTEAM_MODEL"],
            )
        except KeyError as exc:
            raise RuntimeError(f"attacker model not configured: missing {exc.args[0]} (see .env)") from exc

    def complete(self, system: str, user: str, *, max_tokens: int = 800, temperature: float = 0.9) -> str:
        payload = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        try:
            resp = httpx.post(f"{self.base_url}/chat/completions", json=payload, headers=headers, timeout=self.timeout)
        except httpx.HTTPError as exc:
            raise TargetUnreachable(f"attacker model endpoint unreachable: {exc}") from exc

        if resp.status_code == 400 and "data_inspection" in resp.text.lower():
            raise ProviderBlock("attacker model refused input (content filter)")
        if resp.status_code >= 400:
            raise TargetUnreachable(f"attacker model HTTP {resp.status_code}: {resp.text[:200]}")

        data = resp.json()
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise TargetUnreachable(f"unexpected attacker model response shape: {data}") from exc
