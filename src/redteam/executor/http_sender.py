"""The real HTTP sender the Executor delegates to (the only code that opens a socket
to a target). It returns a plain, hashable record so the Judge sees deterministic evidence
and never a live client object.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import httpx


@dataclass(frozen=True)
class ResponseRecord:
    status_code: int
    text: str
    latency_ms: float


def http_sender(url: str, /, *, method: str = "GET", timeout: float = 30.0, **kwargs: Any) -> ResponseRecord:
    """Send one request and record status, body, and wall latency.

    `kwargs` pass through to httpx (json=, headers=, content=, params=). Only ever called
    by the Executor, and only after the origin has been authorized.
    """
    start = time.perf_counter()
    resp = httpx.request(method, url, timeout=timeout, **kwargs)
    latency_ms = (time.perf_counter() - start) * 1000.0
    return ResponseRecord(status_code=resp.status_code, text=resp.text, latency_ms=latency_ms)
