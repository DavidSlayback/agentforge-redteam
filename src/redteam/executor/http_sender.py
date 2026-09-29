"""The real HTTP sender the Executor delegates to (the only code that opens a socket
to a target). It returns a plain, hashable record so the Judge sees deterministic evidence
and never a live client object.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import httpx

from redteam.errors import TargetUnreachable


@dataclass(frozen=True)
class ResponseRecord:
    status_code: int
    text: str
    latency_ms: float


def http_sender(url: str, /, *, method: str = "GET", timeout: float = 90.0, **kwargs: Any) -> ResponseRecord:
    """Send one request and record status, body, and wall latency.

    `kwargs` pass through to httpx (json=, headers=, content=, params=). Only ever called
    by the Executor, and only after the origin has been authorized. A transport failure
    (timeout, dropped connection, refused) becomes a typed TargetUnreachable so the runner
    records it as INCONCLUSIVE instead of crashing the campaign.
    """
    # Hard-pin: never follow redirects. Only the authorized origin's URL passes the gate; a 3xx
    # (or an open redirect on the target) would send the next hop to an unauthorized origin that
    # never hits assert_authorized. Pop any caller-supplied value so this cannot be overridden
    # (role-review T2.1). If a redirect is ever needed, re-authorize each hop explicitly.
    kwargs.pop("follow_redirects", None)
    start = time.perf_counter()
    try:
        resp = httpx.request(method, url, timeout=timeout, follow_redirects=False, **kwargs)
    except httpx.HTTPError as exc:
        raise TargetUnreachable(f"{method} {url}: {type(exc).__name__}: {exc}") from exc
    latency_ms = (time.perf_counter() - start) * 1000.0
    return ResponseRecord(status_code=resp.status_code, text=resp.text, latency_ms=latency_ms)
