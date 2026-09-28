"""Selecting among the top candidates.

The deterministic ranker (candidates.py) produces the ordered list and enforces all hard
rules; a selector only chooses among the top-k and records why. The deterministic selector
takes the argmax. The Jev selector (TypeSafe) makes a calibrated choice among the top-k and
logs per-option probabilities — but it can never override budget/halt/authorization, which
live outside it (ADR 0003 Q4/Q13). Jev is live-gated on configuration.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Protocol

from redteam.agents.orchestrator.candidates import Candidate


class Selector(Protocol):
    def select(self, candidates: list[Candidate]) -> tuple[Candidate, dict]: ...


@dataclass
class DeterministicSelector:
    def select(self, candidates: list[Candidate]) -> tuple[Candidate, dict]:
        chosen = candidates[0]
        return chosen, {"selector": "deterministic", "chosen_score": chosen.score}


@dataclass
class JevSelector:
    """Chooses among the top-k with TypeSafe Jev. Requires typesafe-sdk + a configured key;
    raises a clear error otherwise so it never silently degrades to a guess."""

    top_k: int = 3
    model: str = "jev-1.13.0"

    def select(self, candidates: list[Candidate]) -> tuple[Candidate, dict]:
        if "AGENTFORGE_REDTEAM_JEV_KEY" not in os.environ:
            raise RuntimeError("Jev selector not configured: set AGENTFORGE_REDTEAM_JEV_KEY (see .env)")
        try:
            from typesafe_sdk import Client  # noqa: F401  (imported here so the dep is optional)
        except ImportError as exc:  # pragma: no cover - exercised only when the dep is absent
            raise RuntimeError("Jev selector needs the 'typesafe-sdk' package installed") from exc
        # Intentionally not implemented until a key is provided; the deterministic ranker
        # is the live default. See docs/PLAN.md open items.
        raise NotImplementedError("JevSelector.select is wired but pending a Jev key + integration test")
