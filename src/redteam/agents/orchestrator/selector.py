"""Selecting among the top candidates.

The deterministic ranker (candidates.py) produces the ordered list and enforces all hard
rules; a selector only chooses among the top-k and records why. The deterministic selector
takes the argmax. The Jev selector (TypeSafe) makes a calibrated choice among the top-k and
logs per-option probabilities — but it can never override budget/halt/authorization, which
live outside it (ADR 0003 Q4/Q13). Jev is gated on configuration; below its confidence
threshold it falls back to the deterministic top-1 and never stalls.
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


def _apply_bands(top: list[Candidate], jev_index: int, confidence: float, threshold: float) -> tuple[Candidate, bool]:
    """Q13 bands: take Jev's pick at/above the threshold; otherwise fall back to the
    deterministic top-1 (never stall). Returns (chosen, fell_back)."""
    if confidence >= threshold and 0 <= jev_index < len(top):
        return top[jev_index], False
    return top[0], True


@dataclass
class JevSelector:
    """Chooses among the top-k with TypeSafe Jev. Requires typesafe-sdk + a key; raises a
    clear error otherwise so it never silently degrades to a guess."""

    top_k: int = 3
    model: str = "jev-1.13.0"
    threshold: float = 0.5   # vendor example floor; tune from logged decisions

    def select(self, candidates: list[Candidate]) -> tuple[Candidate, dict]:
        api_key = os.environ.get("AGENTFORGE_REDTEAM_JEV_KEY")
        if not api_key:
            raise RuntimeError("Jev selector not configured: set AGENTFORGE_REDTEAM_JEV_KEY (see .env)")
        try:
            import typesafe_sdk as ts
        except ImportError as exc:  # pragma: no cover - only without the optional dep
            raise RuntimeError("Jev selector needs 'typesafe-sdk' (uv sync --group jev)") from exc

        top = candidates[: self.top_k]
        criteria = {
            str(i): f"{c.brief.get('category')} tried={c.inputs.get('tried')} open_findings={c.inputs.get('open_findings')}"
            for i, c in enumerate(top)
        }
        client = ts.TypeSafeClient(api_key=api_key, model=self.model)
        try:
            resp = client.system_one(
                {"candidates": [c.brief | c.inputs for c in top]},
                {"pick": ts.Choice(
                    instructions="Which candidate id should the red team run next to maximize NEW findings? "
                                 "Prefer under-tested categories and those with open findings.",
                    criteria=criteria,
                )},
            )
        except Exception as exc:  # vendor/network outage: degrade to the deterministic top-1 rather
            # than kill an unattended run — the ranker sitting right here is the safe fallback (T3.7).
            return top[0], {"selector": "jev", "model": self.model, "fell_back": True,
                            "error": f"{type(exc).__name__}: {exc}"[:200]}
        finally:
            client.close()

        answer = resp.answers["pick"]
        chosen, fell_back = _apply_bands(top, int(answer.choice), answer.confidence, self.threshold)
        return chosen, {
            "selector": "jev", "model": self.model, "confidence": answer.confidence,
            "probabilities": answer.probabilities, "jev_choice": answer.choice, "fell_back": fell_back,
        }
