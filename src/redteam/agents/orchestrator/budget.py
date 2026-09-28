"""The budget governor — halts when cost accrues without signal (PRD).

Tracks campaigns run, spend, and a no-signal streak (campaigns since the last new finding),
and stops on the first limit reached. A halt is a normal, recorded outcome, not a failure.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Budget:
    max_campaigns: int = 5
    max_usd: float = 1.0
    max_no_signal: int = 3   # stop after this many campaigns with no new finding


@dataclass
class Governor:
    budget: Budget
    campaigns: int = 0
    spend_usd: float = 0.0
    no_signal: int = 0

    def record(self, *, produced_finding: bool, spend_usd: float) -> None:
        self.campaigns += 1
        self.spend_usd += spend_usd
        self.no_signal = 0 if produced_finding else self.no_signal + 1

    def halt_reason(self) -> str | None:
        if self.campaigns >= self.budget.max_campaigns:
            return f"campaign budget reached ({self.campaigns}/{self.budget.max_campaigns})"
        if self.spend_usd >= self.budget.max_usd:
            return f"spend budget reached (${self.spend_usd:.4f}/${self.budget.max_usd:.4f})"
        if self.no_signal >= self.budget.max_no_signal:
            return f"no signal for {self.no_signal} campaigns (limit {self.budget.max_no_signal})"
        return None

    def should_halt(self) -> bool:
        return self.halt_reason() is not None
