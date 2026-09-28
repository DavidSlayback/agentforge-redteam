"""The budget governor — halts when cost accrues without signal (PRD).

Cost is counted in **model calls** (generation + mutation), not USD: the Qwen key bills in
tokens/credits, not dollars, so a dollar cap would be fiction. The governor tracks campaigns
run, model calls spent, and a no-signal streak (campaigns since the last new finding), and
stops on the first limit reached. A halt is a normal, recorded outcome, not a failure.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Budget:
    max_campaigns: int = 5
    max_model_calls: int = 200
    max_no_signal: int = 3   # stop after this many campaigns with no new finding


@dataclass
class Governor:
    budget: Budget
    campaigns: int = 0
    model_calls: int = 0
    no_signal: int = 0

    def record(self, *, produced_finding: bool, model_calls: int) -> None:
        self.campaigns += 1
        self.model_calls += model_calls
        self.no_signal = 0 if produced_finding else self.no_signal + 1

    def halt_reason(self) -> str | None:
        if self.campaigns >= self.budget.max_campaigns:
            return f"campaign budget reached ({self.campaigns}/{self.budget.max_campaigns})"
        if self.model_calls >= self.budget.max_model_calls:
            return f"model-call budget reached ({self.model_calls}/{self.budget.max_model_calls})"
        if self.no_signal >= self.budget.max_no_signal:
            return f"no signal for {self.no_signal} campaigns (limit {self.budget.max_no_signal})"
        return None

    def should_halt(self) -> bool:
        return self.halt_reason() is not None
