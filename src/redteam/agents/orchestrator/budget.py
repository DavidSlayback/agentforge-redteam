"""The budget governor — halts when cost accrues without signal (PRD).

Cost is counted in **model calls** (generation + mutation + rubric), not USD: the Qwen key bills in
tokens/credits, not dollars, so a dollar cap would be fiction. The governor tracks campaigns
run, model calls spent, and a no-signal streak (campaigns since the last new finding), and
stops on the first limit reached. A halt is a normal, recorded outcome, not a failure.
"""

from __future__ import annotations

from dataclasses import dataclass

from redteam.errors import BudgetExceeded


@dataclass
class CallBudget:
    """The model-call cap, checked before every metered call rather than only between campaigns,
    so a single campaign's generation retry, mutation and rubric can never overshoot it. One
    instance spans a whole run, so ``used`` is also the run's own call count (cost attribution).
    """

    max_calls: int | None
    used: int = 0

    @property
    def has_room(self) -> bool:
        """Whether at least one more metered call fits under the cap."""
        return self.max_calls is None or self.used < self.max_calls

    def charge(self) -> None:
        """Account for one metered call about to be made; raise before the cap is exceeded."""
        if not self.has_room:
            raise BudgetExceeded(f"model-call budget reached ({self.used}/{self.max_calls})")
        self.used += 1


@dataclass(frozen=True)
class Budget:
    max_campaigns: int = 5
    max_model_calls: int = 200
    max_no_signal: int = 3   # stop after this many campaigns with no new finding


@dataclass
class Governor:
    """Campaign- and no-signal budgets. The model-call cap is owned by ``CallBudget`` (checked
    before every metered call), so the Governor does not count calls — one source for the cap,
    not two (review item 6)."""

    budget: Budget
    campaigns: int = 0
    tested: int = 0
    no_signal: int = 0

    def record(self, *, outcome: str, produced_finding: bool) -> None:
        """Account for one finished campaign. Only a *tested* campaign moves the no-signal
        streak: an untested outcome (skip / provider block / error / unreachable) was never a
        test, so it is neither signal nor an absence of signal, and a run that halts on no-signal
        really did test and find nothing. The campaign budget counts every campaign's work."""
        self.campaigns += 1
        if outcome == "tested":
            self.tested += 1
            self.no_signal = 0 if produced_finding else self.no_signal + 1

    def halt_reason(self) -> str | None:
        if self.campaigns >= self.budget.max_campaigns:
            return f"campaign budget reached ({self.campaigns}/{self.budget.max_campaigns})"
        if self.no_signal >= self.budget.max_no_signal:
            return (f"no signal for {self.no_signal} tested campaigns "
                    f"(limit {self.budget.max_no_signal})")
        return None

    def should_halt(self) -> bool:
        return self.halt_reason() is not None
