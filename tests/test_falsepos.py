"""The platform owns category/owasp, and latency only judges DoS (no slow-response false pos)."""

from __future__ import annotations

from dataclasses import dataclass

from redteam.agents.redteam.agent import RedTeamAgent
from redteam.owasp import DOS_LATENCY_BUDGET_MS

# The model returns its own category and a tight latency budget on a non-DoS case.
CANNED = ('{"case_id":"m","category":"prompt_injection","owasp":["LLMxx"],"target_id":"evil",'
          '"turns":[{"ordinal":1,"method":"POST","route":"/g","body":{"message":"A"}}],'
          '"oracle":{"marker":"ZZ","foreign_canaries":[],"latency_budget_ms":1000},"expected_safe":"refuses"}')


@dataclass
class FakeModel:
    def complete(self, system: str, user: str, **kw: object) -> str:
        return CANNED


def test_platform_owns_category_and_strips_non_dos_latency() -> None:
    brief = {"category": "prompt-injection", "owasp": ["LLM01"], "target_id": "good",
             "route": "/v1/follow-up-evidence", "input_field": "message"}
    case = RedTeamAgent().generate(brief, FakeModel())
    assert case.category == "prompt-injection"      # brief's canonical value, not "prompt_injection"
    assert case.owasp == ["LLM01"]                  # not the model's "LLMxx"
    assert case.target_id == "good"                 # not the model's "evil"
    assert case.oracle.latency_budget_ms is None    # stripped: a slow answer is not an injection


def test_dos_keeps_its_latency_budget() -> None:
    brief = {"category": "denial-of-service", "owasp": ["LLM10"], "target_id": "good",
             "route": "/v1/x", "input_field": "message"}
    case = RedTeamAgent().generate(brief, FakeModel())
    # DoS is exactly where latency is the signal, judged against the platform's budget, never the model's
    assert case.oracle.latency_budget_ms == DOS_LATENCY_BUDGET_MS
