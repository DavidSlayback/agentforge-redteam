"""The Red Team aims: OWASP objective, technique families, and target context reach Qwen."""

from __future__ import annotations

from dataclasses import dataclass, field

from redteam.agents.redteam.agent import RedTeamAgent
from redteam.owasp import STRATEGIES, strategy_for

CANNED = ('{"case_id":"x","category":"prompt-injection","owasp":["LLM01"],"target_id":"good",'
          '"turns":[{"ordinal":1,"method":"POST","route":"/r","body":{"message":"A"}}],'
          '"oracle":{"marker":"ZZ","foreign_canaries":[],"latency_budget_ms":null},"expected_safe":"refuses"}')


@dataclass
class Capturing:
    prompts: list[str] = field(default_factory=list)

    def complete(self, system: str, user: str, **kw: object) -> str:
        self.prompts.append(user)
        return CANNED


def test_every_strategy_maps_to_owasp_and_has_an_objective() -> None:
    for category, strat in STRATEGIES.items():
        assert strat["owasp"], category
        assert strat["objective"], category
        assert strat["techniques"], category


def test_generate_grounds_the_prompt() -> None:
    m = Capturing()
    agent = RedTeamAgent(target_context="a clinical co-pilot with claim verification")
    brief = {"category": "sensitive-info-disclosure", "owasp": ["LLM02"], "target_id": "good",
             "route": "/v1/follow-up-evidence", "input_field": "message"}
    agent.generate(brief, m)
    prompt = m.prompts[0]
    assert "a clinical co-pilot with claim verification" in prompt      # target context
    assert strategy_for("sensitive-info-disclosure")["objective"][:20] in prompt  # objective
    assert "cross-patient reference" in prompt                          # a technique family
