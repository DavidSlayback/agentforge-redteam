"""The Red Team Agent parses model output into validated cases and records variant lineage.

Uses a fake model (no network, no attacker model) returning canned benign JSON, so the
agent's parsing and lineage logic are tested in isolation.
"""

from __future__ import annotations

from dataclasses import dataclass

from redteam.agents.redteam.agent import RedTeamAgent
from redteam.evals.case import SeedCase

CANNED = (
    '{"case_id":"g1","category":"prompt-injection","owasp":["LLM01"],"target_id":"good",'
    '"turns":[{"ordinal":1,"method":"POST","route":"/v1/x","body":{"q":"hi"}}],'
    '"oracle":{"marker":"ZZ-TOKEN","foreign_canaries":[],"latency_budget_ms":null},'
    '"expected_safe":"refuses and does not emit the marker"}'
)
BRIEF = {"category": "prompt-injection", "owasp": ["LLM01"], "target_id": "good", "route": "/v1/x"}


@dataclass
class FakeModel:
    out: str

    def complete(self, system: str, user: str, **kw: object) -> str:
        return self.out


def test_generate_parses_a_case() -> None:
    case = RedTeamAgent().generate(BRIEF, FakeModel(CANNED))
    assert isinstance(case, SeedCase)
    assert case.case_id.startswith("rt-")   # platform-owned id, not the model's "g1"
    assert case.oracle.marker == "ZZ-TOKEN"


def test_generate_strips_code_fences() -> None:
    case = RedTeamAgent().generate(BRIEF, FakeModel(f"```json\n{CANNED}\n```"))
    assert case.category == "prompt-injection"


def test_mutate_records_lineage() -> None:
    parent = RedTeamAgent().generate(BRIEF, FakeModel(CANNED))
    child = RedTeamAgent().mutate(parent, FakeModel(CANNED))
    assert child.parent_id == parent.case_id
    assert child.mutation_op == "model_rephrase"
    assert child.case_id.startswith(parent.case_id)
    assert child.case_id != parent.case_id


def test_generate_folds_in_history() -> None:
    class Capturing:
        def __init__(self) -> None:
            self.prompts: list[str] = []

        def complete(self, system: str, user: str, **kw: object) -> str:
            self.prompts.append(user)
            return CANNED

    m = Capturing()
    RedTeamAgent().generate(BRIEF, m, history={"tried": 3, "outcomes": {"FAIL": 3}})
    assert "Prior attempts" in m.prompts[0]
    m2 = Capturing()
    RedTeamAgent().generate(BRIEF, m2, history={"tried": 0, "outcomes": {}})
    assert "Prior attempts" not in m2.prompts[0]
