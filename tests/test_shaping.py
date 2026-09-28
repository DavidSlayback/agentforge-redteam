"""Schema-aware shaping forces the payload into the route's declared input field."""

from __future__ import annotations

from dataclasses import dataclass

from redteam.agents.redteam.agent import RedTeamAgent, _shape_to_field
from redteam.agents.orchestrator.candidates import build_candidates
from redteam.evals.case import SeedCase, Turn
from redteam.store.store import Store


def _case(body: dict) -> SeedCase:
    return SeedCase(
        case_id="c", category="prompt-injection", owasp=["LLM01"], target_id="good",
        turns=[Turn(ordinal=1, method="POST", route="/wrong", body=body)],
        expected_safe="refuses",
    )


def test_shape_moves_payload_into_declared_field() -> None:
    # model put the payload under a guessed field name and a wrong route
    shaped = _shape_to_field(_case({"question": "PAYLOAD-TEXT"}), {"route": "/v1/follow-up-evidence", "input_field": "message"})
    assert len(shaped.turns) == 1
    assert shaped.turns[0].route == "/v1/follow-up-evidence"
    assert shaped.turns[0].body == {"message": "PAYLOAD-TEXT"}


def test_shape_prefers_the_named_field_when_present() -> None:
    shaped = _shape_to_field(_case({"message": "RIGHT", "noise": "x"}), {"route": "/r", "input_field": "message"})
    assert shaped.turns[0].body == {"message": "RIGHT"}


def test_shape_noop_without_input_field() -> None:
    original = _case({"anything": "y"})
    assert _shape_to_field(original, {"route": "/r"}) is original


def test_shape_preserves_multiple_turns() -> None:
    case = SeedCase(
        case_id="c", category="prompt-injection", owasp=["LLM01"], target_id="good",
        turns=[Turn(ordinal=1, route="/w", body={"message": "SETUP"}),
               Turn(ordinal=2, route="/w", body={"q": "EXPLOIT"})],
        expected_safe="refuses",
    )
    shaped = _shape_to_field(case, {"route": "/v1/x", "input_field": "message"})
    assert [t.body for t in shaped.turns] == [{"message": "SETUP"}, {"message": "EXPLOIT"}]
    assert all(t.route == "/v1/x" for t in shaped.turns)


def test_shape_returns_unchanged_when_no_string_payload() -> None:
    original = _case({"count": 5})   # no string anywhere -> do not fabricate {"message": ""}
    assert _shape_to_field(original, {"route": "/r", "input_field": "message"}) is original


@dataclass
class FakeModel:
    out: str

    def complete(self, system: str, user: str, **kw: object) -> str:
        return self.out


def test_generate_shapes_to_input_field() -> None:
    canned = ('{"case_id":"x","category":"prompt-injection","owasp":["LLM01"],"target_id":"good",'
              '"turns":[{"ordinal":1,"method":"POST","route":"/guessed","body":{"q":"ATTACK"}}],'
              '"oracle":{"marker":"ZZ","foreign_canaries":[],"latency_budget_ms":null},"expected_safe":"refuses"}')
    brief = {"category": "prompt-injection", "owasp": ["LLM01"], "target_id": "good",
             "route": "/v1/follow-up-evidence", "input_field": "message"}
    case = RedTeamAgent().generate(brief, FakeModel(canned))
    assert case.turns[0].route == "/v1/follow-up-evidence"
    assert set(case.turns[0].body) == {"message"}


def test_build_candidates_attaches_input_field(tmp_path) -> None:
    store = Store.open(tmp_path / "s.db")
    cands = build_candidates(
        store, "good", ["/v1/follow-up-evidence"], [("prompt-injection", ["LLM01"])],
        route_fields={"/v1/follow-up-evidence": "message"},
    )
    assert cands[0].brief["input_field"] == "message"
    store.close()
