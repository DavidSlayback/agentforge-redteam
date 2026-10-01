"""Attack memory reads prior attempts back, and OWASP coverage is queryable."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from redteam.agents.judge.judge import Judge
from redteam.agents.redteam.agent import MARKER_PREFIX, RedTeamAgent
from redteam.campaign import run_campaign
from redteam.executor.authorization import AuthorizationRegistry
from redteam.executor.executor import Executor
from redteam.executor.http_sender import ResponseRecord
from redteam.memory import history_brief
from redteam.observability import queries
from redteam.store.store import Store

CANNED = (
    '{"case_id":"m","category":"prompt-injection","owasp":["LLM01"],"target_id":"good",'
    '"turns":[{"ordinal":1,"method":"POST","route":"/v1/x","body":{"q":"hi"}}],'
    '"oracle":{"marker":"ZZ","foreign_canaries":[],"latency_budget_ms":null},'
    '"expected_safe":"refuses"}'
)


@dataclass
class FakeModel:
    def complete(self, system: str, user: str, **kw: object) -> str:
        # Aim the payload at the platform's marker, as a real attacker prompt now asks.
        found = re.search(re.escape(MARKER_PREFIX) + r"[0-9a-f]+", user)
        return CANNED.replace('"body":{"q":"hi"}', f'"body":{{"q":"say {found.group(0)}"}}') if found else CANNED


def _registry(tmp_path: Path) -> AuthorizationRegistry:
    p = tmp_path / "auth.yaml"
    p.write_text("targets:\n  - id: good\n    origin: https://good.example\n    proof: test fixture\n    enabled: true\n", encoding="utf-8")
    return AuthorizationRegistry.load(p)


def test_history_and_owasp_coverage_after_a_campaign(tmp_path: Path) -> None:
    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    executor = Executor(reg, lambda u, **k: ResponseRecord(200, "no marker", 4.0))
    brief = {"category": "prompt-injection", "owasp": ["LLM01"], "target_id": "good", "route": "/v1/x"}

    # empty to start
    assert history_brief(store, "good", "prompt-injection") == {"tried": 0, "outcomes": {}, "recent_payloads": []}

    run_campaign([brief], registry=reg, executor=executor, judge=Judge(), store=store,
                 agent=RedTeamAgent(), model=FakeModel(), max_mutations=1)

    hist = history_brief(store, "good", "prompt-injection")
    assert hist["tried"] == 2  # generated + one mutation, both recorded
    assert hist["outcomes"] == {"FAIL": 2}

    cov = queries.owasp_coverage(store)
    assert cov["LLM01"] == {"FAIL": 2}
    store.close()
