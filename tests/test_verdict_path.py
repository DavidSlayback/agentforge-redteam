"""Characterization of the deterministic probes' persisted verdicts (refactor 1/4, one verdict path).

Each test drives a probe end to end through its public builder and the shared driver, against a
fake sender and a temporary store, and pins what reaches the store: the verdict outcome, the
oracle name, and the finding's dedup key. Reason text is not asserted (it is the Judge's wording).
The frozen-case round trips pin that regression replay rebuilds each probe kind faithfully.
"""

from __future__ import annotations

import json
from pathlib import Path

from redteam.agents.judge.judge import Judge
from redteam.authz_probe import (
    contradiction_probe,
    disclosure_probe,
    dos_probe,
    enumeration_probe,
    grounding_probe,
    rate_limit_probe,
    run_probe,
    run_rate_limit_probe,
    _OFF_CONDITION_QUERIES,
)
from redteam.executor.authorization import AuthorizationRegistry
from redteam.executor.executor import Executor
from redteam.executor.http_sender import ResponseRecord
from redteam.regression import replay
from redteam.store.store import Store

PATIENT = "fixture-patient-001"
TRACE = "Traceback (most recent call last): boom"


def _registry(tmp_path: Path) -> AuthorizationRegistry:
    p = tmp_path / "auth.yaml"
    p.write_text("targets:\n  - id: good\n    origin: https://good.example\n    proof: test fixture\n    enabled: true\n",
                 encoding="utf-8")
    return AuthorizationRegistry.load(p)


class _Minter:
    def auth_fields(self, patient_uuid: str) -> dict:
        return {"patient_uuid": patient_uuid, "clinician_uuid": "c", "demo_token": "t"}


def _fixed(status: int, text: str, latency_ms: float = 2.0):
    return lambda u, **k: ResponseRecord(status, text, latency_ms)


def _persisted(store: Store, attempt_id: str) -> tuple[str, dict[str, str]]:
    """(verdict outcome, {oracle name: oracle outcome}) as stored for one attempt."""
    row = store.conn.execute("SELECT outcome, oracle_results FROM verdicts WHERE attempt_id = ?",
                             (attempt_id,)).fetchone()
    return row["outcome"], {r["oracle"]: r["outcome"] for r in json.loads(row["oracle_results"])}


def _detail(store: Store, attempt_id: str, oracle: str) -> str:
    row = store.conn.execute("SELECT oracle_results FROM verdicts WHERE attempt_id = ?", (attempt_id,)).fetchone()
    return next(r["detail"] for r in json.loads(row["oracle_results"]) if r["oracle"] == oracle)


def _dedup_keys(store: Store) -> list[str]:
    return [r["dedup_key"] for r in store.conn.execute("SELECT dedup_key FROM findings")]


def _facts(*pairs) -> str:
    return json.dumps({"status": "ready",
                       "patient_facts": [{"field": f, "value": v, "current": c} for f, v, c in pairs]})


CONFLICT = _facts(("medication.lisinopril.dose", "5 mg", None), ("medication.lisinopril.dose", "10 mg", None))
RECONCILED = _facts(("medication.lisinopril.dose", "5 mg", False), ("medication.lisinopril.dose", "10 mg", True))


# ---- rate limit ------------------------------------------------------------------------------

def test_rate_limit_open_persists_a_rate_limit_finding(tmp_path: Path) -> None:
    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    res = run_rate_limit_probe(reg, Executor(reg, _fixed(200, '{"demo_token":"x"}')), Judge(), store,
                               reg.by_id("good"), PATIENT, n=4)
    assert _persisted(store, res.attempt_id) == ("SUCCESS", {"rate_limit": "violation"})
    assert _dedup_keys(store) == ["rate_limit:/v1/demo-context:denial-of-service"]
    store.close()


def test_rate_limit_throttled_persists_a_held_defense(tmp_path: Path) -> None:
    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    res = run_rate_limit_probe(reg, Executor(reg, _fixed(429, "slow down")), Judge(), store,
                               reg.by_id("good"), PATIENT, n=4)
    assert _persisted(store, res.attempt_id) == ("FAIL", {"rate_limit": "safe"})
    assert _dedup_keys(store) == []
    store.close()


# ---- enumeration -----------------------------------------------------------------------------

def _enumerate(tmp_path: Path, sender):
    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    res = run_probe(enumeration_probe(Executor(reg, sender), Judge(), reg.by_id("good")), store, reg)
    return store, res


def test_enumeration_issued_persists_an_enumeration_finding(tmp_path: Path) -> None:
    store, res = _enumerate(tmp_path, _fixed(200, '{"demo_token":"x","expires_in_seconds":300}'))
    outcome, oracles = _persisted(store, res.attempt_id)
    assert outcome == "SUCCESS" and oracles["enumeration"] == "violation"
    assert _dedup_keys(store) == ["enumeration:/v1/demo-context:enumeration"]
    store.close()


def test_enumeration_uniform_refusal_is_a_held_defense(tmp_path: Path) -> None:
    store, res = _enumerate(tmp_path, _fixed(400, '{"error":"invalid_synthetic_patient"}'))
    outcome, oracles = _persisted(store, res.attempt_id)
    assert outcome == "FAIL" and oracles["enumeration"] == "safe"
    assert _dedup_keys(store) == []
    store.close()


def test_enumeration_200_without_a_credential_is_inconclusive(tmp_path: Path) -> None:
    store, res = _enumerate(tmp_path, _fixed(200, '{"status":"ok"}'))
    outcome, oracles = _persisted(store, res.attempt_id)
    assert outcome == "INCONCLUSIVE" and "enumeration" in oracles
    assert _dedup_keys(store) == []
    store.close()


def test_enumeration_crash_with_a_trace_is_not_a_finding(tmp_path: Path) -> None:
    # The probe is judged by its own oracle only: a 5xx or a leaked trace is not a second finding.
    store, res = _enumerate(tmp_path, _fixed(500, TRACE))
    assert _persisted(store, res.attempt_id)[0] == "INCONCLUSIVE"
    assert _dedup_keys(store) == []
    store.close()


# ---- contradiction ---------------------------------------------------------------------------

def _contradict(tmp_path: Path, sender):
    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    res = run_probe(contradiction_probe(Executor(reg, sender), Judge(), _Minter(), reg.by_id("good"), PATIENT),
                    store, reg)
    return store, res


def test_contradiction_conflict_persists_a_data_integrity_finding(tmp_path: Path) -> None:
    store, res = _contradict(tmp_path, _fixed(200, CONFLICT))
    outcome, oracles = _persisted(store, res.attempt_id)
    assert outcome == "SUCCESS" and oracles["contradiction"] == "violation"
    assert _dedup_keys(store) == ["contradiction:/v1/follow-up-evidence:data-integrity"]
    store.close()


def test_contradiction_reconciled_chart_is_a_held_defense(tmp_path: Path) -> None:
    store, res = _contradict(tmp_path, _fixed(200, RECONCILED))
    outcome, oracles = _persisted(store, res.attempt_id)
    assert outcome == "FAIL" and oracles["contradiction"] == "safe"
    store.close()


def test_contradiction_unparseable_or_non_object_200_is_inconclusive(tmp_path: Path) -> None:
    for i, body in enumerate(("not json", "[1, 2]", '"a string"', '{"patient_facts": ["x"]}')):
        run_dir = tmp_path / str(i)
        run_dir.mkdir()
        store, res = _contradict(run_dir, _fixed(200, body))
        outcome, oracles = _persisted(store, res.attempt_id)
        assert outcome == "INCONCLUSIVE" and "contradiction" in oracles, body
        assert _dedup_keys(store) == []
        store.close()


def test_contradiction_empty_fact_list_is_inconclusive(tmp_path: Path) -> None:
    # D5: an empty chart may never have been retrieved; it is not a reconciled chart (was FAIL).
    for i, body in enumerate(({"status": "ready", "patient_facts": []}, {"status": "ready"})):
        run_dir = tmp_path / str(i)
        run_dir.mkdir()
        store, res = _contradict(run_dir, _fixed(200, json.dumps(body)))
        assert _persisted(store, res.attempt_id)[0] == "INCONCLUSIVE", body
        store.close()


def test_contradiction_crash_is_not_a_finding(tmp_path: Path) -> None:
    store, res = _contradict(tmp_path, _fixed(503, TRACE))
    assert _persisted(store, res.attempt_id)[0] == "INCONCLUSIVE"
    assert _dedup_keys(store) == []
    store.close()


# ---- frozen-case regression rebuild, per probe kind ------------------------------------------

def _round_trip(tmp_path: Path, build, open_sender, fixed_sender, oracle: str, key: str) -> None:
    """Run a probe against an open build (freezes a finding), then replay it against the same
    open build (reappears, same finding) and a fixed build (holds)."""
    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    first = run_probe(build(Executor(reg, open_sender), reg.by_id("good")), store, reg)
    assert _persisted(store, first.attempt_id)[1][oracle] == "violation"
    assert _dedup_keys(store) == [key] and store.count("regression_cases") == 1

    reopened = replay(store, reg, Executor(reg, open_sender), Judge(), "sha-open", minter=_Minter())
    assert reopened.reappeared and not reopened.held
    assert _dedup_keys(store) == [key]                       # the replay re-fired the same oracle

    fixed = replay(store, reg, Executor(reg, fixed_sender), Judge(), "sha-fixed", minter=_Minter())
    assert fixed.held and fixed.ok
    store.close()


def test_rate_limit_replays_from_its_frozen_case(tmp_path: Path) -> None:
    _round_trip(tmp_path, lambda ex, t: rate_limit_probe(ex, Judge(), t, PATIENT, n=3),
                _fixed(200, '{"demo_token":"x"}'), _fixed(429, "slow down"),
                "rate_limit", "rate_limit:/v1/demo-context:denial-of-service")


def test_enumeration_replays_from_its_frozen_case(tmp_path: Path) -> None:
    _round_trip(tmp_path, lambda ex, t: enumeration_probe(ex, Judge(), t),
                _fixed(200, '{"demo_token":"x"}'), _fixed(400, '{"error":"invalid_synthetic_patient"}'),
                "enumeration", "enumeration:/v1/demo-context:enumeration")


def test_contradiction_replays_from_its_frozen_case(tmp_path: Path) -> None:
    _round_trip(tmp_path, lambda ex, t: contradiction_probe(ex, Judge(), _Minter(), t, PATIENT),
                _fixed(200, CONFLICT), _fixed(200, RECONCILED),
                "contradiction", "contradiction:/v1/follow-up-evidence:data-integrity")


def _grounding_body(qualified: bool) -> str:
    return json.dumps({"status": "ready",
                       "patient_facts": [{"field": "problem.hypertension.status", "value": "active"}],
                       "guideline_evidence": [{"title": "x"}],
                       "qualification": {"required": qualified, "reasons": []}})


def test_grounding_replays_from_its_frozen_case(tmp_path: Path) -> None:
    condition, query = _OFF_CONDITION_QUERIES[0]
    _round_trip(tmp_path, lambda ex, t: grounding_probe(ex, Judge(), _Minter(), t, PATIENT, query, condition),
                _fixed(200, _grounding_body(False)), _fixed(200, _grounding_body(True)),
                "grounding", "grounding:/v1/follow-up-evidence:misinformation")


def test_disclosure_replays_from_its_frozen_case(tmp_path: Path) -> None:
    _round_trip(tmp_path, lambda ex, t: disclosure_probe(ex, Judge(), _Minter(), t, PATIENT),
                _fixed(200, '{"answer":"ok","guideline_provider":"x"}'), _fixed(200, '{"answer":"ok"}'),
                "metadata_disclosure", "metadata_disclosure:/v1/follow-up-evidence:information-disclosure")


def test_oversized_input_replays_from_its_frozen_case(tmp_path: Path) -> None:
    _round_trip(tmp_path, lambda ex, t: dos_probe(ex, Judge(), _Minter(), t, PATIENT, size=1000,
                                                  latency_budget_ms=5000.0),
                _fixed(200, "ok", latency_ms=9000.0), _fixed(200, "ok", latency_ms=50.0),
                "status", "status:/v1/follow-up-evidence:denial-of-service")


# ---- guard: one verdict path ------------------------------------------------------------------

_SRC = Path(__file__).resolve().parents[1] / "src" / "redteam"
_VERDICT_OWNERS = (_SRC / "agents" / "judge", _SRC / "oracles")
_GUARDED = {"Verdict", "OracleResult"}


def _hand_built(source: str) -> list[int]:
    """Line numbers where `source` constructs a Verdict or an OracleResult."""
    import ast

    lines = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call):
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else None
            if name in _GUARDED:
                lines.append(node.lineno)
    return lines


def test_only_the_judge_package_and_the_oracles_build_verdicts() -> None:
    # Every verdict comes from the Judge composing oracle results, or from judge.no_evidence.
    assert _hand_built("v = judge.Verdict(VerdictOutcome.FAIL, ())\nr = OracleResult('x', 0, o)") == [1, 2]
    offenders = {}
    for path in _SRC.rglob("*.py"):
        if any(owner in path.parents for owner in _VERDICT_OWNERS):
            continue
        hits = _hand_built(path.read_text(encoding="utf-8"))
        if hits:
            offenders[str(path.relative_to(_SRC))] = hits
    assert offenders == {}, f"build verdicts through the Judge or judge.no_evidence: {offenders}"


# ---- a set-aside result keeps the probe oracle's own detail ----------------------------------

def test_non_answer_paths_keep_the_oracle_detail(tmp_path: Path) -> None:
    # On a response that is not an answer the Judge records the oracle as not applicable, but
    # the stored detail must still say what the oracle saw (e.g. the throttle on a 429).
    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    target = reg.by_id("good")
    cases = [
        (enumeration_probe(Executor(reg, _fixed(429, "slow down")), Judge(), target),
         "enumeration", "status 429; likely rate-limited"),
        (contradiction_probe(Executor(reg, _fixed(429, "slow down")), Judge(), _Minter(), target, PATIENT),
         "contradiction", "status 429"),
        (rate_limit_probe(Executor(reg, _fixed(404, "{}")), Judge(), target, PATIENT, n=3),
         "rate_limit", "no 429 but non-2xx seen"),
        (rate_limit_probe(Executor(reg, _fixed(200, "{}")), Judge(), target, PATIENT, n=0),
         "rate_limit", "no requests sent"),
    ]
    for probe, oracle, expected in cases:
        res = run_probe(probe, store, reg)
        assert _persisted(store, res.attempt_id) == ("INCONCLUSIVE", {oracle: "not_applicable"}), oracle
        assert expected in _detail(store, res.attempt_id, oracle), oracle
    store.close()
