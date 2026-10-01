"""Contract tests for the versioned inter-agent schemas in /contracts/v1.

Three checks per the contracts README:
1. every schema is a valid Draft 2020-12 schema;
2. a REAL record the code produces (from a live run_case that promotes a finding, plus a
   rendered vuln report and each typed error) validates against its schema — parsing the
   JSON columns the store persists, so the actual shapes are checked;
3. a deliberately malformed record is rejected (a contract that accepts everything is no test).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

from redteam.agents.documentation.agent import DocumentationAgent
from redteam.agents.judge.judge import Judge
from redteam.errors import (AuthorizationDenied, BudgetExceeded, JudgeTimeout, NoFindingsInWindow,
                            ProviderBlock, RegressionDetected, TargetUnreachable)
from redteam.evals.case import OracleConfig, SeedCase, Turn
from redteam.executor.authorization import AuthorizationRegistry
from redteam.executor.executor import Executor
from redteam.executor.http_sender import ResponseRecord
from redteam.runner import run_case
from redteam.store.store import Store

CONTRACTS = Path(__file__).resolve().parents[1] / "contracts" / "v1"
MARK = "ZZ-ECHO"


def _schema(name: str) -> dict:
    return json.loads((CONTRACTS / f"{name}.schema.json").read_text(encoding="utf-8"))


def _row(store, sql: str) -> dict:
    return dict(store.conn.execute(sql).fetchone())


@pytest.fixture
def live(tmp_path: Path):
    """A store after one SUCCESS attempt, so every downstream record actually exists."""
    p = tmp_path / "auth.yaml"
    p.write_text("targets:\n  - id: good\n    origin: https://good.example\n    proof: test fixture\n    enabled: true\n", encoding="utf-8")
    reg = AuthorizationRegistry.load(p)
    store = Store.open(tmp_path / "s.db")
    case = SeedCase(case_id="c1", category="prompt-injection", owasp=["LLM01"], target_id="good",
                    turns=[Turn(ordinal=1, route="/v1/x", body={"message": "hi"})],
                    oracle=OracleConfig(marker=MARK), expected_safe="never emits the marker")
    run_case(case, reg, Executor(reg, lambda u, **k: ResponseRecord(200, f"ok {MARK}", 4.0)), Judge(), store)
    yield store
    store.close()


def test_every_schema_is_valid() -> None:
    files = list(CONTRACTS.glob("*.schema.json"))
    assert len(files) == 7, f"expected 7 contract schemas, found {len(files)}"
    for f in files:
        Draft202012Validator.check_schema(json.loads(f.read_text(encoding="utf-8")))


def test_attack_spec_conforms(live) -> None:
    r = _row(live, "SELECT * FROM attack_specs LIMIT 1")
    msg = {"schema_version": r["schema_version"], "spec_id": r["spec_id"], "category": r["category"],
           "target_route": r["target_route"], "turns": json.loads(r["turns"]),
           "owasp": json.loads(r["owasp"]), "expected_safe_ref": r["expected_safe_ref"]}
    Draft202012Validator(_schema("attack_spec")).validate(msg)


def test_attempt_conforms(live) -> None:
    r = _row(live, "SELECT * FROM attempts LIMIT 1")
    msg = {"schema_version": r["schema_version"], "attempt_id": r["attempt_id"], "spec_id": r["spec_id"],
           "target_id": r["target_id"], "target_env": r["target_env"],
           "exchanges": json.loads(r["exchanges"]), "provider_events": json.loads(r["provider_events"]),
           "evidence_ref": r["evidence_ref"]}
    Draft202012Validator(_schema("attempt")).validate(msg)


def test_verdict_conforms(live) -> None:
    r = _row(live, "SELECT * FROM verdicts LIMIT 1")
    msg = {"schema_version": r["schema_version"], "verdict_id": r["verdict_id"], "attempt_id": r["attempt_id"],
           "outcome": r["outcome"], "oracle_results": json.loads(r["oracle_results"]),
           "evidence_ref": r["evidence_ref"], "judged_at": r["judged_at"]}
    Draft202012Validator(_schema("verdict")).validate(msg)


def test_finding_conforms(live) -> None:
    r = _row(live, "SELECT * FROM findings LIMIT 1")
    msg = {"schema_version": r["schema_version"], "finding_id": r["finding_id"], "title": r["title"],
           "taxonomy": json.loads(r["taxonomy"]), "primary_category": r["primary_category"],
           "severity": json.loads(r["severity"]), "severity_score": r["severity_score"],
           "component": r["component"], "status": r["status"],
           "verdict_ids": json.loads(r["verdict_ids"]), "dedup_key": r["dedup_key"]}
    Draft202012Validator(_schema("finding")).validate(msg)


def test_vuln_report_conforms(live) -> None:
    finding_id = live.conn.execute("SELECT finding_id FROM findings LIMIT 1").fetchone()["finding_id"]
    DocumentationAgent().document(live, finding_id)
    r = _row(live, "SELECT * FROM vuln_reports LIMIT 1")
    msg = {"schema_version": r["schema_version"], "report_id": r["report_id"], "finding_id": r["finding_id"],
           "severity": json.loads(r["severity"]), "description": r["description"],
           "clinical_impact": r["clinical_impact"], "repro": json.loads(r["repro"]),
           "observed_vs_expected": r["observed_vs_expected"], "remediation": r["remediation"],
           "status": r["status"], "fix_validation": json.loads(r["fix_validation"]),
           "approval": json.loads(r["approval"])}
    Draft202012Validator(_schema("vuln_report")).validate(msg)


def test_campaign_conforms() -> None:
    # NOTE: Campaign has no persisting producer yet (the Orchestrator passes a brief + campaign_id
    # to run_campaign and logs agent_actions; it does not write a Campaign row). This validates a
    # HAND-BUILT instance of the intended shape — the contract is defined but "wired: no". The
    # other five messages above are validated against REAL persisted records.
    msg = {"schema_version": 1, "campaign_id": "orch-1", "target_id": "agentforge-w2",
           "category": ["prompt-injection"], "status": "running",
           "budget": {"max_campaigns": 5, "max_no_signal": 5},
           "selector": {"jev_version": None, "chosen": "brief-0"}}
    Draft202012Validator(_schema("campaign")).validate(msg)


def test_typed_errors_conform() -> None:
    schema = _schema("error")
    errors = [TargetUnreachable("x"), AuthorizationDenied("https://nope"), BudgetExceeded("x"),
              JudgeTimeout("x"), NoFindingsInWindow("x"), RegressionDetected("x"), ProviderBlock("x")]
    seen_codes = set()
    for exc in errors:
        msg = {"schema_version": 1, "code": exc.code, "message": str(exc), "retriable": exc.retriable}
        Draft202012Validator(schema).validate(msg)
        seen_codes.add(exc.code)
    # every code the schema enumerates must be produced by a real error class (and vice versa)
    assert seen_codes == set(schema["properties"]["code"]["enum"])


# One malformed instance per schema, so every contract is shown to be able to REJECT — a
# schema that accepts everything tests nothing. Each violates a specific constraint.
_BAD = {
    "verdict": {"schema_version": 1, "verdict_id": "v", "attempt_id": "a",
                "outcome": "DEFINITELY_PWNED", "oracle_results": [], "judged_at": "now"},   # outcome enum
    "attempt": {"schema_version": 1, "attempt_id": "a", "spec_id": "s", "target_id": "t",
                "target_env": "prod", "exchanges": []},                                     # target_env enum
    "finding": {"schema_version": 1, "finding_id": "f", "title": "t", "primary_category": "c",
                "severity": {"provisional_level": "SEV1"}, "status": "new", "dedup_key": "k"},  # level enum
    "vuln_report": {"schema_version": 1, "report_id": "r", "finding_id": "f", "status": "approved"},  # status enum
    "campaign": {"schema_version": 1, "campaign_id": "c", "target_id": "t",
                 "category": ["x"], "status": "invented"},                                  # status enum
    "error": {"schema_version": 1, "code": "boom", "message": "m", "retriable": False},      # code enum
    "attack_spec": {"schema_version": 1, "spec_id": "s", "category": "c",
                    "target_route": "/r", "turns": []},                                     # turns minItems
}


@pytest.mark.parametrize("name", sorted(_BAD))
def test_negative_control_rejects_malformed(name: str) -> None:
    with pytest.raises(ValidationError):
        Draft202012Validator(_schema(name)).validate(_BAD[name])
