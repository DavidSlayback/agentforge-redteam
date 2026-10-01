"""The Documentation agent enforces required fields BEFORE writing any report: severity, attack
category, reproduction steps, observed behavior, expected behavior, unique identifier, and no
duplicate attack sequence. A refused finding raises a typed, named DataQualityError and leaves
the store untouched. (Complements tests/test_data_quality.py, which covers finding dedup.)"""

from __future__ import annotations

from pathlib import Path

import pytest

from redteam.agents.documentation.agent import DataQualityError, DocumentationAgent
from redteam.agents.judge.judge import Judge
from redteam.cli import main
from redteam.evals.case import OracleConfig, SeedCase, Turn
from redteam.executor.authorization import AuthorizationRegistry
from redteam.executor.executor import Executor
from redteam.executor.http_sender import ResponseRecord
from redteam.runner import run_case
from redteam.store.store import Store

_MARK = "ZZ-DQ"


def _documented_store(tmp_path: Path) -> tuple[Store, str]:
    p = tmp_path / "auth.yaml"
    p.write_text("targets:\n  - id: good\n    origin: https://good.example\n    proof: t\n    enabled: true\n",
                 encoding="utf-8")
    reg = AuthorizationRegistry.load(p)
    store = Store.open(tmp_path / "s.db")
    case = SeedCase(case_id="c1", category="prompt-injection", owasp=["LLM01"], target_id="good",
                    turns=[Turn(ordinal=1, route="/v1/x", body={})], oracle=OracleConfig(marker=_MARK),
                    expected_safe="refuses; never emits the marker")
    run_case(case, reg, Executor(reg, lambda u, **k: ResponseRecord(200, f"ok {_MARK}", 4.0)), Judge(), store)
    fid = store.conn.execute("SELECT finding_id FROM findings").fetchone()["finding_id"]
    return store, fid


def _nothing_written(store: Store) -> bool:
    return (store.count("vuln_reports") == 0 and not store.conn.execute(
        "SELECT 1 FROM agent_actions WHERE agent = 'documentation'").fetchone())


def test_a_complete_finding_is_documented(tmp_path: Path) -> None:
    store, fid = _documented_store(tmp_path)
    assert DocumentationAgent().document(store, fid)
    assert store.count("vuln_reports") == 1
    store.close()


@pytest.mark.parametrize("sql, reason", [
    ("UPDATE findings SET primary_category = '' WHERE finding_id = ?", "missing_attack_category"),
    ("UPDATE findings SET severity = NULL WHERE finding_id = ?", "missing_severity"),
    ("UPDATE findings SET severity = '{\"note\": \"no level\"}' WHERE finding_id = ?", "missing_severity"),
    ("UPDATE findings SET severity = 'not json' WHERE finding_id = ?", "missing_severity"),
    ("UPDATE findings SET dedup_key = '' WHERE finding_id = ?", "missing_unique_identifier"),
])
def test_a_finding_missing_a_required_field_is_refused_with_a_named_reason(
        tmp_path: Path, sql: str, reason: str) -> None:
    store, fid = _documented_store(tmp_path)
    with store.transaction():
        store.execute(sql, (fid,))
    with pytest.raises(DataQualityError) as exc:
        DocumentationAgent().document(store, fid)
    assert reason in exc.value.reasons
    assert reason in str(exc.value)
    assert _nothing_written(store)
    store.close()


def test_no_captured_exchange_means_no_reproduction_and_no_observed_behavior(tmp_path: Path) -> None:
    store, fid = _documented_store(tmp_path)
    with store.transaction():
        store.execute("UPDATE findings SET verdict_ids = '[]' WHERE finding_id = ?", (fid,))
    with pytest.raises(DataQualityError) as exc:
        DocumentationAgent().document(store, fid)
    assert {"missing_reproduction_steps", "missing_observed_behavior"} <= set(exc.value.reasons)
    assert _nothing_written(store)
    store.close()


def test_a_spec_without_an_expected_safe_invariant_is_refused(tmp_path: Path) -> None:
    store, fid = _documented_store(tmp_path)
    with store.transaction():
        store.execute("UPDATE attack_specs SET expected_safe_ref = NULL WHERE 1 = ?", (1,))
    with pytest.raises(DataQualityError) as exc:
        DocumentationAgent().document(store, fid)
    assert exc.value.reasons == ["missing_expected_behavior"]
    assert _nothing_written(store)
    store.close()


def test_every_missing_field_is_reported_together(tmp_path: Path) -> None:
    store, fid = _documented_store(tmp_path)
    with store.transaction():
        store.execute("UPDATE findings SET severity = NULL, primary_category = '' WHERE finding_id = ?", (fid,))
    with pytest.raises(DataQualityError) as exc:
        DocumentationAgent().document(store, fid)
    assert {"missing_severity", "missing_attack_category"} <= set(exc.value.reasons)
    store.close()


def test_a_second_finding_with_the_same_attack_sequence_is_refused(tmp_path: Path) -> None:
    store, fid = _documented_store(tmp_path)
    doc = DocumentationAgent()
    first_report = doc.document(store, fid)
    row = dict(store.conn.execute("SELECT * FROM findings WHERE finding_id = ?", (fid,)).fetchone())
    with store.transaction():   # a distinct finding row backed by the very same evidence
        store.insert("findings", {**row, "finding_id": "F-dup", "dedup_key": "other-key"})
    with pytest.raises(DataQualityError) as exc:
        doc.document(store, "F-dup")
    assert exc.value.reasons == ["duplicate_attack_sequence"]
    assert fid in str(exc.value)                      # names the finding it duplicates
    assert store.count("vuln_reports") == 1           # only the first report exists
    assert doc.document(store, fid) == first_report   # re-documenting the SAME finding stays idempotent
    store.close()


def test_data_quality_error_is_a_value_error() -> None:
    assert issubclass(DataQualityError, ValueError)


def test_document_cli_reports_the_refusal_and_exits_nonzero(tmp_path: Path, capsys) -> None:
    store, fid = _documented_store(tmp_path)
    with store.transaction():
        store.execute("UPDATE findings SET severity = NULL WHERE finding_id = ?", (fid,))
    store.close()
    rc = main(["--store", str(tmp_path / "s.db"), "document", fid])
    err = capsys.readouterr().err
    assert rc == 1 and "missing_severity" in err
