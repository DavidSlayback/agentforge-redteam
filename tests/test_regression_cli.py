"""`redteam regression` replays frozen deterministic cases: no attacker-model key needed."""

from __future__ import annotations

from pathlib import Path

from redteam.cli import main
from redteam.evals.case import OracleConfig, SeedCase, Turn
from redteam.executor.http_sender import ResponseRecord
from redteam.regression import freeze
from redteam.store.store import Store

_ATTACKER_ENV = ("AGENTFORGE_REDTEAM_BASE_URL", "AGENTFORGE_REDTEAM_API_KEY", "AGENTFORGE_REDTEAM_MODEL",
                 "AGENTFORGE_REDTEAM_RUBRIC_BASE_URL", "AGENTFORGE_REDTEAM_RUBRIC_KEY",
                 "AGENTFORGE_REDTEAM_RUBRIC_MODEL")


def _env(monkeypatch, tmp_path: Path, response_text: str) -> Path:
    for name in _ATTACKER_ENV:
        monkeypatch.delenv(name, raising=False)
    (tmp_path / "authorization.yaml").write_text(
        "targets:\n  - id: good\n    origin: https://good.example\n    proof: t\n    enabled: true\n",
        encoding="utf-8")
    monkeypatch.chdir(tmp_path)   # no .env here, so nothing re-populates the unset variables
    monkeypatch.setattr("redteam.executor.http_sender.http_sender",
                        lambda url, **k: ResponseRecord(200, response_text, 3.0))
    return tmp_path / "s.db"


def _freeze_case(db: Path, oracle: OracleConfig) -> None:
    case = SeedCase(case_id="c1", category="prompt-injection", owasp=["LLM01"], target_id="good",
                    turns=[Turn(ordinal=1, route="/v1/x", body={})], oracle=oracle, expected_safe="refuses")
    store = Store.open(db)
    with store.transaction():
        store.insert("findings", {"finding_id": "F-1", "title": "t", "status": "new", "dedup_key": "k",
                                  "updated_at": "2026-10-01"})
    with store.transaction():
        store.insert("attack_specs", {"spec_id": "c1", "category": case.category, "created_at": "2026-10-01"})
    with store.transaction():
        freeze(store, "F-1", case)
    store.close()


def test_regression_runs_without_attacker_model_keys(tmp_path: Path, monkeypatch, capsys) -> None:
    db = _env(monkeypatch, tmp_path, "refused")
    _freeze_case(db, OracleConfig(marker="ZZ-MARK"))
    rc = main(["--store", str(db), "regression", "--target", "good", "--sha", "abc"])
    assert rc == 0 and "held=1" in capsys.readouterr().out


def test_regression_reappearance_still_fails_the_gate_without_keys(tmp_path: Path, monkeypatch, capsys) -> None:
    db = _env(monkeypatch, tmp_path, "here is ZZ-MARK")
    _freeze_case(db, OracleConfig(marker="ZZ-MARK"))
    rc = main(["--store", str(db), "regression", "--target", "good", "--sha", "abc"])
    assert rc == 1 and "reappeared=1" in capsys.readouterr().out


def test_regression_rubric_dependent_case_is_inconclusive_not_a_crash_without_keys(
        tmp_path: Path, monkeypatch, capsys) -> None:
    db = _env(monkeypatch, tmp_path, "an ordinary answer")
    _freeze_case(db, OracleConfig())   # no deterministic oracle applies: only a rubric could decide
    rc = main(["--store", str(db), "regression", "--target", "good", "--sha", "abc"])
    out = capsys.readouterr().out
    assert rc == 1 and "inconclusive=1" in out and "held=0" in out


def test_regression_cli_reports_the_typed_error_code_on_reappearance(tmp_path: Path, monkeypatch, capsys) -> None:
    db = _env(monkeypatch, tmp_path, "here is ZZ-MARK")
    _freeze_case(db, OracleConfig(marker="ZZ-MARK"))
    rc = main(["--store", str(db), "regression", "--target", "good", "--sha", "abc"])
    assert rc == 1
    assert "regression_detected" in capsys.readouterr().err
