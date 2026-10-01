"""The CLI parses commands and runs the safe ones without any network or key."""

from __future__ import annotations

from pathlib import Path

import pytest

from redteam.cli import build_parser, main
from redteam.store.store import Store


def test_report_runs_on_a_store(tmp_path: Path, capsys) -> None:
    db = tmp_path / "s.db"
    Store.open(db).close()  # create an empty, migrated store
    rc = main(["--store", str(db), "report"])
    assert rc == 0
    assert "Red Team — status" in capsys.readouterr().out


def test_parser_requires_a_command() -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args([])


def test_campaign_maps_categories_to_owasp() -> None:
    args = build_parser().parse_args(
        ["campaign", "--target", "agentforge-w2", "--category", "prompt-injection", "--route", "/v1/x"]
    )
    assert args.category == ["prompt-injection"]
    assert args.route == ["/v1/x"]
    assert args.max_campaigns == 5


# --- integrity (read-only) -------------------------------------------------------------------

def _half_written_store(db: Path) -> None:
    """One complete attempt + one without a verdict; one frozen finding + one never frozen."""
    store = Store.open(db)
    with store.transaction():
        for a in ("att-ok", "att-orphan"):
            store.insert("attempts", {"attempt_id": a, "target_id": "t", "started_at": "2026-10-01"})
        store.insert("verdicts", {"verdict_id": "ver-ok", "attempt_id": "att-ok", "outcome": "FAIL",
                                  "judged_at": "2026-10-01"})
        for f in ("F-frozen", "F-unfrozen"):
            store.insert("findings", {"finding_id": f, "title": "t", "status": "new", "updated_at": "2026-10-01"})
        store.insert("regression_cases", {"case_id": "reg-1", "finding_id": "F-frozen", "frozen_at": "2026-10-01"})
    store.close()


def test_integrity_reports_half_written_units_and_never_writes(tmp_path: Path, capsys) -> None:
    db = tmp_path / "s.db"
    _half_written_store(db)
    before = db.read_bytes()
    rc = main(["--store", str(db), "integrity"])
    out = capsys.readouterr().out
    assert rc == 1                                             # attention: never a silent pass
    assert "attempts_without_verdict=1 findings_without_regression_case=1 -> ATTENTION" in out
    assert "att-orphan" in out and "F-unfrozen" in out
    assert "att-ok" not in out and "F-frozen" not in out
    assert db.read_bytes() == before                           # read-only: the file is untouched


def test_integrity_is_ok_on_a_clean_store(tmp_path: Path, capsys) -> None:
    db = tmp_path / "s.db"
    Store.open(db).close()
    assert main(["--store", str(db), "integrity"]) == 0
    assert "-> OK" in capsys.readouterr().out


def test_integrity_never_creates_a_missing_store(tmp_path: Path) -> None:
    import sqlite3

    db = tmp_path / "absent.db"
    with pytest.raises(sqlite3.OperationalError):
        main(["--store", str(db), "integrity"])
    assert not db.exists()


def test_a_readonly_store_refuses_writes(tmp_path: Path) -> None:
    import sqlite3

    db = tmp_path / "s.db"
    _half_written_store(db)
    store = Store.open_readonly(db)
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        store.insert("agent_actions", {"ts": "2026-10-01", "agent": "x", "action": "y"})
    store.close()