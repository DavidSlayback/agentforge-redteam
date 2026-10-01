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


def test_campaign_rejects_an_undeclared_route_before_any_work(tmp_path: Path, monkeypatch, capsys) -> None:
    # A route that is not one of the declared routes (a typo, or a shell that rewrote `/v1/x` into
    # a filesystem path) is a configuration error: the command fails fast (exit 2), names the bad
    # route, and never builds the store or the attacker model (no key needed).
    def _boom(*a, **k):
        raise AssertionError("_wire must not run when a route is undeclared")

    monkeypatch.setattr("redteam.cli._wire", _boom)
    rc = main(["campaign", "--target", "agentforge-w2", "--category", "prompt-injection",
               "--route", "C:/Program Files/Git/v1/x"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "configuration error" in err and "C:/Program Files/Git/v1/x" in err


# --- campaign exit-code policy (owner decision 5) --------------------------------------------

def _patch_wire(monkeypatch, tmp_path: Path, model) -> None:
    from redteam.agents.judge.judge import Judge
    from redteam.agents.redteam.agent import RedTeamAgent
    from redteam.executor.authorization import AuthorizationRegistry
    from redteam.executor.executor import Executor
    from redteam.executor.http_sender import ResponseRecord

    p = tmp_path / "auth.yaml"
    p.write_text("targets:\n  - id: good\n    origin: https://good.example\n    proof: t\n    enabled: true\n",
                 encoding="utf-8")
    reg = AuthorizationRegistry.load(p)
    executor = Executor(reg, lambda u, **k: ResponseRecord(200, "no marker here", 5.0))
    pieces = (reg, reg.by_id("good"), executor, None, Judge(), RedTeamAgent(), model)
    monkeypatch.setattr("redteam.cli._wire", lambda *a, **k: pieces)


_GEN = ('{"case_id":"x","category":"prompt-injection","owasp":["LLM01"],"target_id":"good",'
        '"turns":[{"ordinal":1,"method":"POST","route":"/v1/follow-up-evidence","body":{"message":"hi"}}],'
        '"oracle":{"marker":null,"foreign_canaries":[],"latency_budget_ms":null},"expected_safe":"refuses"}')


def test_campaign_exit_zero_on_a_tested_run(tmp_path: Path, monkeypatch) -> None:
    class M:
        def complete(self, s, u, **k): return _GEN
    _patch_wire(monkeypatch, tmp_path, M())
    rc = main(["--store", str(tmp_path / "s.db"), "campaign", "--target", "good",
               "--category", "prompt-injection", "--route", "/v1/follow-up-evidence", "--max-campaigns", "1"])
    assert rc == 0


def test_campaign_exit_one_when_nothing_tested(tmp_path: Path, monkeypatch) -> None:
    class Blocked:
        def complete(self, s, u, **k):
            from redteam.errors import ProviderBlock
            raise ProviderBlock("filtered")
    _patch_wire(monkeypatch, tmp_path, Blocked())
    rc = main(["--store", str(tmp_path / "s.db"), "campaign", "--target", "good",
               "--category", "prompt-injection", "--route", "/v1/follow-up-evidence"])
    assert rc == 1


def test_campaign_exit_two_when_no_candidates(tmp_path: Path, monkeypatch) -> None:
    class M:
        def complete(self, s, u, **k): return _GEN
    _patch_wire(monkeypatch, tmp_path, M())
    # a declared route but a deterministic-only category -> build_candidates proposes nothing
    rc = main(["--store", str(tmp_path / "s.db"), "campaign", "--target", "good",
               "--category", "broken-object-authorization", "--route", "/v1/follow-up-evidence"])
    assert rc == 2


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
        with store.transaction():
            store.insert("agent_actions", {"ts": "2026-10-01", "agent": "x", "action": "y"})
    store.close()

def _crashed_mid_write(tmp_path: Path) -> Path:
    """A copy of a store taken mid-transaction: the db file holds spilled, uncommitted pages and a
    hot rollback journal sits next to it, as after a crash or power loss."""
    import shutil

    live = tmp_path / "live.db"
    crashed = tmp_path / "crashed.db"
    store = Store.open(live)
    store.conn.execute("PRAGMA cache_size = 1")      # force pages to spill to the file mid-unit
    with pytest.raises(RuntimeError, match="simulated crash"):
        with store.transaction():
            for i in range(300):
                store.insert("agent_actions", {"ts": "t", "agent": "a", "action": f"x{i}", "reason": "r" * 200})
            shutil.copyfile(live, crashed)
            shutil.copyfile(f"{live}-journal", f"{crashed}-journal")
            raise RuntimeError("simulated crash")
    store.close()
    return crashed


def test_integrity_on_a_hot_journal_says_so_and_never_writes(tmp_path: Path, capsys) -> None:
    db = _crashed_mid_write(tmp_path)
    journal = Path(f"{db}-journal")
    before = (db.read_bytes(), journal.read_bytes())
    rc = main(["--store", str(db), "integrity"])
    out = capsys.readouterr()
    assert rc == 2
    message = out.out + out.err
    assert "uncommitted" in message and "journal" in message and "readonly database" not in message
    assert (db.read_bytes(), journal.read_bytes()) == before   # nothing recovered, nothing written

    recovered = Store.open(db)                               # a normal open rolls the journal back
    assert recovered.count("agent_actions") == 0
    recovered.close()
    assert main(["--store", str(db), "integrity"]) == 0