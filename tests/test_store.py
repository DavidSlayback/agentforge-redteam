"""The store applies its migrations, is idempotent, and carries the indexed query paths."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from redteam.store.store import MIGRATIONS_DIR, MigrationError, Store, TransactionAborted, UnscopedWrite

EXPECTED_TABLES = {
    "schema_version", "campaigns", "attack_specs", "attempts", "verdicts",
    "findings", "vuln_reports", "regression_cases", "agent_actions",
    "cost_ledger", "coverage", "evidence", "target_health", "benign_runs", "discovery_candidates",
}
EXPECTED_INDEXES = {
    "ix_attempts_target_sha", "ix_verdicts_attempt", "ix_findings_status",
    "ix_findings_severity", "ix_findings_category", "ix_agent_actions_campaign",
    "ix_evidence_attempt", "ix_target_health_target", "ix_benign_runs_sha", "ix_discovery_status",
}


def test_open_applies_migrations(tmp_path: Path) -> None:
    store = Store.open(tmp_path / "s.db")
    assert store.schema_version() == 8
    assert EXPECTED_TABLES <= store.table_names()
    assert EXPECTED_INDEXES <= store.index_names()
    # migration 0002 added the owasp column; 0003 added regression case_json
    spec_cols = {r[1] for r in store.conn.execute("PRAGMA table_info(attack_specs)")}
    reg_cols = {r[1] for r in store.conn.execute("PRAGMA table_info(regression_cases)")}
    assert "owasp" in spec_cols and "case_json" in reg_cols
    store.close()


def test_migrations_are_idempotent(tmp_path: Path) -> None:
    db = tmp_path / "s.db"
    Store.open(db).close()
    reopened = Store.open(db)
    assert reopened.schema_version() == 8
    # one row per applied migration, none re-applied
    count = reopened.conn.execute("SELECT COUNT(*) AS c FROM schema_version").fetchone()["c"]
    assert count == 8
    reopened.close()


def test_dedup_key_is_unique(tmp_path: Path) -> None:
    import sqlite3

    store = Store.open(tmp_path / "s.db")
    row = ("f1", "t", "new", "2026-09-28")
    store.conn.execute(
        "INSERT INTO findings(finding_id, title, dedup_key, status, updated_at) VALUES (?,?,?,?,?)",
        ("f1", row[1], "oracle:sink:component", row[2], row[3]),
    )
    store.conn.commit()
    try:
        store.conn.execute(
            "INSERT INTO findings(finding_id, title, dedup_key, status, updated_at) VALUES (?,?,?,?,?)",
            ("f2", "t2", "oracle:sink:component", "new", "2026-09-28"),
        )
        raised = False
    except sqlite3.IntegrityError:
        raised = True
    assert raised, "duplicate dedup_key was accepted; findings would double-count"
    store.close()


# --- atomic migrations (issue #1) ---------------------------------------------------------

def _migrations_with(tmp_path: Path, name: str, sql: str) -> Path:
    """A temporary migrations dir: the real files plus one extra migration."""
    d = tmp_path / "migrations"
    d.mkdir()
    for p in MIGRATIONS_DIR.glob("*.sql"):
        shutil.copy(p, d / p.name)
    (d / name).write_text(sql, encoding="utf-8")
    return d


def _columns(store: Store, table: str) -> set[str]:
    return {r[1] for r in store.conn.execute(f"PRAGMA table_info({table})")}


def test_failed_migration_rolls_back_and_the_store_reopens(tmp_path: Path) -> None:
    db = tmp_path / "s.db"
    mig = _migrations_with(tmp_path, "0009_two_statements.sql",
                           "ALTER TABLE findings ADD COLUMN probe TEXT;\n"
                           "ALTER TABLE no_such_table ADD COLUMN probe TEXT;\n")
    with pytest.raises(MigrationError, match="0009_two_statements.sql"):
        Store.open(db, migrations_dir=mig)

    # The store reopens at the previous version, with the first statement rolled back too.
    store = Store.open(db)
    assert store.schema_version() == 8
    assert "probe" not in _columns(store, "findings")
    store.close()

    # Once the file is fixed it applies cleanly: no "duplicate column" from a half-applied run.
    (mig / "0009_two_statements.sql").write_text("ALTER TABLE findings ADD COLUMN probe TEXT;\n",
                                                 encoding="utf-8")
    store = Store.open(db, migrations_dir=mig)
    assert store.schema_version() == 9 and "probe" in _columns(store, "findings")
    store.close()


def test_migrate_on_an_open_store_rolls_a_failed_file_back(tmp_path: Path) -> None:
    # Called directly (not via open), so the rollback itself is what keeps the store consistent:
    # the same connection must see no half-applied column and no open transaction.
    store = Store.open(tmp_path / "s.db")
    mig = _migrations_with(tmp_path, "0009_two_statements.sql",
                           "ALTER TABLE findings ADD COLUMN probe TEXT;\n"
                           "ALTER TABLE no_such_table ADD COLUMN probe TEXT;\n")
    with pytest.raises(MigrationError, match="0009_two_statements.sql"):
        store.migrate(mig)
    assert not store.conn.in_transaction
    assert store.schema_version() == 8 and "probe" not in _columns(store, "findings")
    with store.transaction():                     # still usable for ordinary work
        store.insert("agent_actions", {"ts": "2026-10-01", "agent": "test", "action": "after"})
    store.close()


def test_a_failed_open_closes_its_connection(tmp_path: Path) -> None:
    import gc
    import warnings

    mig = _migrations_with(tmp_path, "0009_bad.sql", "ALTER TABLE no_such_table ADD COLUMN probe TEXT;\n")
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        try:
            Store.open(tmp_path / "s.db", migrations_dir=mig)
        except MigrationError:
            pass
        gc.collect()                              # an unclosed sqlite3 connection warns when collected
    leaked = [w for w in caught if issubclass(w.category, ResourceWarning) and "sqlite" in str(w.message).lower()]
    assert leaked == []


def test_a_migration_may_not_control_the_transaction(tmp_path: Path) -> None:
    db = tmp_path / "s.db"
    mig = _migrations_with(tmp_path, "0009_own_txn.sql",
                           "-- tries to commit its own work\nBEGIN;\n"
                           "ALTER TABLE findings ADD COLUMN probe TEXT;\nCOMMIT;\n")
    with pytest.raises(MigrationError, match="0009_own_txn.sql.*transaction control"):
        Store.open(db, migrations_dir=mig)
    store = Store.open(db)
    assert store.schema_version() == 8 and "probe" not in _columns(store, "findings")
    store.close()


def test_a_trigger_body_is_not_mistaken_for_transaction_control(tmp_path: Path) -> None:
    mig = _migrations_with(tmp_path, "0009_trigger.sql",
                           "CREATE TRIGGER trg_noop AFTER INSERT ON findings BEGIN\n"
                           "  UPDATE findings SET title = title WHERE 0;\nEND;\n")
    store = Store.open(tmp_path / "s.db", migrations_dir=mig)
    assert store.schema_version() == 9
    store.close()


def test_an_older_store_with_rows_migrates_forward_without_loss(tmp_path: Path) -> None:
    db = tmp_path / "s.db"
    old = tmp_path / "old"
    old.mkdir()
    for p in sorted(MIGRATIONS_DIR.glob("*.sql"))[:4]:   # 0001-0004: before 0005's five ALTERs
        shutil.copy(p, old / p.name)
    store = Store.open(db, migrations_dir=old)
    assert store.schema_version() == 4
    with store.transaction():
        store.insert("attack_specs", {"spec_id": "s1", "category": "prompt-injection", "created_at": "2026-10-01"})
    store.close()

    store = Store.open(db)
    assert store.schema_version() == 8
    row = store.conn.execute("SELECT category, schema_version FROM attack_specs").fetchone()
    assert (row["category"], row["schema_version"]) == ("prompt-injection", 1)
    store.close()


# --- transaction scopes (issue #1) ---------------------------------------------------------
# Committed state is read through a second, independent connection, the way any other process
# (the dashboard, a later CLI run) would see it.

def _action(store: Store, name: str) -> None:
    store.insert("agent_actions", {"ts": "2026-10-01", "agent": "test", "action": name})


def _committed_actions(db: Path) -> list[str]:
    other = Store.open(db)
    try:
        return [r["action"] for r in other.conn.execute("SELECT action FROM agent_actions ORDER BY id")]
    finally:
        other.close()


def test_a_write_outside_a_scope_is_refused(tmp_path: Path) -> None:
    # Every writer must declare its unit of work; a bare write is a design error, not a commit.
    db = tmp_path / "s.db"
    store = Store.open(db)
    with pytest.raises(UnscopedWrite, match="transaction"):
        _action(store, "a")
    with pytest.raises(UnscopedWrite):
        store.execute("UPDATE agent_actions SET reason = 'x'")
    assert _committed_actions(db) == []
    with store.transaction():
        _action(store, "a")
    assert _committed_actions(db) == ["a"]
    store.close()


def test_writes_in_a_scope_commit_together_at_the_end(tmp_path: Path) -> None:
    db = tmp_path / "s.db"
    store = Store.open(db)
    with store.transaction():
        _action(store, "a")
        _action(store, "b")
        assert store.in_transaction
        assert _committed_actions(db) == []        # nothing visible until the scope ends
    assert _committed_actions(db) == ["a", "b"]
    store.close()


def test_an_exception_rolls_the_whole_scope_back(tmp_path: Path) -> None:
    db = tmp_path / "s.db"
    store = Store.open(db)
    with pytest.raises(ValueError):
        with store.transaction():
            _action(store, "a")
            store.execute("UPDATE agent_actions SET reason = 'x'")
            raise ValueError("boom")
    assert not store.in_transaction
    assert _committed_actions(db) == []
    with store.transaction():                     # the store is usable again afterwards
        _action(store, "c")
    assert _committed_actions(db) == ["c"]
    store.close()


def test_nested_scopes_flatten_into_the_outer_unit(tmp_path: Path) -> None:
    db = tmp_path / "s.db"
    store = Store.open(db)
    with store.transaction():
        _action(store, "outer")
        with store.transaction():
            _action(store, "inner")
        assert store.in_transaction                 # leaving the inner scope keeps the unit open
        assert _committed_actions(db) == []        # the inner scope did not commit on its own
        _action(store, "after-inner")
    assert not store.in_transaction
    assert _committed_actions(db) == ["outer", "inner", "after-inner"]
    store.close()


def test_a_scope_refuses_to_adopt_a_transaction_it_did_not_open(tmp_path: Path) -> None:
    # Raw transaction control on the connection is not a unit of work the store can vouch for.
    db = tmp_path / "s.db"
    store = Store.open(db)
    store.conn.execute("BEGIN")
    with pytest.raises(RuntimeError, match="already open"):
        with store.transaction():
            pass
    assert store.conn.in_transaction            # the foreign transaction was left alone
    store.conn.execute("ROLLBACK")
    with store.transaction():
        _action(store, "a")
    assert _committed_actions(db) == ["a"]
    store.close()


def test_a_failed_inner_scope_dooms_the_outer_unit_even_if_caught(tmp_path: Path) -> None:
    db = tmp_path / "s.db"
    store = Store.open(db)
    with pytest.raises(TransactionAborted) as aborted:
        with store.transaction():
            _action(store, "outer")
            try:
                with store.transaction():
                    _action(store, "inner")
                    raise ValueError("inner failure")
            except ValueError:
                pass                              # swallowing it must not commit half a unit
    assert _committed_actions(db) == []
    cause = aborted.value.__cause__               # the swallowed failure stays visible
    assert isinstance(cause, ValueError) and str(cause) == "inner failure"
    store.close()