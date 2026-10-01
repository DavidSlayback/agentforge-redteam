"""The store applies its migrations, is idempotent, and carries the indexed query paths."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from redteam.store.store import MIGRATIONS_DIR, Store

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


@pytest.mark.xfail(strict=True, reason="migrations are not atomic yet (issue #1)")
def test_failed_migration_rolls_back_and_the_store_reopens(tmp_path: Path) -> None:
    db = tmp_path / "s.db"
    mig = _migrations_with(tmp_path, "0009_two_statements.sql",
                           "ALTER TABLE findings ADD COLUMN probe TEXT;\n"
                           "ALTER TABLE no_such_table ADD COLUMN probe TEXT;\n")
    with pytest.raises(Exception, match="0009_two_statements.sql"):
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
