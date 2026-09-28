"""The store applies its migrations, is idempotent, and carries the indexed query paths."""

from __future__ import annotations

from pathlib import Path

from redteam.store.store import Store

EXPECTED_TABLES = {
    "schema_version", "campaigns", "attack_specs", "attempts", "verdicts",
    "findings", "vuln_reports", "regression_cases", "agent_actions",
    "cost_ledger", "coverage",
}
EXPECTED_INDEXES = {
    "ix_attempts_target_sha", "ix_verdicts_attempt", "ix_findings_status",
    "ix_findings_severity", "ix_findings_category", "ix_agent_actions_campaign",
}


def test_open_applies_migrations(tmp_path: Path) -> None:
    store = Store.open(tmp_path / "s.db")
    assert store.schema_version() == 3
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
    assert reopened.schema_version() == 3
    # one row per applied migration, none re-applied
    count = reopened.conn.execute("SELECT COUNT(*) AS c FROM schema_version").fetchone()["c"]
    assert count == 3
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
