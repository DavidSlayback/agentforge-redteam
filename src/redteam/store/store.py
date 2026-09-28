"""The SQLite store and its migration runner (docs/HARNESS_SPEC.md, D2).

Migrations are numbered ``NNNN_name.sql`` files applied in order, each recorded in
``schema_version``. Applying is idempotent: re-opening an up-to-date store applies nothing.
Adding a field later means a new migration file, never an edit to an applied one, so
existing records migrate without loss (E10).
"""

from __future__ import annotations

import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"
_VERSION_RE = re.compile(r"^(\d+)_")


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class Store:
    """A thin wrapper over a migrated SQLite connection."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    @classmethod
    def open(cls, path: str | Path, *, migrations_dir: Path = MIGRATIONS_DIR) -> "Store":
        conn = sqlite3.connect(str(path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        store = cls(conn)
        store.migrate(migrations_dir)
        return store

    def schema_version(self) -> int:
        exists = self.conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_version'"
        ).fetchone()
        if exists is None:
            return 0
        row = self.conn.execute("SELECT COALESCE(MAX(version), 0) AS v FROM schema_version").fetchone()
        return int(row["v"])

    def migrate(self, migrations_dir: Path = MIGRATIONS_DIR) -> int:
        current = self.schema_version()
        for path in sorted(Path(migrations_dir).glob("*.sql")):
            match = _VERSION_RE.match(path.name)
            if match is None:
                continue
            version = int(match.group(1))
            if version <= current:
                continue
            self.conn.executescript(path.read_text(encoding="utf-8"))
            self.conn.execute(
                "INSERT INTO schema_version(version, name, applied_at) VALUES (?, ?, ?)",
                (version, path.stem, _utcnow()),
            )
            self.conn.commit()
        return self.schema_version()

    def insert(self, table: str, row: dict[str, object]) -> None:
        """Insert one row. `table` and column names come from platform code, never user
        input, so the interpolation here is not an injection surface."""
        columns = ", ".join(row)
        placeholders = ", ".join("?" for _ in row)
        self.conn.execute(f"INSERT INTO {table} ({columns}) VALUES ({placeholders})", tuple(row.values()))
        self.conn.commit()

    def count(self, table: str) -> int:
        return int(self.conn.execute(f"SELECT COUNT(*) AS c FROM {table}").fetchone()["c"])

    def table_names(self) -> set[str]:
        return {r["name"] for r in self.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}

    def index_names(self) -> set[str]:
        return {r["name"] for r in self.conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}

    def close(self) -> None:
        self.conn.close()
