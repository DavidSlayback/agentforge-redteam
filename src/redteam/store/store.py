"""The SQLite store and its migration runner (docs/HARNESS_SPEC.md, D2).

Migrations are numbered ``NNNN_name.sql`` files applied in order, each recorded in
``schema_version``. Applying is idempotent: re-opening an up-to-date store applies nothing.
Adding a field later means a new migration file, never an edit to an applied one, so
existing records migrate without loss (E10).
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"
_VERSION_RE = re.compile(r"^(\d+)_")
# A statement's leading keyword, after any comments/whitespace. The runner owns the transaction,
# so a migration file may not open, end, or nest one itself.
_LEADING_COMMENTS = re.compile(r"^(?:\s+|--[^\n]*(?:\n|$)|/\*.*?\*/)*", re.DOTALL)
_TXN_CONTROL = re.compile(r"(BEGIN|COMMIT|END|ROLLBACK|SAVEPOINT|RELEASE)\b", re.IGNORECASE)


class MigrationError(RuntimeError):
    """A migration file failed and was rolled back; the store is still at the previous version."""


class TransactionAborted(RuntimeError):
    """An inner transaction scope failed, so the enclosing unit of work was rolled back even
    though the exception was caught before the outer scope ended."""


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _statements(sql: str) -> list[str]:
    """Split a script into complete statements (sqlite3 decides; trigger bodies stay whole)."""
    out, buf = [], ""
    for part in sql.split(";"):
        buf += part + ";"
        if sqlite3.complete_statement(buf):
            out.append(buf)
            buf = ""
    return out


def _check_no_transaction_control(path: Path, sql: str) -> None:
    for stmt in _statements(sql):
        body = _LEADING_COMMENTS.sub("", stmt, count=1)
        if _TXN_CONTROL.match(body):
            raise MigrationError(f"migration {path.name} contains transaction control "
                                 f"({body.split()[0]}); the migration runner owns the transaction")


class Store:
    """A thin wrapper over a migrated SQLite connection."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        self._depth = 0          # open transaction scopes; >0 means writes wait for the outer COMMIT
        self._aborted = False    # an inner scope raised: the outer unit must not commit

    @classmethod
    def open(cls, path: str | Path, *, migrations_dir: Path = MIGRATIONS_DIR) -> "Store":
        # autocommit=True: sqlite3 never opens or commits a transaction on its own, so the store
        # issues BEGIN/COMMIT/ROLLBACK itself and behaves the same on every Python version.
        conn = sqlite3.connect(str(path), autocommit=True)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        store = cls(conn)
        try:
            store.migrate(migrations_dir)
        except BaseException:
            conn.close()
            raise
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
        """Apply each pending migration atomically: its statements and its version row commit
        together, or the whole file rolls back (SQLite DDL is transactional) and
        ``MigrationError`` names the file. The store then reopens at the previous version."""
        current = self.schema_version()
        for path in sorted(Path(migrations_dir).glob("*.sql")):
            match = _VERSION_RE.match(path.name)
            if match is None:
                continue
            version = int(match.group(1))
            if version <= current:
                continue
            sql = path.read_text(encoding="utf-8")
            _check_no_transaction_control(path, sql)
            self.conn.execute("BEGIN")
            try:
                self.conn.executescript(sql)   # autocommit=True: no implicit COMMIT first
                self.conn.execute(
                    "INSERT INTO schema_version(version, name, applied_at) VALUES (?, ?, ?)",
                    (version, path.stem, _utcnow()),
                )
                self.conn.execute("COMMIT")
            except BaseException as exc:
                if self.conn.in_transaction:
                    self.conn.execute("ROLLBACK")
                if isinstance(exc, sqlite3.Error):
                    raise MigrationError(f"migration {path.name} failed and was rolled back: {exc}") from exc
                raise
        return self.schema_version()

    @property
    def in_transaction(self) -> bool:
        """True while a transaction scope is open on this store."""
        return self._depth > 0

    @contextmanager
    def transaction(self) -> Iterator["Store"]:
        """One unit of work: every write inside commits together at the end of the outermost
        scope, or rolls back together if an exception escapes.

        Nested scopes flatten: an inner scope joins the outer one and commits nothing itself.
        If an inner scope raises, the whole unit is doomed even when a caller catches the
        exception, and the outer scope rolls back and raises ``TransactionAborted`` instead
        of committing half a unit.
        """
        if self._depth:
            self._depth += 1
            try:
                yield self
            except BaseException:
                self._aborted = True
                raise
            finally:
                self._depth -= 1
            return
        if self.conn.in_transaction:
            raise RuntimeError("a transaction is already open on this connection outside a store scope")
        self.conn.execute("BEGIN")
        self._depth, self._aborted = 1, False
        try:
            yield self
            if self._aborted:
                raise TransactionAborted("an inner transaction scope failed; the unit was rolled back")
            self.conn.execute("COMMIT")
        except BaseException:
            if self.conn.in_transaction:
                self.conn.execute("ROLLBACK")
            raise
        finally:
            self._depth, self._aborted = 0, False

    def insert(self, table: str, row: dict[str, object]) -> None:
        """Insert one row. Inside a transaction scope it commits with the scope; outside one it
        commits on its own (autocommit). `table` and column names come from platform code,
        never user input, so the interpolation here is not an injection surface."""
        columns = ", ".join(row)
        placeholders = ", ".join("?" for _ in row)
        self.conn.execute(f"INSERT INTO {table} ({columns}) VALUES ({placeholders})", tuple(row.values()))

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        """Run one write statement (an UPDATE, or an INSERT that ``insert`` cannot express).
        Same commit rule as ``insert``. Reads use ``conn.execute`` directly."""
        return self.conn.execute(sql, params)

    def count(self, table: str) -> int:
        return int(self.conn.execute(f"SELECT COUNT(*) AS c FROM {table}").fetchone()["c"])

    def table_names(self) -> set[str]:
        return {r["name"] for r in self.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}

    def index_names(self) -> set[str]:
        return {r["name"] for r in self.conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}

    def close(self) -> None:
        self.conn.close()
