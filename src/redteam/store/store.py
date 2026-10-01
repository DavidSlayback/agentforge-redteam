"""The SQLite store and its migration runner (docs/HARNESS_SPEC.md, D2).

Migrations are numbered ``NNNN_name.sql`` files applied in order, each recorded in
``schema_version``. Applying is idempotent: re-opening an up-to-date store applies nothing.
Adding a field later means a new migration file, never an edit to an applied one, so
existing records migrate without loss (E10).

**Transactions.** The connection runs with ``autocommit=True``: sqlite3 never opens or commits a
transaction implicitly, so the store issues ``BEGIN``/``COMMIT``/``ROLLBACK`` itself and behaves
the same on every supported Python version.

* Each migration file and its ``schema_version`` row apply in one transaction. A failure rolls
  the whole file back and raises ``MigrationError`` naming it; the store reopens at the previous
  version. A migration file must not contain transaction control; the runner owns it.
* A logical unit of work (one judged attempt with its verdict, finding and regression case; one
  replayed case and its recorded result; one report and its audit action; one recon trigger; one
  discovery pass; one benign run) runs inside ``with store.transaction():`` and commits once at
  the end, or rolls back entirely if an exception escapes. Nested scopes flatten into the
  outermost one; if an inner scope raises, the whole unit rolls back with ``TransactionAborted``
  even if the exception was caught. ``insert``/``execute`` outside a scope raise ``UnscopedWrite``:
  every writer declares its unit of work, and nothing commits row by row. The rule also holds at
  the connection: a sqlite3 authorizer refuses INSERT/UPDATE/DELETE (and DDL) on ``store.conn``
  whenever no scope or migration is running, so raw ``conn.execute`` writes cannot bypass it.
* Units are written after the network or model calls that produce them where possible, so no
  write lock is held during I/O. Cost metering is its own unit and refuses to join another one.
* ``Store.open_readonly`` + ``integrity()`` (``redteam integrity``) report half-written units
  left by older code: attempts without a verdict and findings without a frozen regression case.
  That check never writes.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
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


class UnscopedWrite(RuntimeError):
    """A write was attempted outside ``with store.transaction():``. Every writer must declare
    its unit of work; nothing commits row by row."""


class HotJournal(RuntimeError):
    """A read-only open found an uncommitted rollback journal from an interrupted write. Only a
    normal (writable) open can roll it back; a read-only check must not, so it stops here."""


class TransactionAborted(RuntimeError):
    """An inner transaction scope failed, so the enclosing unit of work was rolled back even
    though the exception was caught before the outer scope ended."""


_WRITE_ACTIONS = frozenset({sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE})


def _deny_unscoped_writes(action: int, *_: object) -> int:
    """sqlite3 authorizer installed whenever no unit of work is open: reads pass, writes (incl.
    DDL, which inserts into sqlite_master) are refused at prepare time. Setting or clearing an
    authorizer expires cached statements, so one prepared inside a scope is re-checked here."""
    return sqlite3.SQLITE_DENY if action in _WRITE_ACTIONS else sqlite3.SQLITE_OK


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


@dataclass(frozen=True)
class IntegrityReport:
    """Half-written units already in a store: attempts with no verdict, and findings that were
    never frozen into the regression suite. Read-only; nothing here repairs them."""
    attempts_without_verdict: list[str]
    findings_without_regression_case: list[str]

    @property
    def ok(self) -> bool:
        return not (self.attempts_without_verdict or self.findings_without_regression_case)


class Store:
    """A thin wrapper over a migrated SQLite connection."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        self._in_scope = False   # a unit of work is open; nested scopes join it, writes wait for COMMIT
        self._aborted: BaseException | None = None   # an inner scope raised: the unit must not commit
        self._guarded = False    # writes outside a scope are refused at the connection (Store.open)

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
        store._guarded = True
        conn.set_authorizer(_deny_unscoped_writes)
        return store

    @classmethod
    def open_readonly(cls, path: str | Path) -> "Store":
        """Open an existing store for reading only: no migrations run, no file is created, and
        SQLite itself refuses every write on this connection."""
        conn = sqlite3.connect(f"{Path(path).resolve().as_uri()}?mode=ro", uri=True, autocommit=True)
        conn.row_factory = sqlite3.Row
        return cls(conn)

    def integrity(self) -> IntegrityReport:
        """Report half-written units (read-only queries). A missing verdict is never silent.
        Raises ``HotJournal`` if a read-only connection meets a journal it may not roll back."""
        try:
            attempts = [r["attempt_id"] for r in self.conn.execute(
                "SELECT a.attempt_id FROM attempts a WHERE NOT EXISTS "
                "(SELECT 1 FROM verdicts v WHERE v.attempt_id = a.attempt_id) ORDER BY a.started_at")]
        except sqlite3.OperationalError as exc:
            if getattr(exc, "sqlite_errorname", "") == "SQLITE_READONLY_ROLLBACK":
                raise HotJournal("the store has an uncommitted rollback journal from an interrupted write; "
                                 "open it normally once (any write-capable redteam command) so SQLite "
                                 "rolls it back, then re-run the check") from exc
            raise
        findings = [r["finding_id"] for r in self.conn.execute(
            "SELECT f.finding_id FROM findings f WHERE NOT EXISTS "
            "(SELECT 1 FROM regression_cases r WHERE r.finding_id = f.finding_id) ORDER BY f.finding_id")]
        return IntegrityReport(attempts, findings)

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
        with self._writes_open():
            return self._apply_migrations(Path(migrations_dir))

    def _apply_migrations(self, migrations_dir: Path) -> int:
        current = self.schema_version()
        for path in sorted(migrations_dir.glob("*.sql")):
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

    @contextmanager
    def _writes_open(self) -> Iterator[None]:
        """Lift the connection's write guard for the store's own transaction (a scope or a
        migration), and put it back afterwards whatever happens."""
        if self._guarded:
            self.conn.set_authorizer(None)
        try:
            yield
        finally:
            if self._guarded:
                self.conn.set_authorizer(_deny_unscoped_writes)

    @property
    def in_transaction(self) -> bool:
        """True while a transaction scope is open on this store."""
        return self._in_scope

    @contextmanager
    def transaction(self) -> Iterator["Store"]:
        """One unit of work: every write inside commits together at the end of the outermost
        scope, or rolls back together if an exception escapes.

        Nested scopes flatten: an inner scope joins the outer one and commits nothing itself.
        If an inner scope raises, the whole unit is doomed even when a caller catches the
        exception, and the outer scope rolls back and raises ``TransactionAborted`` instead
        of committing half a unit.
        """
        if self._in_scope:            # nested: join the outer unit; only the outermost commits
            try:
                yield self
            except BaseException as exc:
                self._aborted = self._aborted or exc   # keep the first failure as the cause
                raise
            return
        if self.conn.in_transaction:
            raise RuntimeError("a transaction is already open on this connection outside a store scope")
        with self._writes_open():
            self.conn.execute("BEGIN")
            self._in_scope, self._aborted = True, None
            try:
                yield self
                if self._aborted is not None:
                    raise TransactionAborted(
                        "an inner transaction scope failed; the unit was rolled back") from self._aborted
                self.conn.execute("COMMIT")
            except BaseException:
                if self.conn.in_transaction:
                    self.conn.execute("ROLLBACK")
                raise
            finally:
                self._in_scope, self._aborted = False, None

    def _require_scope(self, what: str) -> None:
        if not self._in_scope:
            raise UnscopedWrite(f"store.{what} outside a transaction scope; "
                                "wrap the unit of work in `with store.transaction():`")

    def insert(self, table: str, row: dict[str, object]) -> None:
        """Insert one row; it commits with the enclosing transaction scope (required).
        `table` and column names come from platform code, never user input, so the
        interpolation here is not an injection surface."""
        self._require_scope("insert")
        columns = ", ".join(row)
        placeholders = ", ".join("?" for _ in row)
        self.conn.execute(f"INSERT INTO {table} ({columns}) VALUES ({placeholders})", tuple(row.values()))

    def record_action(self, agent: str, action: str, refs: dict | None = None,
                      reason: str | None = None) -> None:
        """Append one ``agent_actions`` audit row. Its own unit of work, or part of the unit
        already open (scopes flatten)."""
        with self.transaction():
            self.insert("agent_actions", {"ts": _utcnow(), "agent": agent, "action": action,
                                          "refs": json.dumps(refs) if refs is not None else None,
                                          "reason": reason})

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        """Run one write statement (an UPDATE, or an INSERT that ``insert`` cannot express)
        inside the enclosing transaction scope (required). Reads use ``conn.execute`` directly."""
        self._require_scope("execute")
        return self.conn.execute(sql, params)

    def count(self, table: str) -> int:
        return int(self.conn.execute(f"SELECT COUNT(*) AS c FROM {table}").fetchone()["c"])

    def table_names(self) -> set[str]:
        return {r["name"] for r in self.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}

    def index_names(self) -> set[str]:
        return {r["name"] for r in self.conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}

    def close(self) -> None:
        self.conn.close()
