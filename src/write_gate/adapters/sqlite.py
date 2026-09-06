"""SQLite adapter. User SQL must not be executed from here; use WriteGate."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from write_gate.adapters.base import BACKEND_SQLITE, count_sql as _count_sql

DIALECT = "sqlite"
BACKEND = BACKEND_SQLITE

ORDERS_DDL = """
CREATE TABLE orders (
    order_id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    amount REAL NOT NULL,
    dt DATE NOT NULL,
    email TEXT,
    phone TEXT,
    status TEXT NOT NULL
)
"""


def count_sql(table: str, predicate: str | None) -> str:
    """Blast-radius estimate: COUNT(*) of the matching predicate (not EXPLAIN)."""
    return _count_sql(table, predicate, backend=BACKEND_SQLITE)


def explain_sql(table: str, predicate: str | None) -> str:
    """Optional EXPLAIN form. Blast-radius uses count_sql() instead."""
    return f"EXPLAIN {count_sql(table, predicate)}"


def _parse_sqlite_path(dsn: str) -> str:
    """Extract a filesystem path (or :memory:) from sqlite:/// / sqlite+aiosqlite://.

    Handles Unix absolute (``sqlite:////tmp/x.db`` → ``/tmp/x.db``), relative
    (``sqlite:///rel.db``), ``:memory:``, and Windows drive letters
    (``sqlite:///C:/temp/x.db`` → ``C:/temp/x.db``).
    """
    raw = dsn.strip()
    lower = raw.lower()
    if lower.startswith("sqlite+aiosqlite://"):
        rest = raw[len("sqlite+aiosqlite://") :]
    elif lower.startswith("sqlite://"):
        rest = raw[len("sqlite://") :]
    else:
        raise ValueError(f"not a sqlite URL: {dsn}")

    if "?" in rest:
        rest = rest.split("?", 1)[0]
    rest = unquote(rest)

    if rest in (":memory:", "/:memory:"):
        return ":memory:"
    # Four-slash absolute: //tmp/x.db -> /tmp/x.db
    # or //C:/temp/x.db -> /C:/temp/x.db (normalized below)
    if rest.startswith("//"):
        rest = rest[1:]
    # Windows drive letter: /C:/path or C:/path (and backslash forms)
    if len(rest) >= 3 and rest[0] == "/" and rest[1].isalpha() and rest[2] == ":":
        rest = rest[1:]
    if len(rest) >= 2 and rest[0].isalpha() and rest[1] == ":":
        return rest.replace("\\", "/")
    # Three-slash Unix absolute: /tmp/x.db
    if rest.startswith("/"):
        return rest
    return rest or ":memory:"


def _connect_raw(dsn: str, **kwargs: Any) -> Any:
    """Open a stdlib sqlite3 connection. Tests may monkeypatch this."""
    path = _parse_sqlite_path(dsn)
    timeout = kwargs.pop("timeout", 3.0)
    if path != ":memory:":
        parent = Path(path).parent
        if str(parent) not in ("", "."):
            parent.mkdir(parents=True, exist_ok=True)
    try:
        conn = sqlite3.connect(path, timeout=timeout, **kwargs)
    except TypeError:
        # Unexpected kwargs from callers; retry with path only.
        conn = sqlite3.connect(path, timeout=timeout)
    conn.isolation_level = None  # autocommit-like
    return conn


class SQLiteConnection:
    """DuckDB-like execute/fetchone surface over stdlib sqlite3."""

    def __init__(self, raw: Any) -> None:
        self._raw = raw

    def execute(self, sql: str):
        cursor_fn = getattr(self._raw, "cursor", None)
        if callable(cursor_fn):
            cur = cursor_fn()
            cur.execute(sql)
            return cur
        execute = getattr(self._raw, "execute", None)
        if callable(execute):
            return execute(sql)
        raise RuntimeError("SQLite connection does not support execute/cursor")

    def close(self) -> None:
        close = getattr(self._raw, "close", None)
        if callable(close):
            close()

    def commit(self) -> None:
        commit = getattr(self._raw, "commit", None)
        if callable(commit):
            commit()


def connect(dsn: str, *, read_only: bool = False) -> SQLiteConnection:
    del read_only
    return SQLiteConnection(_connect_raw(dsn))


def execute_user_sql(conn: Any, sql: str):
    """Run already-gated SQL. Called only by write_gate.wrapper.WriteGate."""
    return conn.execute(sql)
