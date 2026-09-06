"""Adapter routing: postgres:// / mysql:// / sqlite:// URLs vs DuckDB file paths."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Mapping

from write_gate.paths import default_db_path

BACKEND_DUCKDB = "duckdb"
BACKEND_POSTGRES = "postgres"
BACKEND_MYSQL = "mysql"
BACKEND_SQLITE = "sqlite"

_PG_PREFIXES = ("postgres://", "postgresql://")
_MYSQL_PREFIXES = ("mysql://", "mysql+pymysql://")
_SQLITE_PREFIXES = ("sqlite:///", "sqlite+aiosqlite://")


def is_postgres_url(value: str | None) -> bool:
    if not value:
        return False
    lowered = value.strip().lower()
    return lowered.startswith(_PG_PREFIXES)


def is_mysql_url(value: str | None) -> bool:
    if not value:
        return False
    lowered = value.strip().lower()
    return lowered.startswith(_MYSQL_PREFIXES)


def is_sqlite_url(value: str | None) -> bool:
    if not value:
        return False
    lowered = value.strip().lower()
    return lowered.startswith(_SQLITE_PREFIXES)


def detect_backend(target: str | None) -> str:
    if is_sqlite_url(target):
        return BACKEND_SQLITE
    if is_mysql_url(target):
        return BACKEND_MYSQL
    if is_postgres_url(target):
        return BACKEND_POSTGRES
    return BACKEND_DUCKDB


def sqlglot_dialect(backend: str) -> str:
    if backend in {BACKEND_POSTGRES, "postgresql", "pg"}:
        return "postgres"
    if backend == BACKEND_MYSQL:
        return "mysql"
    if backend == BACKEND_SQLITE:
        return "sqlite"
    return "duckdb"


def quote_ident(name: str, *, backend: str = BACKEND_DUCKDB) -> str:
    """Dialect-aware identifier quoting for COUNT targets."""
    if backend == BACKEND_MYSQL:
        safe = name.replace("`", "``")
        return f"`{safe}`"
    safe = name.replace('"', '""')
    return f'"{safe}"'


def count_sql(
    table: str,
    predicate: str | None,
    *,
    backend: str = BACKEND_DUCKDB,
    alias: str | None = None,
) -> str:
    """SELECT COUNT(*) of rows matching the write predicate.

    Includes table alias when the UPDATE/DELETE used one so predicates like
    ``o.order_id > 0`` still resolve. Quoting is dialect-aware (MySQL backticks).
    """
    quoted = quote_ident(table, backend=backend)
    if alias:
        quoted = f"{quoted} AS {quote_ident(alias, backend=backend)}"
    sql = f"SELECT COUNT(*) FROM {quoted}"
    if predicate:
        sql = f"{sql} WHERE {predicate}"
    return sql


def resolve_target(
    *,
    database: str | None = None,
    database_url: str | None = None,
    db_path: str | Path | None = None,
    environ: Mapping[str, str] | None = None,
) -> tuple[str, str]:
    """Return (backend, target).

    Priority:
      1. ``database=``
      2. ``database_url=``
      3. ``db_path=`` (explicit path wins over env so tests/demo stay DuckDB)
      4. Env URLs: ``POSTGRES_URL``, ``MYSQL_URL``, then ``DATABASE_URL``
      5. default DuckDB warehouse
    """
    env = os.environ if environ is None else environ
    for candidate in (database, database_url):
        if candidate:
            return detect_backend(candidate), candidate
    if db_path is not None:
        target = str(db_path)
        return detect_backend(target), target
    for key in ("POSTGRES_URL", "MYSQL_URL", "DATABASE_URL"):
        env_url = env.get(key)
        if env_url:
            return detect_backend(env_url), env_url
    return BACKEND_DUCKDB, str(default_db_path())
