"""Helpers for optional live Postgres / MySQL integration tests.

Env (CI sets these via service containers; local optional):

- ``POSTGRES_URL`` — preferred for Postgres live tests
- ``MYSQL_URL`` — preferred for MySQL live tests
- ``DATABASE_URL`` — fallback when scheme matches (postgres* / mysql*)

When unset or unreachable, live tests skip (``make test`` stays green offline).
"""

from __future__ import annotations

import os
from typing import Callable

import pytest

from write_gate.adapters.base import is_mysql_url, is_postgres_url

ORDERS_DDL_PG = """
CREATE TABLE IF NOT EXISTS orders (
    order_id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    amount DOUBLE PRECISION NOT NULL,
    dt DATE NOT NULL,
    email VARCHAR,
    phone VARCHAR,
    status VARCHAR NOT NULL
)
"""

ORDERS_DDL_MYSQL = """
CREATE TABLE IF NOT EXISTS orders (
    order_id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    amount DOUBLE NOT NULL,
    dt DATE NOT NULL,
    email VARCHAR(255),
    phone VARCHAR(64),
    status VARCHAR(64) NOT NULL
)
"""


def postgres_url() -> str | None:
    for key in ("POSTGRES_URL", "DATABASE_URL"):
        url = (os.environ.get(key) or "").strip()
        if url and is_postgres_url(url):
            return url
    return None


def mysql_url() -> str | None:
    for key in ("MYSQL_URL", "DATABASE_URL"):
        url = (os.environ.get(key) or "").strip()
        if url and is_mysql_url(url):
            return url
    return None


def require_postgres() -> str:
    url = postgres_url()
    if not url:
        pytest.skip("POSTGRES_URL / DATABASE_URL (postgres) not set")
    return url


def require_mysql() -> str:
    url = mysql_url()
    if not url:
        pytest.skip("MYSQL_URL / DATABASE_URL (mysql) not set")
    return url


def connect_ok(connect: Callable[[str], object], url: str) -> bool:
    try:
        conn = connect(url)
        try:
            conn.execute("SELECT 1")
        finally:
            close = getattr(conn, "close", None)
            if callable(close):
                close()
        return True
    except Exception:
        return False
