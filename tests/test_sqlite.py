"""SQLite adapter routing and AST BLOCK without requiring prior tables."""

from __future__ import annotations

import os
from write_gate.adapters.base import (
    BACKEND_DUCKDB,
    BACKEND_MYSQL,
    BACKEND_POSTGRES,
    BACKEND_SQLITE,
    count_sql,
    detect_backend,
    is_sqlite_url,
    resolve_target,
    sqlglot_dialect,
)
from write_gate.adapters.sqlite import ORDERS_DDL, count_sql as sqlite_count_sql
from write_gate.catalog import load_catalog
from write_gate.config import demo_policy, production_policy
from write_gate.engine import evaluate
from write_gate.mcp_tools import write_sql
from write_gate.wrapper import WriteGate

SQLITE_URL = "sqlite:////tmp/x.db"
SQLITE_AIOSQLITE_URL = "sqlite+aiosqlite:////tmp/x.db"


class FakeSQLite:
    """DuckDB-like execute/fetchone surface used as a fake SQLite backend."""

    def __init__(self, count: int = 3) -> None:
        self.count = count
        self.statements: list[str] = []

    def execute(self, sql: str):
        self.statements.append(sql)
        return self

    def fetchone(self):
        return (self.count,)

    def fetchall(self):
        return []

    def close(self) -> None:
        pass


def test_is_sqlite_url_routing():
    assert is_sqlite_url(SQLITE_URL) is True
    assert is_sqlite_url(SQLITE_AIOSQLITE_URL) is True
    assert is_sqlite_url("SQLITE:///tmp/x.db") is True
    assert is_sqlite_url("SQLite+AioSQLite:///tmp/x.db") is True
    assert is_sqlite_url("postgresql://localhost/db") is False
    assert is_sqlite_url("mysql://localhost/db") is False
    assert is_sqlite_url("/tmp/warehouse.duckdb") is False
    assert is_sqlite_url(None) is False


def test_detect_backend_sqlite_and_others():
    assert detect_backend(SQLITE_URL) == BACKEND_SQLITE
    assert detect_backend(SQLITE_AIOSQLITE_URL) == BACKEND_SQLITE
    assert detect_backend("mysql://localhost/db") == BACKEND_MYSQL
    assert detect_backend("postgres://localhost/db") == BACKEND_POSTGRES
    assert detect_backend("/tmp/wh.duckdb") == BACKEND_DUCKDB


def test_sqlglot_dialect_sqlite():
    assert sqlglot_dialect(BACKEND_SQLITE) == "sqlite"


def test_resolve_target_sqlite_url():
    backend, target = resolve_target(database=SQLITE_URL)
    assert backend == BACKEND_SQLITE
    assert target == SQLITE_URL
    backend2, target2 = resolve_target(database_url=SQLITE_AIOSQLITE_URL)
    assert backend2 == BACKEND_SQLITE
    assert target2 == SQLITE_AIOSQLITE_URL


def test_resolve_env_sqlite(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", SQLITE_URL)
    backend, target = resolve_target(environ=os.environ)
    assert backend == BACKEND_SQLITE
    assert target == SQLITE_URL


def test_writegate_database_selects_sqlite(tmp_path):
    gate = WriteGate(
        database=SQLITE_URL,
        policy=production_policy(),
        audit_path=tmp_path / "audit.jsonl",
    )
    assert gate.backend == BACKEND_SQLITE
    assert gate.database == SQLITE_URL


def test_check_delete_without_where_sqlite_url_no_live_db(tmp_path):
    gate = WriteGate(
        database="sqlite:////tmp/x.db",
        policy=production_policy(),
        audit_path=tmp_path / "audit.jsonl",
    )
    ev = gate.check("DELETE FROM orders")
    assert ev.action == "BLOCK"
    assert ev.rule_id == "delete_without_where"
    assert ev.operation == "delete"
    assert ev.table == "orders"


def test_check_delete_sqlite_aiosqlite_url(tmp_path):
    gate = WriteGate(
        database=SQLITE_AIOSQLITE_URL,
        policy=production_policy(),
        audit_path=tmp_path / "audit.jsonl",
    )
    ev = gate.check("DELETE FROM orders")
    assert ev.action == "BLOCK"
    assert ev.rule_id == "delete_without_where"


def test_execute_delete_without_where_sqlite_url_no_live_db(tmp_path):
    gate = WriteGate(
        database=SQLITE_URL,
        policy=production_policy(),
        audit_path=tmp_path / "audit.jsonl",
    )
    ev, result = gate.execute("DELETE FROM orders")
    assert ev.action == "BLOCK"
    assert ev.rule_id == "delete_without_where"
    assert result is None


def test_write_sql_delete_sqlite_url_blocks():
    result = write_sql("DELETE FROM orders", database=SQLITE_URL)
    assert result["action"] == "BLOCK"
    assert result["rule_id"] == "delete_without_where"
    assert result.get("executed") is False


def test_proxy_sqlite_url_delete_block_without_live_db(capsys):
    from write_gate.cli import main

    rc = main(
        [
            "proxy",
            "--database",
            SQLITE_URL,
            "--sql",
            "DELETE FROM orders",
        ]
    )
    out = capsys.readouterr().out
    assert rc == 2
    assert "BLOCKED" in out
    assert "delete_without_where" in out


def test_cli_check_database_sqlite_blocks_delete(capsys):
    from write_gate.cli import main

    rc = main(["check", "--database", "sqlite:////tmp/wg.db", "DELETE FROM orders"])
    out = capsys.readouterr().out
    assert rc == 2
    assert "BLOCKED" in out
    assert "delete_without_where" in out


def test_sqlite_count_sql_shared():
    sql = sqlite_count_sql("orders", "dt = '2026-09-01'")
    assert "COUNT(*)" in sql
    assert '"orders"' in sql
    assert "WHERE dt = '2026-09-01'" in sql
    assert sql == count_sql("orders", "dt = '2026-09-01'", backend="sqlite")


def test_sqlite_blast_uses_count_sql():
    conn = FakeSQLite(count=3)
    ev = evaluate(
        "UPDATE orders SET status = 'expired' WHERE dt = '2026-09-01'",
        load_catalog(),
        policy=demo_policy().__class__(
            environment="test",
            rules={
                "select": "allow",
                "insert": "allow",
                "update": "allow",
                "delete": "allow",
                "ddl": "block",
            },
            update_rows=2,
            delete_rows=2,
        ),
        conn=conn,
        dialect="sqlite",
    )
    assert any("COUNT(*)" in s for s in conn.statements)
    assert ev.action == "BLOCK"
    assert ev.rule_id == "blast_radius_exceeded"
    assert ev.estimated_rows == 3


def test_execute_delete_with_fake_sqlite_backend(tmp_path):
    fake = FakeSQLite(count=99)
    gate = WriteGate(
        database=SQLITE_URL,
        conn=fake,
        policy=production_policy(),
        audit_path=tmp_path / "audit.jsonl",
    )
    ev, result = gate.execute("DELETE FROM orders")
    assert ev.rule_id == "delete_without_where"
    assert result is None
    assert not any(s.strip().upper().startswith("DELETE") for s in fake.statements)


def test_live_sqlite_insert_allow(tmp_path):
    """Optional live path: tempfile SQLite can CREATE + ALLOW insert."""
    abs_path = str((tmp_path / "live.db").resolve())
    url = f"sqlite:///{abs_path}"  # absolute path -> sqlite:////...
    assert url.startswith("sqlite:////"), url

    from write_gate.adapters import sqlite as sqlite_mod

    raw = sqlite_mod.connect(url)
    raw.execute(ORDERS_DDL)
    raw.close()

    gate = WriteGate(
        database=url,
        policy=demo_policy(),
        audit_path=tmp_path / "audit.jsonl",
    )
    assert gate.backend == BACKEND_SQLITE
    ev, result = gate.execute(
        "INSERT INTO orders (order_id, user_id, amount, dt, status) "
        "VALUES (900001, 42, 18.50, '2026-09-01', 'paid')"
    )
    assert ev.action == "ALLOW"
    assert result is not None
