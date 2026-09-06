"""MySQL adapter routing and AST BLOCK without a live MySQL server."""

from __future__ import annotations

import os

import pytest

from write_gate.adapters.base import (
    BACKEND_DUCKDB,
    BACKEND_MYSQL,
    BACKEND_POSTGRES,
    count_sql,
    detect_backend,
    is_mysql_url,
    resolve_target,
)
from write_gate.adapters.mysql import count_sql as mysql_count_sql
from write_gate.catalog import load_catalog
from write_gate.config import demo_policy, production_policy
from write_gate.engine import evaluate
from write_gate.mcp_tools import write_sql
from write_gate.wrapper import WriteGate

MYSQL_URL = "mysql://user:pass@localhost/db"
MYSQL_PYMYSQL_URL = "mysql+pymysql://user:pass@localhost/db"


def _allow_writes(**limits):
    return demo_policy().__class__(
        environment="test",
        rules={
            "select": "allow",
            "insert": "allow",
            "update": "allow",
            "delete": "allow",
            "ddl": "block",
        },
        update_rows=limits.get("update_rows", 2),
        delete_rows=limits.get("delete_rows", 2),
    )


class FakeMySQL:
    """DuckDB-like execute/fetchone surface used as a fake MySQL backend."""

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


def test_is_mysql_url_routing():
    assert is_mysql_url(MYSQL_URL) is True
    assert is_mysql_url(MYSQL_PYMYSQL_URL) is True
    assert is_mysql_url("MYSQL://localhost/db") is True
    assert is_mysql_url("MySQL+PyMySQL://localhost/db") is True
    assert is_mysql_url("postgresql://localhost/db") is False
    assert is_mysql_url("/tmp/warehouse.duckdb") is False
    assert is_mysql_url(None) is False


def test_detect_backend_mysql_and_others():
    assert detect_backend(MYSQL_URL) == BACKEND_MYSQL
    assert detect_backend(MYSQL_PYMYSQL_URL) == BACKEND_MYSQL
    assert detect_backend("postgres://localhost/db") == BACKEND_POSTGRES
    assert detect_backend("/tmp/wh.duckdb") == BACKEND_DUCKDB


def test_resolve_target_mysql_url():
    backend, target = resolve_target(database=MYSQL_URL)
    assert backend == BACKEND_MYSQL
    assert target == MYSQL_URL
    backend2, target2 = resolve_target(database_url=MYSQL_PYMYSQL_URL)
    assert backend2 == BACKEND_MYSQL
    assert target2 == MYSQL_PYMYSQL_URL


def test_resolve_env_mysql(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", MYSQL_URL)
    backend, target = resolve_target(environ=os.environ)
    assert backend == BACKEND_MYSQL
    assert target == MYSQL_URL


def test_writegate_database_selects_mysql(tmp_path):
    gate = WriteGate(
        database=MYSQL_URL,
        policy=production_policy(),
        audit_path=tmp_path / "audit.jsonl",
    )
    assert gate.backend == BACKEND_MYSQL
    assert gate.database == MYSQL_URL


def test_check_delete_without_where_mysql_url_no_live_db(tmp_path):
    gate = WriteGate(
        database=MYSQL_URL,
        policy=production_policy(),
        audit_path=tmp_path / "audit.jsonl",
    )
    ev = gate.check("DELETE FROM orders")
    assert ev.action == "BLOCK"
    assert ev.rule_id == "delete_without_where"
    assert ev.operation == "delete"
    assert ev.table == "orders"


def test_check_delete_mysql_pymysql_url(tmp_path):
    gate = WriteGate(
        database=MYSQL_PYMYSQL_URL,
        policy=production_policy(),
        audit_path=tmp_path / "audit.jsonl",
    )
    ev = gate.check("DELETE FROM orders")
    assert ev.action == "BLOCK"
    assert ev.rule_id == "delete_without_where"


def test_execute_delete_without_where_mysql_url_no_live_db(tmp_path):
    gate = WriteGate(
        database=MYSQL_URL,
        policy=production_policy(),
        audit_path=tmp_path / "audit.jsonl",
    )
    ev, result = gate.execute("DELETE FROM orders")
    assert ev.action == "BLOCK"
    assert ev.rule_id == "delete_without_where"
    assert result is None


def test_write_sql_delete_mysql_url_blocks():
    result = write_sql("DELETE FROM orders", database=MYSQL_URL)
    assert result["action"] == "BLOCK"
    assert result["rule_id"] == "delete_without_where"
    assert result.get("executed") is False


def test_proxy_mysql_url_delete_block_without_live_db(capsys):
    from write_gate.cli import main

    rc = main(
        [
            "proxy",
            "--database",
            MYSQL_URL,
            "--sql",
            "DELETE FROM orders",
        ]
    )
    out = capsys.readouterr().out
    assert rc == 2
    assert "BLOCKED" in out
    assert "delete_without_where" in out


def test_cli_check_database_mysql_blocks_delete(capsys):
    from write_gate.cli import main

    rc = main(["check", "--database", MYSQL_URL, "DELETE FROM orders"])
    out = capsys.readouterr().out
    assert rc == 2
    assert "BLOCKED" in out
    assert "delete_without_where" in out


def test_mysql_count_sql_shared():
    sql = mysql_count_sql("orders", "dt = '2026-09-01'")
    assert "COUNT(*)" in sql
    assert "`orders`" in sql  # MySQL dialect-aware quoting
    assert "WHERE dt = '2026-09-01'" in sql
    assert sql == count_sql("orders", "dt = '2026-09-01'", backend="mysql")


def test_mysql_blast_uses_count_sql():
    conn = FakeMySQL(count=3)
    ev = evaluate(
        "UPDATE orders SET status = 'expired' WHERE dt = '2026-09-01'",
        load_catalog(),
        policy=_allow_writes(update_rows=2),
        conn=conn,
        dialect="mysql",
    )
    assert any("COUNT(*)" in s for s in conn.statements)
    assert ev.action == "BLOCK"
    assert ev.rule_id == "blast_radius_exceeded"
    assert ev.estimated_rows == 3


def test_execute_delete_with_fake_mysql_backend(tmp_path):
    fake = FakeMySQL(count=99)
    gate = WriteGate(
        database=MYSQL_URL,
        conn=fake,
        policy=production_policy(),
        audit_path=tmp_path / "audit.jsonl",
    )
    ev, result = gate.execute("DELETE FROM orders")
    assert ev.rule_id == "delete_without_where"
    assert result is None
    assert not any(s.strip().upper().startswith("DELETE") for s in fake.statements)


def test_connect_mocked_pymysql(monkeypatch, tmp_path):
    fake = FakeMySQL(count=0)

    def fake_connect(dsn, **kwargs):
        assert dsn.lower().startswith("mysql")
        return fake

    monkeypatch.setattr("write_gate.adapters.mysql._connect_raw", fake_connect)
    gate = WriteGate(
        database=MYSQL_URL,
        policy=demo_policy(),
        audit_path=tmp_path / "audit.jsonl",
    )
    ev, result = gate.execute(
        "INSERT INTO orders (order_id, user_id, amount, dt, status) "
        "VALUES (900001, 42, 18.50, '2026-09-01', 'paid')"
    )
    assert ev.action == "ALLOW"
    assert result is not None


def test_missing_driver_install_hint(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name in {"pymysql", "mysql", "mysql.connector"} or name.startswith("mysql."):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(ImportError) as ei:
        from write_gate.adapters import mysql as mysql_mod

        mysql_mod._connect_raw(MYSQL_URL)
    assert "sql-write-gate[mysql]" in str(ei.value)


def test_resolve_env_postgres_url_preferred(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("POSTGRES_URL", "postgresql://gate@localhost/db")
    monkeypatch.setenv("MYSQL_URL", "mysql://gate@localhost/db")
    backend, target = resolve_target(environ=os.environ)
    assert backend == BACKEND_POSTGRES
    assert target.startswith("postgresql://")


def test_resolve_env_mysql_url(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("POSTGRES_URL", raising=False)
    monkeypatch.setenv("MYSQL_URL", MYSQL_URL)
    backend, target = resolve_target(environ=os.environ)
    assert backend == BACKEND_MYSQL
    assert target == MYSQL_URL
