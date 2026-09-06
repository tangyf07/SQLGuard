"""Adapter routing, PG blast COUNT SQL, destructive without a live DB."""

from __future__ import annotations

import os

import pytest

from write_gate.adapters.base import (
    BACKEND_DUCKDB,
    BACKEND_POSTGRES,
    count_sql,
    detect_backend,
    is_postgres_url,
    resolve_target,
)
from write_gate.adapters.postgres import count_sql as pg_count_sql
from write_gate.catalog import load_catalog
from write_gate.cases import PII_WRITE_SQL
from write_gate.config import demo_policy, production_policy
from write_gate.engine import evaluate
from write_gate.wrapper import WriteGate


PG_URL = "postgresql://user:pass@localhost:5432/app"
PG_URL_SHORT = "postgres://localhost/db"


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


class FakePg:
    """DuckDB-like execute/fetchone surface used as a fake PG backend."""

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


def test_is_postgres_url_routing():
    assert is_postgres_url(PG_URL) is True
    assert is_postgres_url(PG_URL_SHORT) is True
    assert is_postgres_url("POSTGRESQL://localhost/db") is True
    assert is_postgres_url("/tmp/warehouse.duckdb") is False
    assert is_postgres_url("warehouse.duckdb") is False
    assert is_postgres_url(None) is False


def test_detect_backend():
    assert detect_backend(PG_URL) == BACKEND_POSTGRES
    assert detect_backend(PG_URL_SHORT) == BACKEND_POSTGRES
    assert detect_backend("/tmp/wh.duckdb") == BACKEND_DUCKDB
    assert detect_backend("seed/warehouse.duckdb") == BACKEND_DUCKDB


def test_resolve_database_kwarg():
    backend, target = resolve_target(database=PG_URL)
    assert backend == BACKEND_POSTGRES
    assert target == PG_URL


def test_resolve_database_url_kwarg():
    backend, target = resolve_target(database_url=PG_URL_SHORT)
    assert backend == BACKEND_POSTGRES
    assert target == PG_URL_SHORT


def test_resolve_db_path_is_duckdb(tmp_path):
    path = tmp_path / "wh.duckdb"
    backend, target = resolve_target(db_path=path)
    assert backend == BACKEND_DUCKDB
    assert target == str(path)


def test_resolve_db_path_postgres_url():
    backend, target = resolve_target(db_path=PG_URL)
    assert backend == BACKEND_POSTGRES
    assert target == PG_URL


def test_resolve_env_database_url(monkeypatch):
    monkeypatch.delenv("POSTGRES_URL", raising=False)
    monkeypatch.delenv("MYSQL_URL", raising=False)
    monkeypatch.setenv("DATABASE_URL", PG_URL)
    backend, target = resolve_target(environ=os.environ)
    assert backend == BACKEND_POSTGRES
    assert target == PG_URL


def test_explicit_db_path_wins_over_env(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", PG_URL)
    path = tmp_path / "wh.duckdb"
    backend, target = resolve_target(db_path=path, environ=os.environ)
    assert backend == BACKEND_DUCKDB
    assert target == str(path)


def test_database_kwarg_wins_over_env_and_path(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", "postgres://env/db")
    backend, target = resolve_target(
        database=PG_URL,
        db_path=tmp_path / "wh.duckdb",
        environ=os.environ,
    )
    assert backend == BACKEND_POSTGRES
    assert target == PG_URL


def test_writegate_database_selects_postgres(tmp_path):
    gate = WriteGate(
        database=PG_URL,
        policy=production_policy(),
        audit_path=tmp_path / "audit.jsonl",
    )
    assert gate.backend == BACKEND_POSTGRES
    assert gate.database == PG_URL


def test_writegate_database_url_alias(tmp_path):
    gate = WriteGate(
        database_url=PG_URL,
        policy=production_policy(),
        audit_path=tmp_path / "audit.jsonl",
    )
    assert gate.backend == BACKEND_POSTGRES


def test_writegate_env_database_url(monkeypatch, tmp_path):
    monkeypatch.delenv("POSTGRES_URL", raising=False)
    monkeypatch.delenv("MYSQL_URL", raising=False)
    monkeypatch.setenv("DATABASE_URL", PG_URL)
    gate = WriteGate(policy=production_policy(), audit_path=tmp_path / "audit.jsonl")
    assert gate.backend == BACKEND_POSTGRES


def test_writegate_db_path_stays_duckdb_when_env_set(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", PG_URL)
    gate = WriteGate(
        db_path=tmp_path / "wh.duckdb",
        policy=demo_policy(),
        audit_path=tmp_path / "audit.jsonl",
    )
    assert gate.backend == BACKEND_DUCKDB


def test_pg_count_sql_uses_count_star():
    sql = pg_count_sql("orders", "dt = '2026-09-01'")
    assert "COUNT(*)" in sql
    assert '"orders"' in sql
    assert "WHERE dt = '2026-09-01'" in sql
    assert sql == count_sql("orders", "dt = '2026-09-01'", backend="postgres")


def test_pg_count_sql_without_predicate():
    sql = pg_count_sql("orders", None)
    assert sql == 'SELECT COUNT(*) FROM "orders"'
    assert "WHERE" not in sql


def test_pg_blast_uses_count_sql():
    conn = FakePg(count=3)
    ev = evaluate(
        "UPDATE orders SET status = 'expired' WHERE dt = '2026-09-01'",
        load_catalog(),
        policy=_allow_writes(update_rows=2),
        conn=conn,
        dialect="postgres",
    )
    assert any("COUNT(*)" in s for s in conn.statements)
    assert ev.action == "BLOCK"
    assert ev.rule_id == "blast_radius_exceeded"
    assert ev.estimated_rows == 3


def test_pg_blast_within_limit_allows():
    conn = FakePg(count=1)
    ev = evaluate(
        "UPDATE orders SET status = 'paid' WHERE order_id = 1",
        load_catalog(),
        policy=_allow_writes(update_rows=2),
        conn=conn,
        dialect="postgres",
    )
    assert ev.action == "ALLOW"
    assert any("COUNT(*)" in s for s in conn.statements)


def test_delete_without_where_blocked_with_pg_url_no_live_db(tmp_path):
    gate = WriteGate(
        database=PG_URL,
        policy=production_policy(),
        audit_path=tmp_path / "audit.jsonl",
    )
    ev = gate.check("DELETE FROM orders")
    assert ev.action == "BLOCK"
    assert ev.rule_id == "delete_without_where"
    assert ev.operation == "delete"
    assert ev.table == "orders"


def test_execute_delete_without_where_pg_url_no_live_table(tmp_path):
    """AST path: execute() blocks even if Postgres is unreachable / has no orders table."""
    gate = WriteGate(
        database=PG_URL,
        policy=production_policy(),
        audit_path=tmp_path / "audit.jsonl",
    )
    ev, result = gate.execute("DELETE FROM orders")
    assert ev.action == "BLOCK"
    assert ev.rule_id == "delete_without_where"
    assert result is None


def test_execute_delete_without_where_with_fake_pg_backend(tmp_path):
    fake = FakePg(count=99)
    gate = WriteGate(
        database=PG_URL,
        conn=fake,
        policy=production_policy(),
        audit_path=tmp_path / "audit.jsonl",
    )
    ev, result = gate.execute("DELETE FROM orders")
    assert ev.rule_id == "delete_without_where"
    assert result is None
    # Destructive fires before blast-radius COUNT; no user DELETE is sent.
    assert not any(s.strip().upper().startswith("DELETE") for s in fake.statements)


def test_pg_url_other_guards_still_apply_without_live_db(tmp_path):
    gate = WriteGate(
        database=PG_URL,
        policy=demo_policy(),
        audit_path=tmp_path / "audit.jsonl",
    )
    ev = gate.check(PII_WRITE_SQL)
    assert ev.action == "BLOCK"
    assert ev.rule_id == "pii_column"


def test_pg_url_drop_table_blocked_without_live_db(tmp_path):
    gate = WriteGate(
        database=PG_URL,
        policy=demo_policy(),
        audit_path=tmp_path / "audit.jsonl",
    )
    ev = gate.check("DROP TABLE orders")
    assert ev.action == "BLOCK"
    assert ev.rule_id == "drop_table"


def test_execute_legal_insert_with_fake_pg(tmp_path):
    fake = FakePg(count=0)
    gate = WriteGate(
        database=PG_URL,
        conn=fake,
        policy=demo_policy(),
        audit_path=tmp_path / "audit.jsonl",
    )
    sql = (
        "INSERT INTO orders (order_id, user_id, amount, dt, status) "
        "VALUES (900001, 42, 18.50, '2026-09-01', 'paid')"
    )
    ev, result = gate.execute(sql)
    assert ev.action == "ALLOW"
    assert result is not None
    assert any("INSERT" in s.upper() for s in fake.statements)


def test_cli_check_database_flag_blocks_delete(capsys, tmp_path):
    from write_gate.cli import main

    rc = main(["check", "--database", PG_URL, "DELETE FROM orders"])
    out = capsys.readouterr().out
    assert rc == 2
    assert "BLOCKED" in out
    assert "delete_without_where" in out


def test_connect_mocked_psycopg(monkeypatch, tmp_path):
    fake = FakePg(count=0)

    def fake_connect(dsn, **kwargs):
        assert dsn.startswith("postgres")
        return fake

    monkeypatch.setattr("write_gate.adapters.postgres._connect_raw", fake_connect)
    gate = WriteGate(
        database=PG_URL,
        policy=demo_policy(),
        audit_path=tmp_path / "audit.jsonl",
    )
    ev, result = gate.execute(
        "INSERT INTO orders (order_id, user_id, amount, dt, status) "
        "VALUES (900001, 42, 18.50, '2026-09-01', 'paid')"
    )
    assert ev.action == "ALLOW"
    assert result is not None
