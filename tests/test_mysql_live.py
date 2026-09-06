"""Live MySQL integration. Skipped unless MYSQL_URL / mysql DATABASE_URL."""

from __future__ import annotations

import pytest

from live_db import ORDERS_DDL_MYSQL, connect_ok, mysql_url, require_mysql
from write_gate.adapters import mysql as mysql_mod
from write_gate.adapters.base import count_sql
from write_gate.audit import read_audit
from write_gate.config import Policy, demo_policy, production_policy
from write_gate.wrapper import WriteGate

_URL = mysql_url()
_CAN_CONNECT = bool(_URL) and connect_ok(mysql_mod.connect, _URL) if _URL else False

pytestmark = pytest.mark.skipif(
    not _CAN_CONNECT,
    reason="MySQL live service unavailable (set MYSQL_URL or DATABASE_URL)",
)


def _fresh_gate(url: str, tmp_path, *, policy=None):
    return WriteGate(
        database=url,
        policy=policy or demo_policy(),
        audit_path=tmp_path / "audit.jsonl",
        approvals_path=tmp_path / "approvals.jsonl",
        agent="mysql-live",
    )


def _ensure_schema(url: str) -> None:
    conn = mysql_mod.connect(url)
    try:
        conn.execute(ORDERS_DDL_MYSQL)
        conn.execute("DELETE FROM orders")
    finally:
        conn.close()


def _count_via_new_conn(url: str, where: str = "1=1") -> int:
    conn = mysql_mod.connect(url)
    try:
        cur = conn.execute(f"SELECT COUNT(*) FROM orders WHERE {where}")
        row = cur.fetchone()
        return int(row[0])
    finally:
        conn.close()


def _scalar_via_new_conn(url: str, sql: str):
    conn = mysql_mod.connect(url)
    try:
        cur = conn.execute(sql)
        return cur.fetchone()
    finally:
        conn.close()


def test_mysql_allowed_insert_persists_new_connection(tmp_path):
    url = require_mysql()
    _ensure_schema(url)
    oid = 920001
    with _fresh_gate(url, tmp_path) as gate:
        ev, result = gate.execute(
            "INSERT INTO orders (order_id, user_id, amount, dt, status) "
            f"VALUES ({oid}, 42, 18.50, '2026-09-01', 'paid')"
        )
        assert ev.action == "ALLOW"
        assert result is not None
    assert _count_via_new_conn(url, f"order_id = {oid}") == 1


def test_mysql_allowed_update_persists_new_connection(tmp_path):
    url = require_mysql()
    _ensure_schema(url)
    seed = mysql_mod.connect(url)
    try:
        seed.execute(
            "INSERT INTO orders (order_id, user_id, amount, dt, status) "
            "VALUES (920002, 1, 1.0, '2026-09-01', 'pending')"
        )
    finally:
        seed.close()
    with _fresh_gate(url, tmp_path) as gate:
        ev, result = gate.execute(
            "UPDATE orders SET status = 'paid' WHERE order_id = 920002"
        )
        assert ev.action == "ALLOW"
        assert result is not None
    row = _scalar_via_new_conn(url, "SELECT status FROM orders WHERE order_id = 920002")
    assert row is not None and row[0] == "paid"


def test_mysql_blocked_delete_leaves_db_unchanged(tmp_path):
    url = require_mysql()
    _ensure_schema(url)
    seed = mysql_mod.connect(url)
    try:
        seed.execute(
            "INSERT INTO orders (order_id, user_id, amount, dt, status) "
            "VALUES (920003, 1, 1.0, '2026-09-01', 'paid')"
        )
    finally:
        seed.close()
    before = _count_via_new_conn(url)
    with _fresh_gate(url, tmp_path, policy=production_policy()) as gate:
        ev, result = gate.execute("DELETE FROM orders")
        assert ev.action == "BLOCK"
        assert ev.rule_id == "delete_without_where"
        assert result is None
    assert _count_via_new_conn(url) == before


def test_mysql_constraint_failure_audited_not_silent_success(tmp_path):
    url = require_mysql()
    _ensure_schema(url)
    seed = mysql_mod.connect(url)
    try:
        seed.execute(
            "INSERT INTO orders (order_id, user_id, amount, dt, status) "
            "VALUES (920004, 1, 1.0, '2026-09-01', 'paid')"
        )
    finally:
        seed.close()
    audit = tmp_path / "audit.jsonl"
    with WriteGate(
        database=url,
        policy=demo_policy(),
        audit_path=audit,
        approvals_path=tmp_path / "approvals.jsonl",
        agent="mysql-live",
    ) as gate:
        with pytest.raises(Exception):
            gate.execute(
                "INSERT INTO orders (order_id, user_id, amount, dt, status) "
                "VALUES (920004, 2, 2.0, '2026-09-01', 'paid')"
            )
    rows = read_audit(audit, limit=20)
    failed = [r for r in rows if r.get("execution_outcome") == "failed"]
    assert failed, "constraint failure must be audited"
    assert failed[-1].get("executed") is False
    assert failed[-1].get("decision") == "ALLOW"
    assert _count_via_new_conn(url, "order_id = 920004") == 1


def test_mysql_pii_approve_returns_data(tmp_path):
    url = require_mysql()
    _ensure_schema(url)
    seed = mysql_mod.connect(url)
    try:
        seed.execute(
            "INSERT INTO orders (order_id, user_id, amount, dt, email, phone, status) "
            "VALUES (920005, 1, 1.0, '2026-09-01', 'pii@example.com', '13800000999', 'paid')"
        )
    finally:
        seed.close()
    with _fresh_gate(url, tmp_path, policy=production_policy()) as gate:
        decision, _ = gate.execute("SELECT email FROM orders WHERE order_id = 920005")
        assert decision.action == "REQUIRE_APPROVAL"
        aid = decision.approval_id
        assert aid
        d2, result = gate.approve(aid)
        assert d2.action == "ALLOW"
        assert result is not None
        rows = result.fetchall() if hasattr(result, "fetchall") else list(result)
        assert rows and rows[0][0] == "pii@example.com"


def test_mysql_blast_radius_count_dialect_quoting(tmp_path):
    url = require_mysql()
    _ensure_schema(url)
    seed = mysql_mod.connect(url)
    try:
        for i in range(3):
            seed.execute(
                "INSERT INTO orders (order_id, user_id, amount, dt, status) VALUES "
                f"({921000 + i}, 1, 1.0, '2026-09-01', 'paid')"
            )
    finally:
        seed.close()
    sql = count_sql("orders", "dt = '2026-09-01'", backend="mysql")
    assert "`orders`" in sql
    conn = mysql_mod.connect(url)
    try:
        cur = conn.execute(sql)
        assert int(cur.fetchone()[0]) == 3
    finally:
        conn.close()
    tight = Policy(
        environment="test",
        rules={
            "select": "allow",
            "insert": "allow",
            "update": "allow",
            "delete": "allow",
            "ddl": "block",
        },
        update_rows=1,
        delete_rows=1,
    )
    with _fresh_gate(url, tmp_path, policy=tight) as gate:
        ev, result = gate.execute(
            "UPDATE orders SET status = 'x' WHERE dt = '2026-09-01'"
        )
        assert ev.action == "BLOCK"
        assert ev.rule_id == "blast_radius_exceeded"
        assert result is None
    assert _count_via_new_conn(url, "status = 'x'") == 0
