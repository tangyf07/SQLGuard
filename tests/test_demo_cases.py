"""End-to-end wrapper tests: three demo verdicts + schema + read-only."""

import duckdb
import pytest

from write_gate.cases import (
    EXPIRED_WRITE_SQL,
    LEGAL_WRITE_SQL,
    PII_WRITE_SQL,
    READ_ONLY_SQL,
    SCHEMA_MISMATCH_SQL,
)
from write_gate.config import demo_policy
from write_gate.db import ORDERS_DDL
from write_gate.wrapper import WriteGate


@pytest.fixture()
def gate(tmp_path):
    db_path = tmp_path / "warehouse.duckdb"
    conn = duckdb.connect(str(db_path))
    conn.execute(ORDERS_DDL)
    conn.execute(
        "INSERT INTO orders VALUES "
        "(1, 1001, 12.5, DATE '2026-09-01', 'a@example.com', '13800000001', 'paid'),"
        "(2, 1002, 9.9, DATE '2026-08-01', 'b@example.com', '13800000002', 'pending')"
    )
    g = WriteGate(
        db_path=db_path,
        conn=conn,
        policy=demo_policy(),
        audit_path=tmp_path / "audit.jsonl",
    )
    yield g
    g.close()


def test_demo_legal_write_allowed(gate):
    ev, result = gate.execute(LEGAL_WRITE_SQL)
    assert ev.allowed is True
    assert ev.rule_id == "ok"
    assert result is not None
    n = gate.conn.execute(
        "SELECT COUNT(*) FROM orders WHERE order_id = 900001"
    ).fetchone()[0]
    assert n == 1


def test_demo_expired_partition_blocked(gate):
    before = gate.conn.execute("SELECT COUNT(*) FROM orders").fetchone()[0]
    ev, result = gate.execute(EXPIRED_WRITE_SQL)
    after = gate.conn.execute("SELECT COUNT(*) FROM orders").fetchone()[0]
    assert ev.allowed is False
    assert ev.rule_id == "expired_partition"
    assert result is None
    assert after == before


def test_demo_pii_write_blocked(gate):
    before = gate.conn.execute("SELECT COUNT(*) FROM orders").fetchone()[0]
    ev, result = gate.execute(PII_WRITE_SQL)
    after = gate.conn.execute("SELECT COUNT(*) FROM orders").fetchone()[0]
    assert ev.allowed is False
    assert ev.rule_id == "pii_column"
    assert result is None
    assert after == before


def test_schema_mismatch_rejected_no_write(gate):
    before = gate.conn.execute("SELECT COUNT(*) FROM orders").fetchone()[0]
    ev, result = gate.execute(SCHEMA_MISMATCH_SQL)
    after = gate.conn.execute("SELECT COUNT(*) FROM orders").fetchone()[0]
    assert ev.allowed is False
    assert ev.rule_id == "schema_hallucination"
    assert result is None
    assert after == before


def test_read_only_allowed_returns_rows(gate):
    ev, result = gate.execute(READ_ONLY_SQL)
    assert ev.allowed is True
    assert ev.rule_id == "ok"
    rows = result.fetchall()
    assert len(rows) >= 1
    # Read-only query does not go through write rules even if table has PII columns.
    assert all(len(r) == 4 for r in rows)
