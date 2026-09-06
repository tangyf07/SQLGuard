"""v0.7 approval queue: REQUIRE_APPROVAL is recorded, not executed, until approve."""

from __future__ import annotations

from pathlib import Path

import duckdb

from write_gate.approvals import get_approval, list_pending
from write_gate.cases import LEGAL_WRITE_SQL
from write_gate.cli import main
from write_gate.config import production_policy
from write_gate.db import ORDERS_DDL
from write_gate.mcp_tools import write_sql
from write_gate.paths import EXAMPLES_POLICY_PATH
from write_gate.proxy import handle_sql
from write_gate.wrapper import WriteGate

REJECT_SQL = (
    "INSERT INTO orders (order_id, user_id, amount, dt, status) "
    "VALUES (900099, 42, 18.50, '2026-09-01', 'paid')"
)


def _seed_warehouse(tmp_path) -> Path:
    db_path = tmp_path / "warehouse.duckdb"
    conn = duckdb.connect(str(db_path))
    conn.execute(ORDERS_DDL)
    conn.execute(
        "INSERT INTO orders VALUES "
        "(1, 1001, 12.5, DATE '2026-09-01', 'a@example.com', '13800000001', 'paid'),"
        "(2, 1002, 9.9, DATE '2026-08-01', 'b@example.com', '13800000002', 'pending')"
    )
    conn.close()
    return db_path


def _count(db_path: Path, sql: str = "SELECT COUNT(*) FROM orders") -> int:
    conn = duckdb.connect(str(db_path), read_only=True)
    try:
        return int(conn.execute(sql).fetchone()[0])
    finally:
        conn.close()


def _gate(tmp_path, db_path: Path) -> WriteGate:
    return WriteGate(
        db_path=db_path,
        policy_path=EXAMPLES_POLICY_PATH,
        policy=production_policy(),
        audit_path=tmp_path / "audit.jsonl",
        approvals_path=tmp_path / "approvals.jsonl",
        agent="test",
    )


def test_execute_insert_queues_no_row(tmp_path):
    db_path = _seed_warehouse(tmp_path)
    approvals = tmp_path / "approvals.jsonl"
    with _gate(tmp_path, db_path) as gate:
        decision, result = gate.execute(LEGAL_WRITE_SQL)
    assert decision.action == "REQUIRE_APPROVAL"
    assert decision.allowed is False
    assert result is None
    assert decision.approval_id
    rec = get_approval(decision.approval_id, path=approvals)
    assert rec is not None
    assert rec.status == "pending"
    assert rec.sql == LEGAL_WRITE_SQL
    assert rec.database
    n = _count(db_path, "SELECT COUNT(*) FROM orders WHERE order_id = 900001")
    assert n == 0


def test_write_sql_insert_queues_no_row(tmp_path):
    db_path = _seed_warehouse(tmp_path)
    approvals = tmp_path / "approvals.jsonl"
    result = write_sql(
        LEGAL_WRITE_SQL,
        db_path=db_path,
        policy_path=EXAMPLES_POLICY_PATH,
        approvals_path=approvals,
    )
    assert result["action"] == "REQUIRE_APPROVAL"
    assert result["executed"] is False
    assert result.get("approval_id")
    rec = get_approval(result["approval_id"], path=approvals)
    assert rec is not None
    assert rec.status == "pending"
    n = _count(db_path, "SELECT COUNT(*) FROM orders WHERE order_id = 900001")
    assert n == 0


def test_proxy_insert_queues_no_row(tmp_path):
    db_path = _seed_warehouse(tmp_path)
    approvals = tmp_path / "approvals.jsonl"
    with _gate(tmp_path, db_path) as gate:
        decision, result = handle_sql(gate, LEGAL_WRITE_SQL)
    assert decision.action == "REQUIRE_APPROVAL"
    assert result is None
    assert decision.approval_id
    rec = get_approval(decision.approval_id, path=approvals)
    assert rec is not None
    assert rec.status == "pending"
    n = _count(db_path, "SELECT COUNT(*) FROM orders WHERE order_id = 900001")
    assert n == 0


def test_approve_id_writes_row(tmp_path, capsys):
    db_path = _seed_warehouse(tmp_path)
    approvals = tmp_path / "approvals.jsonl"
    with _gate(tmp_path, db_path) as gate:
        decision, result = gate.execute(LEGAL_WRITE_SQL)
        assert decision.action == "REQUIRE_APPROVAL"
        assert result is None
        aid = decision.approval_id
    n = _count(db_path, "SELECT COUNT(*) FROM orders WHERE order_id = 900001")
    assert n == 0

    rc = main(["approve", aid, "--approvals", str(approvals)])
    out = capsys.readouterr()
    text = out.out + out.err
    assert rc == 0
    assert "ALLOWED" in text
    rec = get_approval(aid, path=approvals)
    assert rec is not None
    assert rec.status == "succeeded"
    n = _count(db_path, "SELECT COUNT(*) FROM orders WHERE order_id = 900001")
    assert n == 1


def test_reject_id_does_not_write(tmp_path, capsys):
    db_path = _seed_warehouse(tmp_path)
    approvals = tmp_path / "approvals.jsonl"
    with _gate(tmp_path, db_path) as gate:
        decision, result = gate.execute(REJECT_SQL)
        assert decision.action == "REQUIRE_APPROVAL"
        aid = decision.approval_id
    rc = main(["reject", aid, "--approvals", str(approvals)])
    out = capsys.readouterr()
    text = out.out + out.err
    assert rc == 0
    assert "REJECTED" in text
    rec = get_approval(aid, path=approvals)
    assert rec is not None
    assert rec.status == "rejected"
    n = _count(db_path, "SELECT COUNT(*) FROM orders WHERE order_id = 900099")
    assert n == 0


def test_delete_without_where_block_not_queued(tmp_path):
    db_path = _seed_warehouse(tmp_path)
    approvals = tmp_path / "approvals.jsonl"
    before = _count(db_path)
    with _gate(tmp_path, db_path) as gate:
        decision, result = gate.execute("DELETE FROM orders")
    assert decision.action == "BLOCK"
    assert decision.rule_id == "delete_without_where"
    assert result is None
    assert decision.approval_id is None
    assert list_pending(path=approvals) == []
    assert _count(db_path) == before


def test_check_does_not_enqueue(tmp_path):
    db_path = _seed_warehouse(tmp_path)
    approvals = tmp_path / "approvals.jsonl"
    with _gate(tmp_path, db_path) as gate:
        decision = gate.check(LEGAL_WRITE_SQL)
    assert decision.action == "REQUIRE_APPROVAL"
    assert decision.approval_id is None
    assert list_pending(path=approvals) == []
    n = _count(db_path, "SELECT COUNT(*) FROM orders WHERE order_id = 900001")
    assert n == 0


def test_hook_insert_does_not_enqueue(tmp_path, capsys):
    db_path = _seed_warehouse(tmp_path)
    approvals = tmp_path / "approvals.jsonl"
    rc = main(
        [
            "hook",
            "--sql",
            LEGAL_WRITE_SQL,
            "--policy",
            str(EXAMPLES_POLICY_PATH),
            "--approvals",
            str(approvals),
            "--db",
            str(db_path),
        ]
    )
    out = capsys.readouterr()
    text = out.out + out.err
    assert rc == 2
    assert "BLOCKED" in text
    assert "environment_policy" in text
    assert list_pending(path=approvals) == []
    n = _count(db_path, "SELECT COUNT(*) FROM orders WHERE order_id = 900001")
    assert n == 0


def test_approve_missing_or_not_pending_exit_1(tmp_path, capsys):
    approvals = tmp_path / "approvals.jsonl"
    approvals.write_text("", encoding="utf-8")
    rc = main(["approve", "deadbeefdead", "--approvals", str(approvals)])
    err = capsys.readouterr().err
    assert rc == 1
    assert "not found" in err


def test_pending_lists_id(tmp_path, capsys):
    db_path = _seed_warehouse(tmp_path)
    approvals = tmp_path / "approvals.jsonl"
    with _gate(tmp_path, db_path) as gate:
        decision, _ = gate.execute(LEGAL_WRITE_SQL)
    rc = main(["pending", "--approvals", str(approvals)])
    out = capsys.readouterr().out
    assert rc == 0
    assert decision.approval_id in out
    assert "pending" in out


def test_approve_clears_pii_select_and_executes(tmp_path, capsys):
    """v0.18: after PII SELECT is queued, approve clears PII approval and executes."""
    db_path = _seed_warehouse(tmp_path)
    approvals = tmp_path / "approvals.jsonl"
    with _gate(tmp_path, db_path) as gate:
        decision, result = gate.execute("SELECT email FROM orders LIMIT 1")
        assert decision.action == "REQUIRE_APPROVAL"
        assert decision.rule_id == "pii_column"
        aid = decision.approval_id
        assert result is None
    rc = main(["approve", aid, "--approvals", str(approvals)])
    out = capsys.readouterr()
    text = out.out + out.err
    assert rc == 0
    assert "ALLOWED" in text
    rec = get_approval(aid, path=approvals)
    assert rec is not None
    assert rec.status == "succeeded"


def test_approve_does_not_clear_destructive_block(tmp_path):
    """Destructive BLOCK is never queued; approve path is irrelevant."""
    db_path = _seed_warehouse(tmp_path)
    approvals = tmp_path / "approvals.jsonl"
    with _gate(tmp_path, db_path) as gate:
        decision, result = gate.execute("DELETE FROM orders")
    assert decision.action == "BLOCK"
    assert decision.rule_id == "delete_without_where"
    assert result is None
    assert list_pending(path=approvals) == []


def test_cli_proxy_json_includes_approval_id(tmp_path, capsys):
    db_path = _seed_warehouse(tmp_path)
    approvals = tmp_path / "approvals.jsonl"
    rc = main(
        [
            "proxy",
            "--database",
            str(db_path),
            "--policy",
            str(EXAMPLES_POLICY_PATH),
            "--approvals",
            str(approvals),
            "--json",
            "--sql",
            LEGAL_WRITE_SQL,
        ]
    )
    out = capsys.readouterr().out
    assert rc == 1
    assert "REQUIRE_APPROVAL" in out
    assert "approval_id" in out
    assert "executed" in out
    n = _count(db_path, "SELECT COUNT(*) FROM orders WHERE order_id = 900001")
    assert n == 0
