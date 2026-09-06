"""v0.18.0 acceptance: freshness ranges, PII approve, hooks nest, mysql autocommit, approvals lock."""

from __future__ import annotations

import io
import json
from pathlib import Path
from unittest.mock import MagicMock

import duckdb
import pytest

from write_gate.adapters.mysql import MySQLConnection
from write_gate.approvals import (
    STATUS_APPROVED,
    enqueue_approval,
    get_approval,
    list_pending,
    mark_approved,
    set_status,
)
from write_gate.audit import append_audit, read_audit, redact_database_url
from write_gate.catalog import load_catalog
from write_gate.cli import main
from write_gate.config import production_policy
from write_gate.db import ORDERS_DDL
from write_gate.decision import ACTION_ALLOW, ACTION_APPROVAL, Decision
from write_gate.hooks import inspect_bash, run_hook
from write_gate.paths import EXAMPLES_POLICY_PATH
from write_gate.policy import evaluate
from write_gate.wrapper import WriteGate

ROOT = Path(__file__).resolve().parents[1]


# --- 1) freshness: ranges, UPDATE SET dt expired, INSERT expired ---------------


def test_freshness_range_lt_blocks():
    ev = evaluate(
        "UPDATE orders SET status = 'x' WHERE dt < '2026-09-01'",
        load_catalog(),
    )
    assert ev.action == "BLOCK"
    assert ev.rule_id == "expired_partition"


def test_freshness_range_lte_blocks():
    ev = evaluate(
        "DELETE FROM orders WHERE dt <= '2026-08-26'",
        load_catalog(),
    )
    assert ev.action == "BLOCK"
    assert ev.rule_id == "expired_partition"


def test_freshness_range_gt_into_expired_blocks():
    # cutoff = 2026-08-26; dt > 2026-08-01 still includes expired days before cutoff
    ev = evaluate(
        "UPDATE orders SET status = 'x' WHERE dt > '2026-08-01'",
        load_catalog(),
    )
    assert ev.action == "BLOCK"
    assert ev.rule_id == "expired_partition"


def test_freshness_range_gte_expired_blocks():
    ev = evaluate(
        "UPDATE orders SET status = 'x' WHERE dt >= '2026-08-01'",
        load_catalog(),
    )
    assert ev.action == "BLOCK"
    assert ev.rule_id == "expired_partition"


def test_freshness_update_set_dt_to_expired_blocks():
    ev = evaluate(
        "UPDATE orders SET dt = '2026-08-01' WHERE order_id = 1",
        load_catalog(),
    )
    assert ev.action == "BLOCK"
    assert ev.rule_id == "expired_partition"


def test_freshness_insert_expired_blocks():
    ev = evaluate(
        "INSERT INTO orders (order_id, user_id, amount, dt, status) "
        "VALUES (1, 1, 1.0, '2026-08-01', 'paid')",
        load_catalog(),
    )
    assert ev.action == "BLOCK"
    assert ev.rule_id == "expired_partition"


def test_freshness_fresh_equality_not_expired_by_freshness_alone():
    # May still hit environment/blast; must NOT be expired_partition
    ev = evaluate(
        "UPDATE orders SET status = 'x' WHERE dt = '2026-09-01'",
        load_catalog(),
    )
    assert ev.rule_id != "expired_partition"


# --- 2) wrapper.approve clears PII SELECT approval -----------------------------


def _seed(tmp_path) -> Path:
    db_path = tmp_path / "warehouse.duckdb"
    conn = duckdb.connect(str(db_path))
    conn.execute(ORDERS_DDL)
    conn.execute(
        "INSERT INTO orders VALUES "
        "(1, 1001, 12.5, DATE '2026-09-01', 'a@example.com', '13800000001', 'paid')"
    )
    conn.close()
    return db_path


def test_approve_pii_select_clears_and_executes(tmp_path):
    db_path = _seed(tmp_path)
    approvals = tmp_path / "approvals.jsonl"
    audit = tmp_path / "audit.jsonl"
    with WriteGate(
        db_path=db_path,
        policy=production_policy(),
        audit_path=audit,
        approvals_path=approvals,
        agent="test",
    ) as gate:
        decision, result = gate.execute("SELECT email FROM orders LIMIT 1")
        assert decision.action == ACTION_APPROVAL
        assert decision.rule_id == "pii_column"
        assert result is None
        aid = decision.approval_id
        assert aid
        decision2, result2 = gate.approve(aid)
    assert decision2.action == ACTION_ALLOW
    assert result2 is not None
    # Re-read via a fresh connection (adapter cursor may not expose fetchall).
    conn = duckdb.connect(str(db_path), read_only=True)
    try:
        rows = conn.execute("SELECT email FROM orders LIMIT 1").fetchall()
    finally:
        conn.close()
    assert rows == [("a@example.com",)]
    rec = get_approval(aid, path=approvals)
    assert rec is not None
    assert rec.status == STATUS_APPROVED
    audit_rows = read_audit(audit, limit=20)
    executed = [r for r in audit_rows if r.get("approval_id") == aid and r.get("executed")]
    assert executed
    assert executed[-1].get("execution_outcome") == "executed"


def test_approve_pii_select_idempotent_no_reexec(tmp_path):
    db_path = _seed(tmp_path)
    approvals = tmp_path / "approvals.jsonl"
    with WriteGate(
        db_path=db_path,
        policy=production_policy(),
        audit_path=tmp_path / "audit.jsonl",
        approvals_path=approvals,
        agent="test",
    ) as gate:
        decision, _ = gate.execute("SELECT email FROM orders LIMIT 1")
        aid = decision.approval_id
        d1, r1 = gate.approve(aid)
        assert d1.action == ACTION_ALLOW
        assert r1 is not None
        d2, r2 = gate.approve(aid)
    assert d2.action == ACTION_ALLOW
    assert r2 is None  # idempotent: prior approval, not re-executed
    assert "idempotent" in d2.reason.lower() or "already approved" in d2.reason.lower()


def test_approve_still_blocks_destructive(tmp_path):
    """PII-write / destructive never queue as approval; re-approve path stays blocked."""
    db_path = _seed(tmp_path)
    approvals = tmp_path / "approvals.jsonl"
    with WriteGate(
        db_path=db_path,
        policy=production_policy(),
        audit_path=tmp_path / "audit.jsonl",
        approvals_path=approvals,
        agent="test",
    ) as gate:
        decision, result = gate.execute("DELETE FROM orders")
    assert decision.action == "BLOCK"
    assert decision.rule_id == "delete_without_where"
    assert result is None
    assert list_pending(path=approvals) == []


# --- 3) hooks: bash -c / sh -c nested; semicolon glue -------------------------


def test_hooks_bash_c_nested_blocks_dangerous(capsys):
    rc = main(["hook", "--command", 'bash -c "psql -c DELETE FROM orders"'])
    out = capsys.readouterr()
    text = out.err + out.out
    assert rc == 2
    assert "BLOCKED" in text
    assert "delete_without_where" in text


def test_hooks_sh_c_nested_blocks_dangerous(capsys):
    rc = main(["hook", "--command", "sh -c 'mysql -e DELETE FROM orders'"])
    out = capsys.readouterr()
    text = out.err + out.out
    assert rc == 2
    assert "delete_without_where" in text


def test_hooks_semicolon_glue_without_spaces_blocks(capsys):
    rc = main(
        ["hook", "--command", "echo hi;psql -c DELETE FROM orders"]
    )
    out = capsys.readouterr()
    text = out.err + out.out
    assert rc == 2
    assert "delete_without_where" in text


def test_hooks_inspect_bash_nested_and_glue():
    segs = inspect_bash('bash -c "psql -c DELETE FROM orders"')
    assert any(s.cli == "psql" and "DELETE FROM orders" in s.sqls for s in segs)
    segs2 = inspect_bash("ls;mysql -e DROP TABLE orders")
    assert any(s.cli == "mysql" for s in segs2)
    buf = io.StringIO()
    assert run_hook(bash_command="ls -l", err=buf) == 0


# --- 4) mysql callable autocommit ---------------------------------------------


def test_mysql_autocommit_prefers_callable_method():
    raw = MagicMock()
    raw.autocommit = MagicMock(name="autocommit_method")
    conn = MySQLConnection(raw)
    raw.autocommit.assert_called_once_with(True)
    # Must not have replaced the method with True via setattr
    assert callable(conn._raw.autocommit)


def test_mysql_autocommit_setattr_fallback():
    class AttrOnly:
        def __init__(self):
            self.autocommit = False

    raw = AttrOnly()
    MySQLConnection(raw)
    assert raw.autocommit is True


# --- 5) approvals flock / idempotent / audit redact / execution result --------


def test_approvals_mark_approved_idempotent(tmp_path):
    path = tmp_path / "approvals.jsonl"
    decision = Decision(
        action=ACTION_APPROVAL,
        risk="medium",
        rule_id="environment_policy",
        reason="needs approval",
        sql="SELECT 1",
        operation="select",
    )
    rec = enqueue_approval(sql="SELECT 1", decision=decision, path=path)
    a1 = mark_approved(rec.id, path=path)
    assert a1.status == STATUS_APPROVED
    a2 = mark_approved(rec.id, path=path)
    assert a2.status == STATUS_APPROVED
    assert a2.id == rec.id


def test_approvals_lock_file_created(tmp_path):
    path = tmp_path / "approvals.jsonl"
    decision = Decision(
        action=ACTION_APPROVAL,
        risk="low",
        rule_id="ok",
        reason="x",
        sql="SELECT 1",
    )
    enqueue_approval(sql="SELECT 1", decision=decision, path=path)
    lock = path.with_suffix(path.suffix + ".lock")
    assert lock.exists()


def test_audit_redacts_password_in_urls(tmp_path):
    assert (
        redact_database_url("postgresql://user:s3cret@localhost/db")
        == "postgresql://user:***@localhost/db"
    )
    assert (
        redact_database_url("mysql://root:p@ss@127.0.0.1:3306/app")
        == "mysql://root:***@127.0.0.1:3306/app"
    )
    audit = tmp_path / "audit.jsonl"
    decision = Decision(
        action=ACTION_ALLOW,
        risk="low",
        rule_id="ok",
        reason="ok",
        sql="SELECT 1",
        operation="select",
        approval_id="abc123abc123",
    )
    append_audit(
        decision,
        agent="test",
        environment="test",
        path=audit,
        database="postgresql://user:hunter2@localhost/db",
        executed=True,
        execution_outcome="executed",
    )
    rows = read_audit(audit, limit=5)
    assert len(rows) == 1
    assert rows[0]["database"] == "postgresql://user:***@localhost/db"
    assert "hunter2" not in json.dumps(rows[0])
    assert rows[0]["approval_id"] == "abc123abc123"
    assert rows[0]["executed"] is True
    assert rows[0]["execution_outcome"] == "executed"


def test_version_is_019_after_bump():
    from write_gate import __version__

    assert __version__ == "0.19.0"
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'version = "0.19.0"' in text
