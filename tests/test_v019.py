"""v0.19/v0.20 R1–R6 regression: dangerous BLOCK + safe ALLOW/APPROVAL (not over-block)."""

from __future__ import annotations

import json
import os
from datetime import date
from pathlib import Path
from unittest.mock import patch

import duckdb
import pytest

from write_gate.approvals import (
    STATUS_APPROVED,
    STATUS_EXECUTING,
    STATUS_FAILED,
    STATUS_PENDING,
    STATUS_REJECTED,
    ApprovalError,
    claim_for_execute,
    enqueue_approval,
    get_approval,
    mark_approved,
    mark_failed,
    mark_rejected,
    release_claim,
)
from write_gate.audit import (
    append_audit,
    database_config_id,
    read_audit,
    redact_database_url,
    resolve_trusted_database_url,
    url_has_redacted_password,
)
from write_gate.catalog import load_catalog
from write_gate.cli import main
from write_gate.config import demo_policy, production_policy
from write_gate.db import ORDERS_DDL
from write_gate.decision import ACTION_ALLOW, ACTION_APPROVAL, Decision
from write_gate.parser import _nested_dml_nodes, parse
from write_gate.policy import evaluate
from write_gate.wrapper import WriteGate

ROOT = Path(__file__).resolve().parents[1]


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


def _decision(sql: str = "SELECT 1") -> Decision:
    return Decision(
        action=ACTION_APPROVAL,
        risk="medium",
        rule_id="environment_policy",
        reason="needs approval",
        sql=sql,
        operation="select",
    )


# --- R1: atomic pending→executing claim ---------------------------------------


def test_r1_claim_is_atomic_second_approve_does_not_execute(tmp_path):
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
        decision, _ = gate.execute("SELECT email FROM orders LIMIT 1")
        assert decision.action == ACTION_APPROVAL
        aid = decision.approval_id
        assert aid

        # A: observe pending (old race window start)
        seen = get_approval(aid, path=approvals)
        assert seen is not None and seen.status == STATUS_PENDING

        # B: full approve (claims + executes)
        d_b, r_b = gate.approve(aid)
        assert d_b.action == ACTION_ALLOW
        assert r_b is not None

        # A: continues — must NOT execute again
        d_a, r_a = gate.approve(aid)
        assert d_a.action == ACTION_ALLOW
        assert r_a is None
        assert "idempotent" in d_a.reason.lower() or "already approved" in d_a.reason.lower()

    rec = get_approval(aid, path=approvals)
    assert rec is not None and rec.status == STATUS_APPROVED


def test_r1_second_claim_blocked_under_flock(tmp_path):
    path = tmp_path / "approvals.jsonl"
    rec = enqueue_approval(sql="SELECT 1", decision=_decision(), path=path)
    c1 = claim_for_execute(rec.id, path=path)
    assert c1.status == STATUS_EXECUTING
    with pytest.raises(ApprovalError, match="not pending"):
        claim_for_execute(rec.id, path=path)


def test_r1_recover_failed_and_reject_interleave(tmp_path):
    path = tmp_path / "approvals.jsonl"
    rec = enqueue_approval(sql="SELECT 1", decision=_decision(), path=path)
    claim_for_execute(rec.id, path=path)
    mark_failed(rec.id, path=path)
    assert get_approval(rec.id, path=path).status == STATUS_FAILED
    # reclaim failed → executing
    c2 = claim_for_execute(rec.id, path=path)
    assert c2.status == STATUS_EXECUTING
    release_claim(rec.id, path=path)
    assert get_approval(rec.id, path=path).status == STATUS_PENDING
    # reject while pending
    mark_rejected(rec.id, path=path)
    assert get_approval(rec.id, path=path).status == STATUS_REJECTED
    with pytest.raises(ApprovalError):
        claim_for_execute(rec.id, path=path)


def test_r1_approve_reject_interleave_safe(tmp_path):
    path = tmp_path / "approvals.jsonl"
    rec = enqueue_approval(sql="SELECT 1", decision=_decision(), path=path)
    claim_for_execute(rec.id, path=path)
    # cannot reject while executing
    with pytest.raises(ApprovalError, match="not pending"):
        mark_rejected(rec.id, path=path)
    release_claim(rec.id, path=path)
    mark_rejected(rec.id, path=path)
    assert get_approval(rec.id, path=path).status == STATUS_REJECTED


# --- R2: redacted reconnect ---------------------------------------------------


def test_r2_never_treat_stars_as_password():
    assert url_has_redacted_password("postgresql://u:***@localhost:5432/app")
    assert resolve_trusted_database_url(
        "postgresql://u:***@localhost:5432/app",
        environ={"DATABASE_URL": "postgresql://u:real-secret@localhost:5432/app"},
    ) == "postgresql://u:real-secret@localhost:5432/app"
    # wrong target must not bind
    assert (
        resolve_trusted_database_url(
            "postgresql://u:***@localhost:5432/app",
            environ={"DATABASE_URL": "postgresql://u:real-secret@otherhost:5432/app"},
        )
        is None
    )


def test_r2_enqueue_stores_config_id_not_secret(tmp_path):
    path = tmp_path / "approvals.jsonl"
    url = "postgresql://agent:s3cret@db.example:5432/warehouse"
    rec = enqueue_approval(
        sql="SELECT 1",
        decision=_decision(),
        path=path,
        database=url,
    )
    assert rec.database == "postgresql://agent:***@db.example:5432/warehouse"
    assert "s3cret" not in (rec.database or "")
    assert rec.database_config_id == database_config_id(url)
    assert "s3cret" not in (rec.database_config_id or "")


def test_r2_connect_refuses_redacted_without_binding(tmp_path):
    gate = WriteGate(
        database="postgresql://u:***@localhost:5432/app",
        policy=demo_policy(),
        audit_path=tmp_path / "audit.jsonl",
        approvals_path=tmp_path / "approvals.jsonl",
    )
    with pytest.raises(ApprovalError, match="redacted"):
        gate._connect()


# --- R3: CLI approve materializes rows ----------------------------------------


def test_r3_approve_json_includes_rows(tmp_path, capsys):
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
        decision, _ = gate.execute("SELECT email FROM orders LIMIT 1")
        aid = decision.approval_id
    rc = main(
        [
            "approve",
            aid,
            "--json",
            "--approvals",
            str(approvals),
        ]
    )
    out = capsys.readouterr().out
    assert rc == 0
    payload = json.loads(out)
    assert "rows" in payload
    assert payload["rows"]
    assert payload["rows"][0][0] == "a@example.com"
    assert payload.get("rowcount") == 1


# --- R4: audit on execute failure + DSN query password ------------------------


def test_r4_audit_on_execute_exception(tmp_path):
    db_path = _seed(tmp_path)
    audit = tmp_path / "audit.jsonl"
    with WriteGate(
        db_path=db_path,
        policy=demo_policy(),
        audit_path=audit,
        approvals_path=tmp_path / "approvals.jsonl",
        agent="test",
    ) as gate:
        with patch.object(gate, "_execute_user_sql", side_effect=RuntimeError("boom")):
            with pytest.raises(RuntimeError, match="boom"):
                gate.execute(
                    "INSERT INTO orders (order_id, user_id, amount, dt, status) "
                    "VALUES (9, 1, 1.0, '2026-09-01', 'paid')"
                )
    rows = read_audit(audit, limit=20)
    failed = [r for r in rows if r.get("execution_outcome") == "failed"]
    assert failed
    assert failed[-1]["error_class"] == "RuntimeError"
    assert failed[-1]["executed"] is False
    assert failed[-1]["decision"] == "ALLOW"


def test_r4_audit_on_approve_exception_marks_failed(tmp_path):
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
        decision, _ = gate.execute("SELECT email FROM orders LIMIT 1")
        aid = decision.approval_id
        with patch.object(gate, "_execute_user_sql", side_effect=ValueError("nope")):
            with pytest.raises(ValueError, match="nope"):
                gate.approve(aid)
    rec = get_approval(aid, path=approvals)
    assert rec is not None and rec.status == STATUS_FAILED
    rows = read_audit(audit, limit=50)
    failed = [r for r in rows if r.get("approval_id") == aid and r.get("execution_outcome") == "failed"]
    assert failed
    assert failed[-1]["error_class"] == "ValueError"
    assert failed[-1]["approval_id"] == aid


def test_r4_redact_query_password_in_dsn(tmp_path):
    assert (
        redact_database_url("postgresql://localhost/db?password=hunter2&ssl=true")
        == "postgresql://localhost/db?password=***&ssl=true"
    )
    assert "hunter2" not in (
        redact_database_url("mysql://h/db?passwd=hunter2") or ""
    )
    audit = tmp_path / "audit.jsonl"
    decision = Decision(
        action=ACTION_ALLOW,
        risk="low",
        rule_id="ok",
        reason="ok",
        sql="SELECT 1",
        approval_id="abc123abc123",
    )
    append_audit(
        decision,
        path=audit,
        database="postgresql://localhost/db?password=hunter2",
        executed=False,
        execution_outcome="failed",
        error_class="OperationalError",
    )
    row = read_audit(audit, limit=1)[0]
    assert "hunter2" not in json.dumps(row)
    assert "password=***" in row["database"]
    assert row["error_class"] == "OperationalError"
    assert row["approval_id"] == "abc123abc123"


# --- R5: freshness AND/OR/NOT + UPSERT SET ------------------------------------


def test_r5_not_gte_cutoff_blocks():
    cat = load_catalog()
    ev = evaluate(
        "UPDATE orders SET status = 'x' WHERE NOT (dt >= '2026-08-26')",
        cat,
        policy=demo_policy(),
    )
    assert ev.action == "BLOCK"
    assert ev.rule_id == "expired_partition"


def test_r5_fresh_range_and_allows():
    cat = load_catalog()
    ev = evaluate(
        "UPDATE orders SET status = 'x' WHERE dt >= '2026-09-01' AND dt < '2026-09-03'",
        cat,
        policy=demo_policy(),
    )
    assert ev.rule_id != "expired_partition"
    assert ev.action == "ALLOW"


def test_r5_range_crossing_cutoff_blocks():
    cat = load_catalog()
    ev = evaluate(
        "UPDATE orders SET status = 'x' WHERE dt >= '2026-08-01' AND dt < '2026-09-03'",
        cat,
        policy=demo_policy(),
    )
    assert ev.action == "BLOCK"
    assert ev.rule_id == "expired_partition"


def test_r5_or_with_unconstrained_branch_blocks():
    cat = load_catalog()
    ev = evaluate(
        "UPDATE orders SET status = 'x' WHERE dt < '2026-09-03' OR status = 'paid'",
        cat,
        policy=demo_policy(),
    )
    assert ev.action == "BLOCK"
    assert ev.rule_id == "expired_partition"


def test_r5_upsert_set_expired_dt_blocks():
    cat = load_catalog()
    sql = (
        "INSERT INTO orders (order_id, user_id, amount, dt, status) "
        "VALUES (1, 1, 1.0, '2026-09-01', 'paid') "
        "ON CONFLICT (order_id) DO UPDATE SET dt = '2026-08-01'"
    )
    ev = evaluate(sql, cat, policy=demo_policy())
    assert ev.action == "BLOCK"
    assert ev.rule_id == "expired_partition"


# --- R6: nested DML under write root ------------------------------------------


def test_r6_nested_delete_under_insert_rejected():
    sql = (
        "WITH d AS (DELETE FROM orders RETURNING *) "
        "INSERT INTO orders (order_id, user_id, amount, dt, status) "
        "VALUES (1, 1, 1.0, '2026-09-01', 'paid')"
    )
    parsed = parse(sql, dialect="postgres")
    assert parsed.statement is not None
    nested = _nested_dml_nodes(parsed.statement)
    assert nested, "nested DELETE under INSERT root must be found"
    assert parsed.error_rule == "unsupported_sql"
    ev = evaluate(sql, load_catalog(), policy=demo_policy(), dialect="postgres")
    assert ev.action == "BLOCK"
    assert ev.rule_id == "unsupported_sql"


def test_r6_select_dm_cte_still_rejected():
    sql = (
        "WITH d AS (DELETE FROM orders WHERE order_id = 1 RETURNING *) "
        "SELECT * FROM d"
    )
    ev = evaluate(sql, load_catalog(), policy=demo_policy(), dialect="postgres")
    assert ev.action == "BLOCK"
    assert ev.rule_id == "unsupported_sql"




# --- Safe-path counterparts (must not over-block) -----------------------------


def test_r1_safe_single_approve_executes_once(tmp_path):
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
        assert decision.action == ACTION_APPROVAL
        d, rows = gate.approve(decision.approval_id)
        assert d.action == ACTION_ALLOW
        assert rows is not None


def test_r2_plain_url_connect_not_overblocked(tmp_path):
    """Non-redacted DuckDB path still connects; redacted refusal is the only gate."""
    db_path = _seed(tmp_path)
    gate = WriteGate(
        db_path=db_path,
        policy=demo_policy(),
        audit_path=tmp_path / "audit.jsonl",
        approvals_path=tmp_path / "approvals.jsonl",
    )
    conn = gate._connect()
    assert conn is not None
    gate.close()


def test_r4_successful_execute_audited_as_executed(tmp_path):
    db_path = _seed(tmp_path)
    audit = tmp_path / "audit.jsonl"
    with WriteGate(
        db_path=db_path,
        policy=demo_policy(),
        audit_path=audit,
        approvals_path=tmp_path / "approvals.jsonl",
        agent="test",
    ) as gate:
        ev, result = gate.execute(
            "INSERT INTO orders (order_id, user_id, amount, dt, status) "
            "VALUES (88, 1, 1.0, '2026-09-01', 'paid')"
        )
        assert ev.action == ACTION_ALLOW
        assert result is not None
    rows = read_audit(audit, limit=20)
    ok = [r for r in rows if r.get("execution_outcome") == "executed"]
    assert ok
    assert ok[-1]["executed"] is True


def test_r5_safe_fresh_equality_allows():
    cat = load_catalog()
    ev = evaluate(
        "UPDATE orders SET status = 'x' WHERE dt = '2026-09-01'",
        cat,
        policy=demo_policy(),
    )
    assert ev.rule_id != "expired_partition"
    assert ev.action == "ALLOW"


def test_r6_plain_insert_still_allows():
    sql = (
        "INSERT INTO orders (order_id, user_id, amount, dt, status) "
        "VALUES (1, 1, 1.0, '2026-09-01', 'paid')"
    )
    ev = evaluate(sql, load_catalog(), policy=demo_policy(), dialect="postgres")
    assert ev.action == "ALLOW"
    assert ev.rule_id == "ok"


def test_version_is_022():
    from write_gate import __version__

    assert __version__ == "1.0.0"
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'version = "1.0.0"' in text
