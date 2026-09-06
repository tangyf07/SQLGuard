"""v0.21.0: three-state outcomes, SQLite durable store, no unknown auto-retry."""

from __future__ import annotations

import multiprocessing as mp
import os
import time
from pathlib import Path
from unittest.mock import patch

import duckdb
import pytest

from write_gate.approvals import (
    STATUS_EXECUTING,
    STATUS_FAILED,
    STATUS_PENDING,
    STATUS_SUCCEEDED,
    STATUS_UNKNOWN,
    ApprovalError,
    claim_for_execute,
    db_path_for,
    enqueue_approval,
    force_unknown_check,
    get_approval,
    mark_failed,
    mark_succeeded,
    mark_unknown,
    resolve_approval,
    set_status,
)
from write_gate.cli import main
from write_gate.config import production_policy
from write_gate.db import ORDERS_DDL
from write_gate.decision import ACTION_ALLOW, ACTION_APPROVAL, Decision
from write_gate.wrapper import WriteGate

INSERT_SQL = (
    "INSERT INTO orders (order_id, user_id, amount, dt, status) "
    "VALUES (910021, 42, 18.50, '2026-09-01', 'paid')"
)


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


def _count(db_path: Path, where: str = "order_id = 910021") -> int:
    # Avoid read_only while WriteGate may still hold a RW DuckDB handle.
    conn = duckdb.connect(str(db_path))
    try:
        return int(conn.execute(f"SELECT COUNT(*) FROM orders WHERE {where}").fetchone()[0])
    finally:
        conn.close()


def _decision(sql: str = "SELECT 1") -> Decision:
    return Decision(
        action=ACTION_APPROVAL,
        risk="medium",
        rule_id="environment_policy",
        reason="needs approval",
        sql=sql,
        operation="insert",
    )


def _gate(tmp_path, db_path: Path) -> WriteGate:
    return WriteGate(
        db_path=db_path,
        policy=production_policy(),
        audit_path=tmp_path / "audit.jsonl",
        approvals_path=tmp_path / "approvals.jsonl",
        agent="test",
    )


# --- SQLite durable store -----------------------------------------------------


def test_enqueue_uses_sqlite_source_of_truth(tmp_path):
    path = tmp_path / "approvals.jsonl"
    rec = enqueue_approval(sql="SELECT 1", decision=_decision(), path=path)
    sqlite_path = db_path_for(path)
    assert sqlite_path.exists()
    loaded = get_approval(rec.id, path=path)
    assert loaded is not None
    assert loaded.status == STATUS_PENDING
    # JSONL mirror exists for compat
    assert path.exists()
    assert rec.id in path.read_text(encoding="utf-8")


def test_atomic_claim_pending_to_executing(tmp_path):
    path = tmp_path / "approvals.jsonl"
    rec = enqueue_approval(sql="SELECT 1", decision=_decision(), path=path)
    c1 = claim_for_execute(rec.id, path=path)
    assert c1.status == STATUS_EXECUTING
    assert c1.executing_at
    with pytest.raises(ApprovalError, match="not pending"):
        claim_for_execute(rec.id, path=path)


# --- Three-state outcomes -----------------------------------------------------


def test_approve_marks_succeeded(tmp_path):
    db_path = _seed(tmp_path)
    approvals = tmp_path / "approvals.jsonl"
    with _gate(tmp_path, db_path) as gate:
        decision, _ = gate.execute("SELECT email FROM orders LIMIT 1")
        aid = decision.approval_id
        d, rows = gate.approve(aid)
        assert d.action == ACTION_ALLOW
        assert rows is not None
    rec = get_approval(aid, path=approvals)
    assert rec is not None and rec.status == STATUS_SUCCEEDED


def test_approve_known_error_marks_failed_not_unknown(tmp_path):
    db_path = _seed(tmp_path)
    approvals = tmp_path / "approvals.jsonl"
    with _gate(tmp_path, db_path) as gate:
        decision, _ = gate.execute("SELECT email FROM orders LIMIT 1")
        aid = decision.approval_id
        with patch.object(gate, "_execute_user_sql", side_effect=ValueError("nope")):
            with pytest.raises(ValueError, match="nope"):
                gate.approve(aid)
    rec = get_approval(aid, path=approvals)
    assert rec is not None and rec.status == STATUS_FAILED


def test_approve_timeout_marks_unknown(tmp_path):
    db_path = _seed(tmp_path)
    approvals = tmp_path / "approvals.jsonl"
    with _gate(tmp_path, db_path) as gate:
        decision, _ = gate.execute("SELECT email FROM orders LIMIT 1")
        aid = decision.approval_id
        with patch.object(
            gate,
            "_execute_user_sql",
            side_effect=TimeoutError("query timed out"),
        ):
            with pytest.raises(TimeoutError):
                gate.approve(aid)
    rec = get_approval(aid, path=approvals)
    assert rec is not None and rec.status == STATUS_UNKNOWN


def test_post_exec_mark_failure_becomes_unknown(tmp_path):
    db_path = _seed(tmp_path)
    approvals = tmp_path / "approvals.jsonl"
    with _gate(tmp_path, db_path) as gate:
        decision, _ = gate.execute("SELECT email FROM orders LIMIT 1")
        aid = decision.approval_id
        with patch(
            "write_gate.wrapper.mark_succeeded",
            side_effect=RuntimeError("disk full"),
        ):
            with pytest.raises(RuntimeError, match="disk full"):
                gate.approve(aid)
    rec = get_approval(aid, path=approvals)
    assert rec is not None and rec.status == STATUS_UNKNOWN


# --- unknown ≠ failed auto-retry ---------------------------------------------


def test_unknown_second_approve_does_not_write(tmp_path):
    db_path = _seed(tmp_path)
    approvals = tmp_path / "approvals.jsonl"
    with _gate(tmp_path, db_path) as gate:
        decision, _ = gate.execute(INSERT_SQL)
        aid = decision.approval_id
        # Simulate unknown after a speculative write attempt
        claim_for_execute(aid, path=approvals)
        mark_unknown(aid, path=approvals, outcome_note="simulated")
        with pytest.raises(ApprovalError, match="unknown"):
            gate.approve(aid)
    assert _count(db_path) == 0
    # Default CLI approve also refuses
    rc = main(["approve", aid, "--approvals", str(approvals)])
    assert rc == 1
    assert _count(db_path) == 0


def test_succeeded_second_approve_idempotent_no_double_write(tmp_path):
    db_path = _seed(tmp_path)
    approvals = tmp_path / "approvals.jsonl"
    with _gate(tmp_path, db_path) as gate:
        decision, _ = gate.execute(INSERT_SQL)
        aid = decision.approval_id
        d1, _ = gate.approve(aid)
        assert d1.action == ACTION_ALLOW
        d2, r2 = gate.approve(aid)
        assert d2.action == ACTION_ALLOW
        assert r2 is None
        assert "idempotent" in d2.reason.lower() or "already approved" in d2.reason.lower()
    assert _count(db_path) == 1
    rec = get_approval(aid, path=approvals)
    assert rec is not None and rec.status == STATUS_SUCCEEDED


def test_allow_unknown_retry_explicit_only(tmp_path):
    db_path = _seed(tmp_path)
    approvals = tmp_path / "approvals.jsonl"
    with _gate(tmp_path, db_path) as gate:
        decision, _ = gate.execute(INSERT_SQL)
        aid = decision.approval_id
        claim_for_execute(aid, path=approvals)
        mark_unknown(aid, path=approvals)
        d, _ = gate.approve(aid, allow_unknown_retry=True)
        assert d.action == ACTION_ALLOW
    assert _count(db_path) == 1
    assert get_approval(aid, path=approvals).status == STATUS_SUCCEEDED


def test_resolve_succeeded_without_reexec(tmp_path):
    db_path = _seed(tmp_path)
    approvals = tmp_path / "approvals.jsonl"
    with _gate(tmp_path, db_path) as gate:
        decision, _ = gate.execute(INSERT_SQL)
        aid = decision.approval_id
    claim_for_execute(aid, path=approvals)
    mark_unknown(aid, path=approvals)
    # Operator verifies DB manually (row absent) and marks failed — no write
    rec = resolve_approval(aid, as_status="failed", path=approvals, outcome_note="checked")
    assert rec.status == STATUS_FAILED
    assert _count(db_path) == 0
    # Or confirm-succeeded after they applied SQL out-of-band
    claim_for_execute(aid, path=approvals, recover_failed=True)
    mark_unknown(aid, path=approvals)
    rec2 = resolve_approval(
        aid, as_status="confirm-succeeded", path=approvals, outcome_note="saw row"
    )
    assert rec2.status == STATUS_SUCCEEDED
    assert _count(db_path) == 0  # resolve never executes SQL


def test_cli_resolve_and_force_unknown_check(tmp_path, capsys):
    path = tmp_path / "approvals.jsonl"
    rec = enqueue_approval(sql="SELECT 1", decision=_decision(), path=path)
    claim_for_execute(rec.id, path=path)
    mark_unknown(rec.id, path=path)
    rc = main(
        [
            "approve",
            rec.id,
            "--approvals",
            str(path),
            "--force-unknown-check",
        ]
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "unknown" in out.lower() or "STATUS" in out
    rc2 = main(
        [
            "resolve",
            rec.id,
            "--approvals",
            str(path),
            "--as",
            "rejected",
            "--note",
            "ops verified",
        ]
    )
    assert rc2 == 0
    assert get_approval(rec.id, path=path).status == "rejected"


# --- Concurrent multi-process approve ----------------------------------------


def _mp_approve_worker(approvals: str, db_path: str, aid: str, q: mp.Queue) -> None:
    try:
        gate = WriteGate(
            db_path=db_path,
            policy=production_policy(),
            audit_path=str(Path(approvals).with_name("audit-mp.jsonl")),
            approvals_path=approvals,
            agent="mp",
        )
        with gate:
            d, r = gate.approve(aid)
            q.put(("ok", d.action, r is not None, getattr(d, "reason", "")))
    except Exception as exc:  # noqa: BLE001 — surface to parent
        q.put(("err", type(exc).__name__, str(exc), ""))


def test_multiprocess_double_approve_single_write(tmp_path):
    db_path = _seed(tmp_path)
    approvals = tmp_path / "approvals.jsonl"
    with _gate(tmp_path, db_path) as gate:
        decision, _ = gate.execute(INSERT_SQL)
        aid = decision.approval_id
    assert aid
    q: mp.Queue = mp.Queue()
    procs = [
        mp.Process(
            target=_mp_approve_worker,
            args=(str(approvals), str(db_path), aid, q),
        )
        for _ in range(2)
    ]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=30)
        assert p.exitcode == 0
    results = [q.get(timeout=5) for _ in range(2)]
    wrote = [r for r in results if r[0] == "ok" and r[2] is True]
    idempotent = [
        r
        for r in results
        if r[0] == "ok"
        and r[2] is False
        and ("idempotent" in r[3].lower() or "already" in r[3].lower())
    ]
    # One write, one idempotent (or one write + one ApprovalError treated as err
    # that still did not write — either way row count is 1).
    assert _count(db_path) == 1
    assert get_approval(aid, path=approvals).status == STATUS_SUCCEEDED
    assert len(wrote) <= 1
    assert len(wrote) + len(idempotent) + sum(1 for r in results if r[0] == "err") == 2


def test_interleaved_double_approve_single_write(tmp_path):
    """Same-process interleaved approve: second sees succeeded, no second write."""
    db_path = _seed(tmp_path)
    approvals = tmp_path / "approvals.jsonl"
    with _gate(tmp_path, db_path) as gate:
        decision, _ = gate.execute(INSERT_SQL)
        aid = decision.approval_id
        d1, _ = gate.approve(aid)
        assert d1.action == ACTION_ALLOW
        d2, r2 = gate.approve(aid)
        assert r2 is None
    assert _count(db_path) == 1


# --- Crash recovery -----------------------------------------------------------


def test_crash_while_executing_becomes_unknown_no_reclaim(tmp_path, monkeypatch):
    path = tmp_path / "approvals.jsonl"
    rec = enqueue_approval(sql=INSERT_SQL, decision=_decision(INSERT_SQL), path=path)
    claim_for_execute(rec.id, path=path)
    assert get_approval(rec.id, path=path).status == STATUS_EXECUTING
    # Simulate restart with short TTL
    monkeypatch.setenv("SQL_WRITE_GATE_EXECUTING_TTL_SEC", "1")
    time.sleep(1.05)
    checked = force_unknown_check(rec.id, path=path)
    assert checked.status == STATUS_UNKNOWN
    with pytest.raises(ApprovalError, match="unknown"):
        claim_for_execute(rec.id, path=path)
    # Still not claimable without explicit flag
    with pytest.raises(ApprovalError, match="unknown"):
        claim_for_execute(rec.id, path=path, allow_unknown_retry=False)


def test_fresh_executing_not_stolen(tmp_path, monkeypatch):
    path = tmp_path / "approvals.jsonl"
    monkeypatch.setenv("SQL_WRITE_GATE_EXECUTING_TTL_SEC", "3600")
    rec = enqueue_approval(sql="SELECT 1", decision=_decision(), path=path)
    claim_for_execute(rec.id, path=path)
    checked = force_unknown_check(rec.id, path=path)
    assert checked.status == STATUS_EXECUTING
    with pytest.raises(ApprovalError, match="not pending"):
        claim_for_execute(rec.id, path=path)


def test_failed_can_reclaim_unknown_cannot(tmp_path):
    path = tmp_path / "approvals.jsonl"
    rec = enqueue_approval(sql="SELECT 1", decision=_decision(), path=path)
    claim_for_execute(rec.id, path=path)
    mark_failed(rec.id, path=path)
    c2 = claim_for_execute(rec.id, path=path)
    assert c2.status == STATUS_EXECUTING
    mark_unknown(rec.id, path=path)
    with pytest.raises(ApprovalError, match="unknown"):
        claim_for_execute(rec.id, path=path)
    c3 = claim_for_execute(rec.id, path=path, allow_unknown_retry=True)
    assert c3.status == STATUS_EXECUTING


def test_mark_succeeded_idempotent(tmp_path):
    path = tmp_path / "approvals.jsonl"
    rec = enqueue_approval(sql="SELECT 1", decision=_decision(), path=path)
    a1 = mark_succeeded(rec.id, path=path)
    assert a1.status == STATUS_SUCCEEDED
    a2 = mark_succeeded(rec.id, path=path)
    assert a2.status == STATUS_SUCCEEDED
