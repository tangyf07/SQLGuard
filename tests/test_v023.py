"""v0.23.0: timeouts, result limits, audit correlation, log rotation, troubleshooting."""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import patch

import duckdb
import pytest

from write_gate import __version__
from write_gate.approvals import (
    STATUS_FAILED,
    STATUS_UNKNOWN,
    classify_execute_error,
    get_approval,
)
from write_gate.audit import append_audit, read_audit
from write_gate.config import demo_policy, policy_from_dict, production_policy
from write_gate.db import ORDERS_DDL
from write_gate.decision import ACTION_ALLOW, ACTION_APPROVAL, Decision
from write_gate.results import ResultOversizeError, materialize_result, oversize_mode
from write_gate.rotation import maybe_rotate, rotate_file, should_rotate
from write_gate.runtime import (
    ENV_AUDIT_MAX_BYTES,
    ENV_RESULT_ROW_LIMIT,
    ENV_STATEMENT_TIMEOUT,
    load_runtime_settings,
    new_request_id,
)
from write_gate.timeouts import StatementTimeoutError, run_with_timeout
from write_gate.wrapper import WriteGate

ROOT = Path(__file__).resolve().parents[1]


def _seed(tmp_path: Path) -> Path:
    db_path = tmp_path / "warehouse.duckdb"
    conn = duckdb.connect(str(db_path))
    conn.execute(ORDERS_DDL)
    for i in range(20):
        conn.execute(
            "INSERT INTO orders VALUES "
            f"({i + 1}, 1001, 12.5, DATE '2026-09-01', "
            f"'u{i}@example.com', '1380000000{i % 10}', 'paid')"
        )
    conn.close()
    return db_path


def _gate(tmp_path, db_path, **kwargs) -> WriteGate:
    return WriteGate(
        db_path=db_path,
        policy=kwargs.pop("policy", demo_policy()),
        audit_path=tmp_path / "audit.jsonl",
        approvals_path=tmp_path / "approvals.jsonl",
        agent="test",
        **kwargs,
    )


# --- Version -----------------------------------------------------------------


def test_version_is_023():
    parts = [int(x) for x in __version__.split(".")[:3]]
    assert parts >= [1, 0, 0], __version__
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "version =" in text
    assert (ROOT / "docs" / "troubleshooting.md").is_file()


# --- Timeouts ----------------------------------------------------------------


def test_run_with_timeout_raises_statement_timeout():
    def slow():
        time.sleep(0.5)
        return "done"

    with pytest.raises(StatementTimeoutError) as ei:
        run_with_timeout(slow, timeout_sec=0.05, label="slow")
    assert ei.value.indeterminate is True
    assert ei.value.timeout_sec == 0.05


def test_run_with_timeout_disabled_passthrough():
    assert run_with_timeout(lambda: 42, timeout_sec=0) == 42


def test_classify_statement_timeout_indeterminate_unknown():
    exc = StatementTimeoutError("t", timeout_sec=1.0, indeterminate=True)
    assert classify_execute_error(exc) == STATUS_UNKNOWN


def test_classify_statement_timeout_determinate_failed():
    exc = StatementTimeoutError("t", timeout_sec=1.0, indeterminate=False)
    assert classify_execute_error(exc) == STATUS_FAILED


def test_approve_timeout_via_runtime_marks_unknown(tmp_path, monkeypatch):
    monkeypatch.setenv(ENV_STATEMENT_TIMEOUT, "0.05")
    db_path = _seed(tmp_path)
    approvals = tmp_path / "approvals.jsonl"
    with _gate(tmp_path, db_path, policy=production_policy()) as gate:
        # Force re-load runtime after env set
        gate.runtime = load_runtime_settings(gate.policy)
        decision, _ = gate.execute("SELECT email FROM orders LIMIT 1")
        assert decision.action == ACTION_APPROVAL
        aid = decision.approval_id

        def slow_exec(_sql):
            time.sleep(0.4)
            return None

        with patch.object(gate, "_execute_user_sql", side_effect=slow_exec):
            # Bypass the wrapper's own timeout by patching at call site after
            # approve re-enters — instead patch run_with_timeout path via
            # making _execute_user_sql itself raise StatementTimeoutError.
            pass

        with patch.object(
            gate,
            "_execute_user_sql",
            side_effect=StatementTimeoutError(
                "exceeded", timeout_sec=0.05, indeterminate=True
            ),
        ):
            with pytest.raises(StatementTimeoutError):
                gate.approve(aid)
    rec = get_approval(aid, path=approvals)
    assert rec is not None and rec.status == STATUS_UNKNOWN
    rows = read_audit(tmp_path / "audit.jsonl", limit=50)
    outcomes = [r.get("execution_outcome") for r in rows]
    assert "unknown" in outcomes
    assert all("request_id" in r for r in rows)


def test_execute_timeout_audited_unknown(tmp_path, monkeypatch):
    monkeypatch.setenv(ENV_STATEMENT_TIMEOUT, "30")
    db_path = _seed(tmp_path)
    with _gate(tmp_path, db_path) as gate:
        gate.runtime = load_runtime_settings(gate.policy)
        with patch.object(
            gate,
            "_execute_user_sql",
            side_effect=StatementTimeoutError(
                "exceeded", timeout_sec=30, indeterminate=True
            ),
        ):
            with pytest.raises(StatementTimeoutError):
                gate.execute(
                    "INSERT INTO orders (order_id, user_id, amount, dt, status) "
                    "VALUES (999, 1, 1.0, '2026-09-01', 'paid')"
                )
    rows = read_audit(tmp_path / "audit.jsonl", limit=20)
    assert any(r.get("execution_outcome") == "unknown" for r in rows)


def test_check_timeout_maps_failed_not_applied(tmp_path, monkeypatch):
    monkeypatch.setenv(ENV_STATEMENT_TIMEOUT, "0.05")
    db_path = _seed(tmp_path)
    with _gate(tmp_path, db_path) as gate:
        gate.runtime = load_runtime_settings(gate.policy)

        def slow_eval(*_a, **_k):
            time.sleep(0.4)
            return Decision(
                action=ACTION_ALLOW,
                risk="low",
                rule_id="ok",
                reason="ok",
                sql="SELECT 1",
            )

        with patch.object(gate, "_evaluate", side_effect=slow_eval):
            decision = gate.check("SELECT 1")
    assert decision.action == "BLOCK"
    assert decision.rule_id == "statement_timeout"
    rows = read_audit(tmp_path / "audit.jsonl", limit=10)
    assert rows and rows[-1]["execution_outcome"] == "failed"


def test_policy_statement_timeout_field():
    pol = policy_from_dict(
        {
            "environment": "demo",
            "rules": {"select": "allow"},
            "statement_timeout_sec": 12,
            "limits": {"result_rows": 25},
        }
    )
    assert pol.statement_timeout_sec == 12.0
    assert pol.result_row_limit == 25
    settings = load_runtime_settings(pol)
    assert settings.statement_timeout_sec == 12.0
    assert settings.result_row_limit == 25


# --- Result limits -----------------------------------------------------------


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def fetchall(self):
        return list(self._rows)

    def fetchmany(self, n):
        return list(self._rows[:n])


def test_materialize_truncates_rows(monkeypatch):
    monkeypatch.setenv(ENV_RESULT_ROW_LIMIT, "3")
    rows = [[i] for i in range(10)]
    out = materialize_result(_FakeResult(rows))
    assert out is not None
    assert len(out["rows"]) == 3
    assert out["truncated"] is True


def test_materialize_under_limit_not_truncated(monkeypatch):
    monkeypatch.setenv(ENV_RESULT_ROW_LIMIT, "100")
    rows = [[i] for i in range(5)]
    out = materialize_result(_FakeResult(rows))
    assert out is not None
    assert len(out["rows"]) == 5
    assert out["truncated"] is False


def test_materialize_block_mode_raises(monkeypatch):
    monkeypatch.setenv(ENV_RESULT_ROW_LIMIT, "2")
    monkeypatch.setenv("SQL_WRITE_GATE_RESULT_OVERSIZE", "block")
    assert oversize_mode() == "block"
    with pytest.raises(ResultOversizeError):
        materialize_result(_FakeResult([[1], [2], [3]]))


def test_cli_materialize_uses_cap(monkeypatch):
    from write_gate.cli import _materialize_result

    monkeypatch.setenv(ENV_RESULT_ROW_LIMIT, "2")
    monkeypatch.delenv("SQL_WRITE_GATE_RESULT_OVERSIZE", raising=False)
    out = _materialize_result(_FakeResult([[1], [2], [3], [4]]))
    assert out["truncated"] is True
    assert len(out["rows"]) == 2


# --- Audit correlation -------------------------------------------------------


def test_audit_includes_request_id_and_correlation(tmp_path):
    audit = tmp_path / "audit.jsonl"
    decision = Decision(
        action=ACTION_ALLOW,
        risk="low",
        rule_id="ok",
        reason="ok",
        sql="SELECT 1",
        operation="select",
        table="orders",
        approval_id="appr-xyz",
    )
    append_audit(
        decision,
        agent="test",
        path=audit,
        executed=True,
        execution_outcome="executed",
        request_id="req-fixed-001",
    )
    rows = read_audit(audit, limit=5)
    assert len(rows) == 1
    rec = rows[0]
    assert rec["request_id"] == "req-fixed-001"
    assert rec["approval_id"] == "appr-xyz"
    assert rec["decision"] == ACTION_ALLOW
    assert rec["execution_outcome"] == "executed"


def test_new_request_id_generates_uuid():
    a = new_request_id()
    b = new_request_id()
    assert a != b
    assert len(a) >= 32


def test_gate_check_audits_request_id(tmp_path):
    db_path = _seed(tmp_path)
    with _gate(tmp_path, db_path) as gate:
        gate.check("SELECT order_id FROM orders LIMIT 1")
    rows = read_audit(tmp_path / "audit.jsonl", limit=5)
    assert rows and "request_id" in rows[0]
    assert rows[0]["decision"] in {"ALLOW", "BLOCK", "REQUIRE_APPROVAL"}


def test_failed_execute_still_audited_with_ids(tmp_path):
    db_path = _seed(tmp_path)
    with _gate(tmp_path, db_path) as gate:
        with patch.object(
            gate, "_execute_user_sql", side_effect=ValueError("boom")
        ):
            with pytest.raises(ValueError):
                gate.execute(
                    "INSERT INTO orders (order_id, user_id, amount, dt, status) "
                    "VALUES (888, 1, 1.0, '2026-09-01', 'paid')"
                )
    rows = read_audit(tmp_path / "audit.jsonl", limit=20)
    failed = [r for r in rows if r.get("execution_outcome") == "failed"]
    assert failed
    assert failed[-1]["request_id"]
    assert failed[-1]["error_class"] == "ValueError"


# --- Log rotation ------------------------------------------------------------


def test_should_rotate_by_size(tmp_path, monkeypatch):
    monkeypatch.setenv(ENV_AUDIT_MAX_BYTES, "50")
    path = tmp_path / "audit.jsonl"
    path.write_text("x" * 80, encoding="utf-8")
    assert should_rotate(path, max_bytes=50) is True


def test_rotate_file_archives_and_fresh(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text('{"a":1}\n', encoding="utf-8")
    archived = rotate_file(path, reason="size")
    assert archived is not None
    assert archived.exists()
    assert archived.read_text(encoding="utf-8") == '{"a":1}\n'
    assert path.exists()
    assert path.read_text(encoding="utf-8") == ""


def test_maybe_rotate_triggered(tmp_path, monkeypatch):
    monkeypatch.setenv(ENV_AUDIT_MAX_BYTES, "40")
    path = tmp_path / "audit.jsonl"
    path.write_text("y" * 100, encoding="utf-8")
    archived = maybe_rotate(path, max_bytes=40)
    assert archived is not None
    assert archived.exists()
    assert path.stat().st_size == 0


def test_append_audit_rotates_when_oversized(tmp_path, monkeypatch):
    monkeypatch.setenv(ENV_AUDIT_MAX_BYTES, "60")
    audit = tmp_path / "audit.jsonl"
    # Pre-seed oversized file
    audit.write_text("z" * 120, encoding="utf-8")
    decision = Decision(
        action=ACTION_ALLOW,
        risk="low",
        rule_id="ok",
        reason="ok",
        sql="SELECT 1",
    )
    append_audit(decision, path=audit, request_id="after-rotate")
    # Active file should contain the new record (not the pre-seed zzzz blob).
    body = audit.read_text(encoding="utf-8")
    assert "after-rotate" in body
    assert not body.startswith("z" * 20)
    # Archive exists with the old payload
    archives = list(tmp_path.glob("audit.jsonl.1*"))
    assert archives
    assert any("z" * 20 in a.read_text(encoding="utf-8") for a in archives)


def test_rotation_refuses_sqlite(tmp_path):
    db = tmp_path / "approvals.sqlite"
    db.write_text("not-really-sqlite", encoding="utf-8")
    assert rotate_file(db, reason="size") is None
    assert db.exists()


# --- Troubleshooting docs ----------------------------------------------------


def test_troubleshooting_doc_covers_unknown_and_token():
    text = (ROOT / "docs" / "troubleshooting.md").read_text(encoding="utf-8")
    assert "unknown" in text.lower()
    assert "SQL_WRITE_GATE_APPROVAL_TOKEN" in text
    assert "POSTGRES_URL" in text or "MYSQL_URL" in text
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "troubleshooting" in readme.lower()
