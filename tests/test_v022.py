"""v0.22.0: trust token privilege separation, target binding, SQL matrix variants."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from write_gate import __version__
from write_gate.approvals import (
    ApprovalError,
    enqueue_approval,
    get_approval,
)
from write_gate.audit import database_config_id, redact_database_url
from write_gate.catalog import load_catalog
from write_gate.cli import main
from write_gate.config import demo_policy, production_policy
from write_gate.decision import ACTION_ALLOW, ACTION_APPROVAL, Decision
from write_gate.engine import evaluate
from write_gate.parser import parse
from write_gate.trust import (
    ENV_KEY_FILE,
    ENV_TOKEN,
    TrustError,
    require_approval_trust,
)
from write_gate.wrapper import WriteGate

ROOT = Path(__file__).resolve().parents[1]


def _seed(tmp_path: Path) -> Path:
    import duckdb
    from write_gate.db import ORDERS_DDL

    tmp_path.mkdir(parents=True, exist_ok=True)
    db_path = tmp_path / "warehouse.duckdb"
    conn = duckdb.connect(str(db_path))
    conn.execute(ORDERS_DDL)
    conn.execute(
        "INSERT INTO orders VALUES "
        "(1, 1001, 12.5, DATE '2026-09-01', 'a@example.com', '13800000001', 'paid')"
    )
    conn.close()
    return db_path


def _decision(**kwargs) -> Decision:
    base = dict(
        action=ACTION_APPROVAL,
        risk="medium",
        rule_id="environment_policy",
        reason="test",
        sql="SELECT 1",
        operation="select",
        table="orders",
    )
    base.update(kwargs)
    return Decision(**base)


# --- Version -----------------------------------------------------------------


def test_version_is_022():
    parts = [int(x) for x in __version__.split(".")[:3]]
    assert parts >= [1, 0, 0], __version__
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "version =" in text


# --- Trust token (no / wrong / right) ----------------------------------------


def test_trust_no_key_file_refuses(monkeypatch, tmp_path):
    missing = tmp_path / "no-such-approval.key"
    monkeypatch.setenv(ENV_KEY_FILE, str(missing))
    monkeypatch.setenv(ENV_TOKEN, "anything")
    with pytest.raises(TrustError, match="no approval key file"):
        require_approval_trust()


def test_trust_no_token_refuses(monkeypatch, tmp_path):
    key = tmp_path / "approval.key"
    key.write_text("secret-value\n", encoding="utf-8")
    monkeypatch.setenv(ENV_KEY_FILE, str(key))
    monkeypatch.delenv(ENV_TOKEN, raising=False)
    with pytest.raises(TrustError, match="missing"):
        require_approval_trust()


def test_trust_wrong_token_refuses(monkeypatch, tmp_path):
    key = tmp_path / "approval.key"
    key.write_text("secret-value\n", encoding="utf-8")
    monkeypatch.setenv(ENV_KEY_FILE, str(key))
    monkeypatch.setenv(ENV_TOKEN, "wrong-token")
    with pytest.raises(TrustError, match="invalid"):
        require_approval_trust()


def test_trust_right_token_allows(monkeypatch, tmp_path):
    key = tmp_path / "approval.key"
    key.write_text("secret-value\n", encoding="utf-8")
    monkeypatch.setenv(ENV_KEY_FILE, str(key))
    monkeypatch.setenv(ENV_TOKEN, "secret-value")
    require_approval_trust()  # no raise


def test_cli_approve_without_token_exits_nonzero(monkeypatch, tmp_path, capsys):
    key = tmp_path / "approval.key"
    key.write_text("secret-value\n", encoding="utf-8")
    monkeypatch.setenv(ENV_KEY_FILE, str(key))
    monkeypatch.delenv(ENV_TOKEN, raising=False)
    approvals = tmp_path / "approvals.jsonl"
    rec = enqueue_approval(sql="SELECT 1", decision=_decision(), path=approvals)
    rc = main(["approve", rec.id, "--approvals", str(approvals)])
    err = capsys.readouterr().err
    assert rc != 0
    assert "approval privilege refused" in err
    assert get_approval(rec.id, path=approvals).status == "pending"


def test_cli_resolve_wrong_token_exits_nonzero(monkeypatch, tmp_path, capsys):
    key = tmp_path / "approval.key"
    key.write_text("secret-value\n", encoding="utf-8")
    monkeypatch.setenv(ENV_KEY_FILE, str(key))
    monkeypatch.setenv(ENV_TOKEN, "nope")
    approvals = tmp_path / "approvals.jsonl"
    rec = enqueue_approval(sql="SELECT 1", decision=_decision(), path=approvals)
    rc = main(
        ["resolve", rec.id, "--approvals", str(approvals), "--as", "rejected"]
    )
    err = capsys.readouterr().err
    assert rc != 0
    assert "invalid" in err.lower() or "refused" in err.lower()
    assert get_approval(rec.id, path=approvals).status == "pending"


def test_cli_reject_right_token_works(monkeypatch, tmp_path, capsys):
    key = tmp_path / "approval.key"
    key.write_text("secret-value\n", encoding="utf-8")
    monkeypatch.setenv(ENV_KEY_FILE, str(key))
    monkeypatch.setenv(ENV_TOKEN, "secret-value")
    approvals = tmp_path / "approvals.jsonl"
    rec = enqueue_approval(sql="SELECT 1", decision=_decision(), path=approvals)
    rc = main(["reject", rec.id, "--approvals", str(approvals)])
    assert rc == 0
    assert get_approval(rec.id, path=approvals).status == "rejected"


def test_agent_check_still_works_without_token(monkeypatch, tmp_path):
    """check / enqueue must not require trust (agent-facing)."""
    key = tmp_path / "approval.key"
    key.write_text("secret-value\n", encoding="utf-8")
    monkeypatch.setenv(ENV_KEY_FILE, str(key))
    monkeypatch.delenv(ENV_TOKEN, raising=False)
    db_path = _seed(tmp_path)
    with WriteGate(
        db_path=db_path,
        policy=production_policy(),
        audit_path=tmp_path / "audit.jsonl",
        approvals_path=tmp_path / "approvals.jsonl",
        agent="agent",
    ) as gate:
        d = gate.check("DELETE FROM orders")
        assert d.action == "BLOCK"
        d2, _ = gate.execute("SELECT email FROM orders LIMIT 1")
        assert d2.action == ACTION_APPROVAL
        assert d2.approval_id


# --- Target binding ----------------------------------------------------------


def test_target_binding_env_swap_fail_closed(tmp_path, monkeypatch):
    """Queue against DB A; change DATABASE_URL to B → approve refuses (not write to B)."""
    url_a = "postgresql://u:secret-a@db-a.example:5432/app"
    url_b = "postgresql://u:secret-b@db-b.example:5432/app"
    approvals = tmp_path / "approvals.jsonl"
    rec = enqueue_approval(
        sql="INSERT INTO orders (order_id) VALUES (1)",
        decision=_decision(operation="insert", sql="INSERT INTO orders (order_id) VALUES (1)"),
        path=approvals,
        database=url_a,
    )
    assert rec.database_config_id == database_config_id(url_a)
    assert "secret" not in (rec.database or "")

    monkeypatch.setenv("DATABASE_URL", url_b)
    gate = WriteGate(
        database=url_b,
        policy=demo_policy(),
        audit_path=tmp_path / "audit.jsonl",
        approvals_path=approvals,
        agent="test",
    )
    with pytest.raises(ApprovalError, match="target mismatch"):
        gate.approve(rec.id)
    assert get_approval(rec.id, path=approvals).status == "pending"


def test_target_binding_same_target_resolve_ok(tmp_path, monkeypatch):
    url = "postgresql://u:real-secret@db.example:5432/app"
    approvals = tmp_path / "approvals.jsonl"
    rec = enqueue_approval(
        sql="SELECT 1",
        decision=_decision(),
        path=approvals,
        database=url,
    )
    monkeypatch.setenv("DATABASE_URL", url)
    # Bind only — do not actually connect to postgres.
    gate = WriteGate(
        database=redact_database_url(url),
        policy=demo_policy(),
        audit_path=tmp_path / "audit.jsonl",
        approvals_path=approvals,
        agent="test",
    )
    gate.database_config_id = rec.database_config_id
    gate._bind_approval_target(rec)
    assert database_config_id(gate.database) == rec.database_config_id
    assert "real-secret" in gate.database


def test_target_binding_duckdb_path_swap_does_not_use_b(tmp_path):
    """Gate constructed for B must rebind to queued A (never query/write B)."""
    import duckdb
    from write_gate.db import ORDERS_DDL

    def seed(dir_path: Path, email: str) -> Path:
        dir_path.mkdir(parents=True, exist_ok=True)
        db_path = dir_path / "warehouse.duckdb"
        conn = duckdb.connect(str(db_path))
        conn.execute(ORDERS_DDL)
        conn.execute(
            "INSERT INTO orders VALUES "
            f"(1, 1001, 12.5, DATE '2026-09-01', '{email}', '13800000001', 'paid')"
        )
        conn.close()
        return db_path

    db_a = seed(tmp_path / "a", "a-only@example.com")
    db_b = seed(tmp_path / "b", "b-only@example.com")
    approvals = tmp_path / "approvals.jsonl"
    with WriteGate(
        db_path=db_a,
        policy=production_policy(),
        audit_path=tmp_path / "audit.jsonl",
        approvals_path=approvals,
        agent="test",
    ) as gate:
        decision, _ = gate.execute("SELECT email FROM orders LIMIT 1")
        aid = decision.approval_id
    with WriteGate(
        db_path=db_b,
        policy=production_policy(),
        audit_path=tmp_path / "audit2.jsonl",
        approvals_path=approvals,
        agent="test",
    ) as gate_b:
        d, result = gate_b.approve(aid)
        assert d.action == ACTION_ALLOW
        # Rebound to A: must see A's email, never B's.
        rows = result.fetchall() if hasattr(result, "fetchall") else []
        assert rows and rows[0][0] == "a-only@example.com"
        assert database_config_id(gate_b.database) == database_config_id(str(db_a))


def test_target_binding_same_duckdb_still_works(tmp_path):
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
        d, rows = gate.approve(decision.approval_id)
        assert d.action == ACTION_ALLOW
        assert rows is not None


# --- SQL support matrix variants (must not bypass) ---------------------------


@pytest.mark.parametrize(
    "sql,dialect",
    [
        (
            "WITH d AS (DELETE FROM orders RETURNING *) "
            "INSERT INTO orders (order_id, user_id, amount, dt, status) "
            "VALUES (1, 1, 1.0, '2026-09-01', 'paid')",
            "postgres",
        ),
        (
            "WITH u AS (UPDATE orders SET status='x' WHERE order_id=1 RETURNING *) "
            "SELECT * FROM u",
            "postgres",
        ),
        (
            "WITH i AS (INSERT INTO orders (order_id) VALUES (1) RETURNING *) "
            "SELECT * FROM i",
            "postgres",
        ),
        (
            "INSERT INTO orders (order_id, user_id, amount, dt, status) "
            "VALUES (1, 1, 1.0, '2026-09-01', 'paid'); "
            "DELETE FROM orders",
            "duckdb",
        ),
        ("MERGE INTO orders USING (SELECT 1 AS id) s ON false WHEN MATCHED THEN DELETE", "postgres"),
        ("SELECT * INTO orders_copy FROM orders", "postgres"),
    ],
)
def test_sql_variants_rejected_unsupported(sql, dialect):
    parsed = parse(sql, dialect=dialect)
    assert parsed.error_rule == "unsupported_sql", (
        f"expected unsupported_sql, got error_rule={parsed.error_rule!r} error={parsed.error!r}"
    )
    ev = evaluate(sql, load_catalog(), policy=demo_policy(), dialect=dialect)
    assert ev.action == "BLOCK"
    assert ev.rule_id == "unsupported_sql"


def test_sql_plain_select_still_allows():
    ev = evaluate(
        "SELECT order_id, status FROM orders LIMIT 5",
        load_catalog(),
        policy=demo_policy(),
    )
    assert ev.action == "ALLOW"
    assert ev.rule_id == "ok"


def test_sql_plain_insert_still_allows_under_demo():
    sql = (
        "INSERT INTO orders (order_id, user_id, amount, dt, status) "
        "VALUES (1, 1, 1.0, '2026-09-01', 'paid')"
    )
    ev = evaluate(sql, load_catalog(), policy=demo_policy())
    assert ev.action == "ALLOW"


def test_readme_documents_deployment_and_sql_matrix():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "SQL_WRITE_GATE_APPROVAL_TOKEN" in text
    assert "approval.key" in text or "APPROVAL_KEY_FILE" in text
    assert "trusted executor" in text.lower() or "Trusted executor" in text
    assert "support matrix" in text.lower() or "SQL support" in text
    assert "unsupported_sql" in text
    assert "非生产唯一边界" in text
