"""Audit log JSONL + CLI table."""

import json
import re

from write_gate.audit import (
    format_audit_table,
    format_audit_time,
    format_sql_for_audit,
    hash_sql,
    read_audit,
    redact_sql_literals,
)
from write_gate.cases import LEGAL_WRITE_SQL
from write_gate.cli import main
from write_gate.config import demo_policy, production_policy
from write_gate.wrapper import WriteGate

HEADERS = ("TIME", "SOURCE", "OP", "TABLE", "VERDICT")
DELETE_SQL = "DELETE FROM orders"
SELECT_SQL = "SELECT order_id FROM orders LIMIT 1"


def test_check_appends_audit_jsonl(tmp_path):
    audit = tmp_path / "audit.jsonl"
    gate = WriteGate(
        db_path=tmp_path / "wh.duckdb",
        policy=demo_policy(),
        audit_path=audit,
        agent="test",
    )
    ev = gate.check(LEGAL_WRITE_SQL)
    assert ev.action == "ALLOW"
    rows = read_audit(audit, limit=10)
    assert len(rows) == 1
    rec = rows[0]
    assert rec["agent"] == "test"
    assert rec["environment"] == "demo"
    # Default audit_sql_mode=redact scrubs literals
    assert rec["sql"] == format_sql_for_audit(LEGAL_WRITE_SQL, mode="redact")
    assert "18.50" not in rec["sql"]
    assert "'2026-09-01'" not in rec["sql"]
    assert rec["operation"] == "insert"
    assert rec["table"] == "orders"
    assert rec["decision"] == "ALLOW"
    assert rec["rule_id"] == "ok"
    assert "timestamp" in rec
    table = format_audit_table(rows)
    assert "ALLOW" in table
    assert "insert" in table
    for header in HEADERS:
        assert header in table


def test_format_audit_table_maps_require_approval_and_time():
    rows = [
        {
            "timestamp": "2026-09-02T16:40:21.025314+00:00",
            "agent": "cli",
            "operation": "insert",
            "table": "orders",
            "decision": "REQUIRE_APPROVAL",
            "rule_id": "environment_policy",
        }
    ]
    table = format_audit_table(rows)
    assert "TIME" in table
    assert "SOURCE" in table
    assert "VERDICT" in table
    assert "APPROVAL" in table
    assert "REQUIRE_APPROVAL" not in table
    assert "2026-09-03 00:40" in table
    assert format_audit_time(rows[0]["timestamp"]) == "2026-09-03 00:40"


def test_format_audit_table_empty():
    assert format_audit_table([]) == "(no audit records)"
    assert format_audit_table(()) == "(no audit records)"


def test_cli_audit_human_table_after_check(tmp_path, capsys):
    audit = tmp_path / "audit.jsonl"
    gate = WriteGate(
        db_path=tmp_path / "wh.duckdb",
        policy=production_policy(),
        audit_path=audit,
        agent="test",
    )
    blocked = gate.check(DELETE_SQL)
    pending = gate.check(LEGAL_WRITE_SQL)
    allowed = gate.check(SELECT_SQL)
    assert blocked.action == "BLOCK"
    assert pending.action == "REQUIRE_APPROVAL"
    assert allowed.action == "ALLOW"

    rc = main(["audit", "--audit-path", str(audit), "--limit", "20"])
    out = capsys.readouterr().out
    assert rc == 0
    for header in HEADERS:
        assert header in out
    assert "BLOCK" in out
    assert "APPROVAL" in out
    assert "ALLOW" in out
    assert "orders" in out
    assert "delete" in out
    assert "insert" in out
    assert "select" in out
    assert "test" in out
    assert "REQUIRE_APPROVAL" not in out
    assert re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}", out)

    lines = [ln for ln in audit.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) == 3
    decisions = []
    for line in lines:
        rec = json.loads(line)
        decisions.append(rec["decision"])
        assert rec["agent"] == "test"
        assert rec["table"] == "orders"
        assert "timestamp" in rec
        assert "operation" in rec
        assert "rule_id" in rec
    assert decisions == ["BLOCK", "REQUIRE_APPROVAL", "ALLOW"]


def test_cli_audit_empty_message(tmp_path, capsys):
    missing = tmp_path / "missing.jsonl"
    rc = main(["audit", "--audit-path", str(missing)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "no audit records" in out.lower()


def test_audit_sql_mode_redact_hash_plain(tmp_path, monkeypatch):
    from write_gate.audit import append_audit
    from write_gate.decision import ACTION_ALLOW, Decision

    sql = LEGAL_WRITE_SQL
    redacted = redact_sql_literals(sql)
    assert "18.50" not in redacted
    assert "'2026-09-01'" not in redacted
    assert hash_sql(sql).startswith("sha256:")

    audit = tmp_path / "a.jsonl"
    decision = Decision(
        action=ACTION_ALLOW,
        risk="low",
        rule_id="ok",
        reason="ok",
        sql=sql,
        operation="insert",
        table="orders",
    )
    append_audit(decision, path=audit, audit_sql_mode="plain", environment="demo")
    assert read_audit(audit, limit=1)[0]["sql"] == sql

    audit2 = tmp_path / "b.jsonl"
    append_audit(decision, path=audit2, audit_sql_mode="hash", environment="demo")
    assert read_audit(audit2, limit=1)[0]["sql"] == hash_sql(sql)

    monkeypatch.setenv("SQL_WRITE_GATE_AUDIT_SQL_MODE", "plain")
    audit3 = tmp_path / "c.jsonl"
    append_audit(decision, path=audit3, environment="demo")
    assert read_audit(audit3, limit=1)[0]["sql"] == sql

