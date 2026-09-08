"""SQLGuard 1.1.x: AST patterns, permissions, risk score, hallucination, audit, API."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from write_gate import WriteGate, __version__
from write_gate.api import handle_datapilot_request
from write_gate.audit import read_audit
from write_gate.catalog import load_catalog
from write_gate.config import demo_policy, policy_from_dict
from write_gate.parser import parse
from write_gate.policy import evaluate
from write_gate.sqlguard import PRODUCT

ROOT = Path(__file__).resolve().parents[1]


def test_version_is_111():
    assert __version__ == "1.1.3"
    assert 'version = "1.1.3"' in (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "## [1.1.3]" in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert PRODUCT == "SQLGuard"


def test_ast_detects_cartesian_join():
    parsed = parse("SELECT * FROM orders CROSS JOIN orders")
    assert parsed.findings.cartesian_joins
    assert "cartesian_join" in parsed.dangerous_flags


def test_ast_detects_comma_join_cartesian():
    parsed = parse("SELECT * FROM orders, orders")
    assert any(j.is_cartesian for j in parsed.findings.joins)


def test_cartesian_join_blocked():
    # Use two aliases of known table to avoid hallucination on second name
    sql = "SELECT o.order_id FROM orders o CROSS JOIN orders p"
    ev = evaluate(sql, load_catalog())
    assert ev.action == "BLOCK"
    assert ev.rule_id == "cartesian_join"
    assert ev.risk_score >= 50


def test_tautology_where_treated_as_full_table_delete():
    ev = evaluate("DELETE FROM orders WHERE 1=1", load_catalog())
    assert ev.action == "BLOCK"
    assert ev.rule_id == "delete_without_where"


def test_tautology_where_true_update():
    ev = evaluate("UPDATE orders SET status = 'x' WHERE TRUE", load_catalog())
    assert ev.action == "BLOCK"
    assert ev.rule_id == "update_without_where"


def test_schema_hallucination_unknown_table_select():
    ev = evaluate("SELECT * FROM game_sessions_not_real", load_catalog())
    assert ev.action == "BLOCK"
    assert ev.rule_id == "schema_hallucination"
    schema_ev = ev.evidence.get("schema") or ev.evidence
    assert "unknown_tables" in schema_ev or "game_sessions" in ev.reason


def test_schema_hallucination_unknown_column_select():
    ev = evaluate("SELECT not_a_real_col FROM orders", load_catalog())
    assert ev.action == "BLOCK"
    assert ev.rule_id == "schema_hallucination"


def test_schema_hallucination_unknown_column_insert():
    sql = (
        "INSERT INTO orders (order_id, user_id, amount, dt, status, not_a_column) "
        "VALUES (1, 1, 1.0, '2026-09-01', 'paid', 1)"
    )
    ev = evaluate(sql, load_catalog())
    assert ev.action == "BLOCK"
    assert ev.rule_id == "schema_hallucination"


def test_permissions_deny_table_op():
    policy = policy_from_dict(
        {
            "environment": "demo",
            "rules": {"select": "allow", "insert": "allow", "update": "allow", "delete": "allow", "ddl": "block"},
            "permissions": {"enforce": True, "tables": {"orders": ["select"]}},
        }
    )
    sql = (
        "INSERT INTO orders (order_id, user_id, amount, dt, status) "
        "VALUES (910001, 1, 1.0, '2026-09-01', 'paid')"
    )
    ev = evaluate(sql, load_catalog(), policy=policy)
    assert ev.action == "BLOCK"
    assert ev.rule_id == "table_permission"


def test_permissions_allow_listed_op():
    policy = policy_from_dict(
        {
            "environment": "demo",
            "rules": {"select": "allow", "insert": "allow", "update": "allow", "delete": "allow", "ddl": "block"},
            "permissions": {"enforce": True, "tables": {"orders": ["select", "insert"]}},
        }
    )
    sql = (
        "INSERT INTO orders (order_id, user_id, amount, dt, status) "
        "VALUES (910002, 1, 1.0, '2026-09-01', 'paid')"
    )
    ev = evaluate(sql, load_catalog(), policy=policy)
    assert ev.action == "ALLOW"
    assert isinstance(ev.risk_score, int)
    assert 0 <= ev.risk_score <= 100


def test_risk_score_on_decision_dict():
    ev = evaluate("DELETE FROM orders", load_catalog())
    d = ev.to_dict()
    assert "risk_score" in d
    assert "risk_factors" in d
    assert d["risk_score"] >= 50
    assert "block" in d["risk_factors"] or "missing_where" in d["risk_factors"] or "delete" in d["risk_factors"]


def test_richer_audit_fields(tmp_path):
    audit = tmp_path / "audit.jsonl"
    gate = WriteGate(
        db_path=tmp_path / "wh.duckdb",
        policy=demo_policy(),
        audit_path=audit,
        agent="test",
        actor="datapilot-bot",
        model_id="gpt-test",
        prompt_summary="delete all orders",
    )
    gate.check("DELETE FROM orders")
    rows = read_audit(audit, limit=5)
    assert len(rows) == 1
    rec = rows[0]
    assert rec["actor"] == "datapilot-bot"
    assert rec["model_id"] == "gpt-test"
    assert rec["prompt_summary"] == "delete all orders"
    assert "risk_score" in rec
    assert "latency_ms" in rec
    assert rec["success"] is False
    assert rec["decision"] == "BLOCK"


def test_datapilot_api_check_and_execute(tmp_path):
    # Use isolated db copy of seed if present
    defaults = {
        "db_path": str(ROOT / "seed" / "warehouse.duckdb"),
        "policy": str(ROOT / "examples" / "policy.demo.yaml"),
        "agent": "datapilot",
    }
    status, payload = handle_datapilot_request(
        "POST",
        "/v1/check",
        {"sql": "DELETE FROM orders", "actor": "pilot", "model_id": "m1"},
        defaults=defaults,
    )
    assert status == 200
    assert payload["action"] == "BLOCK"
    assert payload["executed"] is False
    assert payload["product"] == "SQLGuard"
    assert payload["risk_score"] >= 50

    status, health = handle_datapilot_request("GET", "/healthz", None, defaults=defaults)
    assert status == 200
    assert health["ok"] is True
    assert health["version"] == "1.1.3"

    # Legal insert — use check (no mutate shared seed); execute path covered by demo
    status, payload = handle_datapilot_request(
        "POST",
        "/v1/check",
        {
            "sql": (
                "INSERT INTO orders (order_id, user_id, amount, dt, status) "
                "VALUES (910099, 1, 1.0, '2026-09-01', 'paid')"
            ),
            "actor": "pilot",
        },
        defaults=defaults,
    )
    assert status == 200
    assert payload["action"] == "ALLOW"
    assert payload["executed"] is False
    assert payload["risk_score"] >= 0


def test_explain_degrades_offline():
    from write_gate.explain import estimate_cost

    cost, plan, skip = estimate_cost(None, "SELECT 1")
    assert cost is None
    assert skip == "no connection"


def test_registry_can_register_custom_guard():
    from write_gate.decision import GuardResult, VERDICT_BLOCK
    from write_gate.registry import GuardRegistry, default_registry

    reg = GuardRegistry()
    for name, fn in zip(default_registry().names(), default_registry().functions()):
        reg.register(name, fn)

    def boom(ctx):
        return GuardResult.block("custom", "custom_rule", "custom blocked")

    reg.register("custom", boom, before="environment")
    assert "custom" in reg.names()
    from write_gate.engine import evaluate
    from write_gate.catalog import load_catalog
    from write_gate.config import demo_policy

    ev = evaluate("SELECT order_id FROM orders", load_catalog(), policy=demo_policy(), registry=reg)
    assert ev.action == "BLOCK"
    assert ev.rule_id == "custom_rule"


def test_ddl_drop_sets_dangerous_flags():
    parsed = parse("DROP TABLE orders")
    assert "ddl" in parsed.dangerous_flags or parsed.operation == "ddl"
    ev = evaluate("DROP TABLE orders", load_catalog())
    assert ev.action == "BLOCK"
    assert ev.rule_id == "drop_table"


def test_datapilot_field_on_api_response():
    defaults = {
        "db_path": str(ROOT / "seed" / "warehouse.duckdb"),
        "policy": str(ROOT / "examples" / "policy.demo.yaml"),
    }
    status, payload = handle_datapilot_request(
        "POST", "/v1/check", {"sql": "DELETE FROM orders"}, defaults=defaults
    )
    assert status == 200
    assert payload.get("datapilot") == "BLOCK"


def test_datapilot_http_routes_check_block_execute(tmp_path):
    """HTTP-only path DataPilot can rely on: check / block / execute (+ datapilot alias)."""
    import shutil

    from write_gate.paths import SEED_DIR

    seed_db = SEED_DIR / "warehouse.duckdb"
    if not seed_db.is_file():
        seed_db = ROOT / "seed" / "warehouse.duckdb"
    assert seed_db.is_file(), f"missing seed duckdb at {seed_db}; run make seed"
    db = tmp_path / "wh.duckdb"
    shutil.copy(seed_db, db)
    defaults = {
        "db_path": str(db),
        "policy": str(ROOT / "examples" / "policy.demo.yaml"),
        "agent": "datapilot",
    }
    block_sql = "DELETE FROM orders"
    allow_sql = (
        "INSERT INTO orders (order_id, user_id, amount, dt, status) "
        "VALUES (910088, 1, 1.0, '2026-09-01', 'paid')"
    )

    status, payload = handle_datapilot_request(
        "POST", "/v1/check", {"sql": block_sql}, defaults=defaults
    )
    assert status == 200
    assert payload["action"] == "BLOCK"
    assert payload["executed"] is False
    assert payload.get("datapilot") == "BLOCK"

    status, payload = handle_datapilot_request(
        "POST", "/v1/block", {"sql": block_sql}, defaults=defaults
    )
    assert status == 200
    assert payload["action"] == "BLOCK"
    assert payload["executed"] is False

    status, payload = handle_datapilot_request(
        "POST", "/v1/execute", {"sql": block_sql}, defaults=defaults
    )
    assert status == 200
    assert payload["action"] == "BLOCK"
    assert payload["executed"] is False

    status, payload = handle_datapilot_request(
        "POST", "/v1/execute", {"sql": allow_sql}, defaults=defaults
    )
    assert status == 200
    assert payload["action"] == "ALLOW"
    assert payload["executed"] is True
    assert payload.get("datapilot") == "EXECUTE"

    # /v1/datapilot is alias of execute (gate then run on ALLOW)
    allow_sql2 = (
        "INSERT INTO orders (order_id, user_id, amount, dt, status) "
        "VALUES (910089, 1, 1.0, '2026-09-01', 'paid')"
    )
    status, payload = handle_datapilot_request(
        "POST", "/v1/datapilot", {"sql": allow_sql2}, defaults=defaults
    )
    assert status == 200
    assert payload["action"] == "ALLOW"
    assert payload["executed"] is True
    assert payload.get("datapilot") == "EXECUTE"

    status, payload = handle_datapilot_request(
        "POST", "/v1/datapilot", {"sql": block_sql}, defaults=defaults
    )
    assert status == 200
    assert payload["action"] == "BLOCK"
    assert payload["executed"] is False


def test_permissions_table_outside_allowlist_blocks():
    """Unknown table relative to permissions allowlist → BLOCK (table_permission)."""
    policy = policy_from_dict(
        {
            "environment": "demo",
            "rules": {
                "select": "allow",
                "insert": "allow",
                "update": "allow",
                "delete": "allow",
                "ddl": "block",
            },
            "permissions": {"enforce": True, "tables": {"ads_dau_di": ["select"]}},
            "hallucination": {
                "allow_unknown_tables": False,
                "allow_unknown_columns": False,
            },
        }
    )
    # orders is in catalog but not in permissions allowlist
    ev = evaluate("SELECT order_id FROM orders", load_catalog(), policy=policy)
    assert ev.action == "BLOCK"
    assert ev.rule_id == "table_permission"


def test_allow_unknown_columns_false_blocks_hallucination():
    policy = policy_from_dict(
        {
            "environment": "demo",
            "rules": {
                "select": "allow",
                "insert": "allow",
                "update": "allow",
                "delete": "allow",
                "ddl": "block",
            },
            "hallucination": {
                "allow_unknown_tables": False,
                "allow_unknown_columns": False,
            },
        }
    )
    assert policy.allow_unknown_columns is False
    ev = evaluate("SELECT not_a_real_col FROM orders", load_catalog(), policy=policy)
    assert ev.action == "BLOCK"
    assert ev.rule_id == "schema_hallucination"


def test_cross_db_same_name_does_not_match_bare_orders():
    """other.orders / evil.orders must NOT collapse to catalog/allowlist key orders."""
    parsed = parse("SELECT order_id FROM other.orders")
    assert parsed.table == "other.orders"
    assert "other.orders" in parsed.tables_referenced
    assert "orders" not in parsed.tables_referenced or parsed.table != "orders"

    parsed2 = parse("SELECT * FROM ads.t")
    assert parsed2.table == "ads.t"
    assert "ads.t" in parsed2.tables_referenced

    policy = policy_from_dict(
        {
            "environment": "demo",
            "rules": {
                "select": "allow",
                "insert": "allow",
                "update": "allow",
                "delete": "allow",
                "ddl": "block",
            },
            "permissions": {"enforce": True, "tables": {"orders": ["select"]}},
            "hallucination": {
                "allow_unknown_tables": False,
                "allow_unknown_columns": False,
            },
        }
    )
    assert policy.allow_unknown_tables is False
    # Catalog + allowlist have bare orders; qualified ref must BLOCK
    for sql in (
        "SELECT order_id FROM other.orders",
        "SELECT order_id FROM evil.orders",
    ):
        ev = evaluate(sql, load_catalog(), policy=policy)
        assert ev.action == "BLOCK", (sql, ev.rule_id, ev.reason)
        # Must not treat as known bare orders (ALLOW)
        assert ev.rule_id in {"schema_hallucination", "table_permission"}

    # Bare name still works (DataPilot / G7 style)
    bare = parse("SELECT order_id FROM ads_dau_di")
    assert bare.table == "ads_dau_di"
    assert bare.tables_referenced == ["ads_dau_di"]
