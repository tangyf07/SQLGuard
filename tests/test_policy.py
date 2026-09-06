"""Policy-only tests (no DuckDB execute, no network, no LLM)."""

from write_gate.cases import (
    EXPIRED_WRITE_SQL,
    LEGAL_WRITE_SQL,
    PII_WRITE_SQL,
    READ_ONLY_SQL,
    SCHEMA_MISMATCH_SQL,
    TYPE_MISMATCH_SQL,
)
from write_gate.catalog import Catalog, TableSpec, load_catalog
from write_gate.policy import evaluate


def _catalog():
    return load_catalog()


def test_read_only_select_allowed():
    ev = evaluate(READ_ONLY_SQL, _catalog())
    assert ev.allowed is True
    assert ev.rule_id == "ok"
    assert ev.action == "ALLOW"


def test_legal_insert_allowed():
    ev = evaluate(LEGAL_WRITE_SQL, _catalog())
    assert ev.allowed is True
    assert ev.rule_id == "ok"


def test_expired_partition_rejected():
    ev = evaluate(EXPIRED_WRITE_SQL, _catalog())
    assert ev.allowed is False
    assert ev.rule_id == "expired_partition"
    assert "2026-08-01" in ev.message
    assert "2026-08-26" in ev.message


def test_pii_insert_rejected():
    ev = evaluate(PII_WRITE_SQL, _catalog())
    assert ev.allowed is False
    assert ev.rule_id == "pii_column"
    assert "email" in ev.message


def test_schema_unknown_column_rejected():
    ev = evaluate(SCHEMA_MISMATCH_SQL, _catalog())
    assert ev.allowed is False
    assert ev.rule_id == "schema_hallucination"
    assert "not_a_column" in ev.message


def test_schema_type_mismatch_rejected():
    ev = evaluate(TYPE_MISMATCH_SQL, _catalog())
    assert ev.allowed is False
    assert ev.rule_id == "schema_mismatch"


def test_unknown_table_rejected():
    ev = evaluate(
        "INSERT INTO no_such_table (user_id) VALUES (1)",
        _catalog(),
    )
    assert ev.allowed is False
    assert ev.rule_id == "schema_hallucination"


def test_pii_update_rejected():
    ev = evaluate(
        "UPDATE orders SET phone = '13900000000' WHERE dt = '2026-09-01'",
        _catalog(),
    )
    assert ev.allowed is False
    assert ev.rule_id == "pii_column"


def test_update_expired_partition_rejected():
    ev = evaluate(
        "UPDATE orders SET amount = 1.0 WHERE dt = '2026-08-01'",
        _catalog(),
    )
    assert ev.allowed is False
    assert ev.rule_id == "expired_partition"


def test_select_star_requires_approval_for_pii():
    ev = evaluate("SELECT * FROM orders", _catalog())
    assert ev.action == "REQUIRE_APPROVAL"
    assert ev.allowed is False
    assert ev.rule_id == "pii_column"


def test_select_pii_column_requires_approval():
    ev = evaluate("SELECT order_id, email FROM orders LIMIT 10", _catalog())
    assert ev.action == "REQUIRE_APPROVAL"
    assert ev.rule_id == "pii_column"
    assert ev.allowed is False


def test_restricted_column_write_blocked():
    base = _catalog()
    orders = base.table("orders")
    assert orders is not None
    spec = TableSpec(
        name=orders.name,
        writable=orders.writable,
        stale=orders.stale,
        partition_column=orders.partition_column,
        columns={**orders.columns, "id_card": "VARCHAR", "card_number": "VARCHAR"},
        allowed_write_columns=orders.allowed_write_columns,
        pii_columns=orders.pii_columns,
        restricted_columns=frozenset({"id_card", "card_number"}),
    )
    catalog = Catalog(
        as_of_date=base.as_of_date,
        freshness_days=base.freshness_days,
        tables={"orders": spec},
    )
    ev = evaluate(
        "INSERT INTO orders (order_id, user_id, amount, dt, status, id_card) "
        "VALUES (1, 2, 3.0, '2026-09-01', 'paid', 'X')",
        catalog,
    )
    assert ev.action == "BLOCK"
    assert ev.rule_id == "restricted_column"
