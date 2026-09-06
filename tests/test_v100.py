"""v1.0.0: support-matrix pilot-ready contracts (version, exports, unsupported, docs)."""

from __future__ import annotations

from pathlib import Path

import pytest

from write_gate import Decision, Evidence, WriteGate, __version__
from write_gate.catalog import load_catalog
from write_gate.config import demo_policy
from write_gate.decision import ACTION_BLOCK
from write_gate.engine import evaluate
from write_gate.parser import parse

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_DECISION_FIELDS = {
    "allowed",
    "rule_id",
    "message",
    "sql",
    "action",
    "risk",
    "reason",
    "evidence",
    "operation",
    "table",
    "estimated_rows",
    "approval_id",
}

# Samples aligned with test_v022 matrix + README unsupported table.
UNSUPPORTED_CASES = [
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
        "INSERT INTO orders (order_id, user_id, amount, dt, status) "
        "VALUES (1, 1, 1.0, '2026-09-01', 'paid'); "
        "DELETE FROM orders",
        "duckdb",
    ),
    (
        "MERGE INTO orders USING (SELECT 1 AS id) s ON false WHEN MATCHED THEN DELETE",
        "postgres",
    ),
    ("SELECT * INTO orders_copy FROM orders", "postgres"),
]


def test_version_is_100():
    parts = [int(x) for x in __version__.split(".")[:3]]
    assert parts >= [1, 0, 0], __version__
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "version =" in text
    init = (ROOT / "src" / "write_gate" / "__init__.py").read_text(encoding="utf-8")
    assert "__version__ =" in init


def test_public_exports():
    assert WriteGate is not None
    assert Decision is not None
    assert Evidence is Decision
    from write_gate import __all__

    for name in ("WriteGate", "Decision", "Evidence"):
        assert name in __all__
    for meth in ("check", "execute", "approve", "reject", "close"):
        assert callable(getattr(WriteGate, meth))


def test_decision_json_fields():
    d = Decision(
        action=ACTION_BLOCK,
        risk="critical",
        rule_id="unsupported_sql",
        reason="test",
        sql="SELECT 1; SELECT 2",
        operation=None,
        table=None,
    )
    payload = d.to_dict()
    assert REQUIRED_DECISION_FIELDS <= set(payload.keys())
    assert payload["allowed"] is False
    assert payload["message"] == payload["reason"]


@pytest.mark.parametrize("sql,dialect", UNSUPPORTED_CASES)
def test_unsupported_sql_still_blocks(sql: str, dialect: str):
    parsed = parse(sql, dialect=dialect)
    assert parsed.error_rule == "unsupported_sql", (
        f"expected unsupported_sql, got error_rule={parsed.error_rule!r} error={parsed.error!r}"
    )
    ev = evaluate(sql, load_catalog(), policy=demo_policy(), dialect=dialect)
    assert ev.action == "BLOCK"
    assert ev.rule_id == "unsupported_sql"


def test_readme_pilot_ready_not_prototype():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    fold = text.split("## Backlog")[0]
    assert "pilot-ready" in fold.lower()
    assert "非生产唯一边界" in fold
    assert "非唯一边界" in fold
    low = fold.lower()
    assert "early prototype" not in low
    assert "early gate prototype" not in low
    for name in ("DuckDB", "PostgreSQL", "MySQL", "SQLite"):
        assert name in fold
    for cmd in ("check", "hook", "mcp", "proxy", "approve"):
        assert cmd in fold
    assert "unsupported_sql" in fold
    assert "sole" in low and "boundary" in low


def test_v1_docs_exist():
    docs = ROOT / "docs"
    for name in (
        "compatibility.md",
        "upgrade-0.23-to-1.0.md",
        "pilot-checklist.md",
        "v1-acceptance.md",
        "troubleshooting.md",
    ):
        path = docs / name
        assert path.is_file(), name
        body = path.read_text(encoding="utf-8")
        assert "非生产唯一边界" in body


def test_changelog_has_100():
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "## [1.0.0]" in text
    assert "pilot-ready" in text.lower()
    assert "非生产唯一边界" in text


def test_compatibility_mentions_semver():
    text = (ROOT / "docs" / "compatibility.md").read_text(encoding="utf-8")
    assert "SemVer" in text or "semver" in text.lower()
    assert "WriteGate" in text
    assert "unsupported_sql" in text


def test_upgrade_doc_covers_approvals_and_token():
    text = (ROOT / "docs" / "upgrade-0.23-to-1.0.md").read_text(encoding="utf-8")
    assert "approvals" in text.lower()
    assert "sqlite" in text.lower()
    assert "SQL_WRITE_GATE_APPROVAL_TOKEN" in text
    assert "SQL_WRITE_GATE_APPROVAL_KEY_FILE" in text or "approval.key" in text
