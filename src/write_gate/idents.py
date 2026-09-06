"""Shared SQL identifier / literal helpers (breaks parser ↔ ast_patterns cycle)."""

from __future__ import annotations

from typing import Any

from sqlglot import exp


def ident(node: exp.Expression | None) -> str | None:
    if node is None:
        return None
    if isinstance(node, exp.Table):
        return node.name.lower() if node.name else None
    if isinstance(node, exp.Schema):
        return ident(node.this)
    if isinstance(node, exp.Identifier):
        return node.name.lower()
    if isinstance(node, exp.Column):
        return node.name.lower() if node.name else None
    name = getattr(node, "name", None)
    return str(name).lower() if name else None


def literal_value(node: exp.Expression | None) -> Any:
    if node is None:
        return None
    if isinstance(node, exp.Null):
        return None
    if isinstance(node, exp.Cast):
        return literal_value(node.this)
    if isinstance(node, (exp.TsOrDsToDate, exp.Date)):
        return literal_value(node.this) if node.this else node.sql()
    if isinstance(node, exp.Literal):
        raw = node.this
        if node.is_int:
            try:
                return int(raw)
            except (TypeError, ValueError):
                return raw
        if node.is_number:
            try:
                return float(raw)
            except (TypeError, ValueError):
                return raw
        return str(raw)
    sql = node.sql(dialect="duckdb").strip().strip("'\"")
    return sql
