"""AST pattern helpers: joins, tautology WHERE, referenced tables/columns.

Builds on sqlglot Expression trees from ``parser.parse`` — never regex.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlglot import exp

from write_gate.idents import ident, literal_value


@dataclass
class JoinInfo:
    """One JOIN (including implicit comma joins)."""

    kind: str  # CROSS | INNER | LEFT | RIGHT | FULL | COMMA | UNKNOWN
    has_predicate: bool
    is_cartesian: bool
    right_table: str | None = None
    sql: str = ""


@dataclass
class AstFindings:
    """Structured AST signals surfaced on ParsedSQL / guards."""

    tables: list[str] = field(default_factory=list)
    columns: list[str] = field(default_factory=list)
    joins: list[JoinInfo] = field(default_factory=list)
    cartesian_joins: list[JoinInfo] = field(default_factory=list)
    missing_where: bool = False
    tautology_where: bool = False
    full_table_write: bool = False
    is_ddl: bool = False
    is_dml: bool = False
    dangerous_flags: list[str] = field(default_factory=list)

    def to_evidence(self) -> dict[str, Any]:
        return {
            "tables": list(self.tables),
            "columns": list(self.columns),
            "joins": [
                {
                    "kind": j.kind,
                    "has_predicate": j.has_predicate,
                    "is_cartesian": j.is_cartesian,
                    "right_table": j.right_table,
                }
                for j in self.joins
            ],
            "cartesian_joins": len(self.cartesian_joins),
            "missing_where": self.missing_where,
            "tautology_where": self.tautology_where,
            "full_table_write": self.full_table_write,
            "is_ddl": self.is_ddl,
            "is_dml": self.is_dml,
            "dangerous_flags": list(self.dangerous_flags),
        }


def _join_kind(join: exp.Join) -> str:
    kind = join.args.get("kind")
    if kind is not None:
        text = str(kind).upper()
        if text:
            return text
    # Implicit comma join: JOIN with no kind and no ON/USING often from FROM a, b
    if join.args.get("on") is None and join.args.get("using") is None:
        # sqlglot represents comma joins as Join with kind=None
        side = join.args.get("side")
        if side is None and kind is None:
            return "COMMA"
    return "INNER"


def analyze_joins(stmt: exp.Expression) -> list[JoinInfo]:
    out: list[JoinInfo] = []
    for join in stmt.find_all(exp.Join):
        on = join.args.get("on")
        using = join.args.get("using")
        has_pred = on is not None or using is not None
        kind = _join_kind(join)
        is_cross = kind == "CROSS" or (kind == "COMMA" and not has_pred)
        is_cartesian = is_cross or (not has_pred and kind in {"COMMA", "INNER", "UNKNOWN"})
        # Explicit INNER/LEFT with ON is fine
        if has_pred:
            is_cartesian = False
        if kind == "CROSS":
            is_cartesian = True
        right = ident(join.this) if join.this is not None else None
        out.append(
            JoinInfo(
                kind=kind,
                has_predicate=has_pred,
                is_cartesian=is_cartesian,
                right_table=right,
                sql=join.sql()[:200],
            )
        )
    return out


def is_tautology_predicate(node: exp.Expression | None) -> bool:
    """True for WHERE TRUE / 1 / 1=1 / '1'='1' style always-true filters."""
    if node is None:
        return False
    if isinstance(node, exp.Paren):
        return is_tautology_predicate(node.this)
    if isinstance(node, exp.Boolean):
        return bool(node.this) is True
    if isinstance(node, exp.Literal):
        if node.is_int:
            try:
                return int(node.this) != 0
            except (TypeError, ValueError):
                return False
        # Non-empty string literal alone is unusual; treat "true" case-insensitively
        return str(node.this).lower() in {"true", "t", "yes"}
    if isinstance(node, exp.EQ):
        left = literal_value(node.this)
        right = literal_value(node.expression)
        if left is None or right is None:
            return False
        return left == right and not isinstance(node.this, exp.Column) and not isinstance(
            node.expression, exp.Column
        )
    return False


def referenced_tables(stmt: exp.Expression) -> list[str]:
    names: list[str] = []
    for table in stmt.find_all(exp.Table):
        name = ident(table)
        if name and name not in names:
            names.append(name)
    return names


def referenced_columns(stmt: exp.Expression) -> list[str]:
    names: list[str] = []
    for col in stmt.find_all(exp.Column):
        name = ident(col)
        if name and name != "*" and name not in names:
            names.append(name)
    return names


def analyze_statement(
    stmt: exp.Expression | None,
    *,
    operation: str,
    has_where: bool,
    where: exp.Expression | None,
) -> AstFindings:
    findings = AstFindings()
    if stmt is None:
        return findings

    findings.tables = referenced_tables(stmt)
    findings.columns = referenced_columns(stmt)
    findings.joins = analyze_joins(stmt)
    findings.cartesian_joins = [j for j in findings.joins if j.is_cartesian]
    findings.is_ddl = operation == "ddl"
    findings.is_dml = operation in {"insert", "update", "delete"}

    tautology = is_tautology_predicate(where)
    findings.tautology_where = tautology
    findings.missing_where = operation in {"update", "delete"} and (
        not has_where or tautology
    )
    findings.full_table_write = findings.missing_where

    flags: list[str] = []
    if findings.is_ddl:
        flags.append("ddl")
    if findings.full_table_write:
        flags.append("full_table_write")
    if findings.tautology_where and operation in {"update", "delete"}:
        flags.append("tautology_where")
    if findings.cartesian_joins:
        flags.append("cartesian_join")
    if isinstance(stmt, (exp.Drop, exp.TruncateTable)) or type(stmt).__name__ in {
        "TruncateTable",
        "Alter",
        "AlterTable",
    }:
        flags.append("destructive_ddl")
    findings.dangerous_flags = flags
    return findings
