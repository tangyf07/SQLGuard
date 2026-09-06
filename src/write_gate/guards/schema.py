"""Schema guard: parse errors, unknown table/column, type mismatch, unsupported SQL."""

from __future__ import annotations

from sqlglot import exp

from write_gate.catalog import TableSpec
from write_gate.decision import RULE_HALLUCINATION, RULE_SCHEMA, GuardResult
from write_gate.parser import literal_value, type_ok

NAME = "schema"


def check_schema(ctx) -> GuardResult:
    parsed = ctx.parsed
    if parsed.error:
        return GuardResult.block(
            NAME,
            parsed.error_rule or RULE_SCHEMA,
            parsed.error,
            risk="medium",
        )

    stmt = parsed.statement
    if stmt is None:
        return GuardResult.block(NAME, RULE_SCHEMA, "SQL 无法解析", risk="medium")

    operation = parsed.operation
    if operation == "select":
        return _check_select_hallucination(parsed, ctx)

    if operation == "ddl":
        # Destructive/environment guards own DROP/ALTER/TRUNCATE/CREATE.
        return GuardResult.pass_(NAME)

    if operation not in {"insert", "update", "delete"}:
        return GuardResult.block(
            NAME,
            RULE_SCHEMA,
            f"不支持的写语句类型 {type(stmt).__name__}，仅允许 INSERT/UPDATE/DELETE",
            risk="medium",
        )

    table_name = parsed.table
    if not table_name:
        return GuardResult.block(NAME, RULE_SCHEMA, "无法从 SQL 中解析目标表", risk="medium")

    spec = ctx.catalog.table(table_name)
    if spec is None:
        return GuardResult.block(
            NAME,
            RULE_HALLUCINATION,
            f"Schema hallucination: unknown table {table_name} not in catalog",
            risk="medium",
            evidence={"table": table_name, "known_tables": sorted(ctx.catalog.tables)},
        )

    if isinstance(stmt, exp.Insert):
        return _check_insert(parsed, spec)
    if isinstance(stmt, exp.Update):
        return _check_update(parsed, spec)
    return GuardResult.pass_(NAME)


def _check_insert(parsed, spec: TableSpec) -> GuardResult:
    # insert_columns: INSERT target list (VALUES arity only).
    # write_columns: insert + ON CONFLICT DO UPDATE SET (allowed/unknown/PII).
    insert_cols = list(getattr(parsed, "insert_columns", None) or [])
    if not insert_cols:
        insert_cols = list(parsed.columns) if parsed.columns else []
    write_cols = list(parsed.write_columns) if parsed.write_columns else list(insert_cols)
    if not insert_cols:
        insert_cols = list(spec.columns.keys())
        parsed.insert_columns = list(insert_cols)
        parsed.columns = list(insert_cols)
        extras = [c for c in write_cols if c not in insert_cols]
        write_cols = list(dict.fromkeys([*insert_cols, *extras]))
        parsed.write_columns = write_cols
    else:
        parsed.insert_columns = list(insert_cols)
        if not write_cols:
            write_cols = list(insert_cols)
            parsed.write_columns = write_cols
    if any(c == "" for c in insert_cols):
        return GuardResult.block(NAME, RULE_SCHEMA, "INSERT 列名无法解析", risk="medium")

    rows = parsed.insert_rows
    if rows is None:
        return GuardResult.block(
            NAME,
            RULE_SCHEMA,
            "仅支持 INSERT ... VALUES (...); INSERT ... SELECT 未开放",
            risk="medium",
        )

    for row in rows:
        if len(row) != len(insert_cols):
            return GuardResult.block(
                NAME,
                RULE_SCHEMA,
                f"INSERT 列数 {len(insert_cols)} 与值个数 {len(row)} 不一致",
                risk="medium",
            )
        assignments = dict(zip(insert_cols, row))
        # Merge ON CONFLICT SET expressions for type checks on upsert cols.
        merged = {**assignments, **(parsed.assignments or {})}
        failed = _columns_and_types(spec, write_cols, merged)
        if failed:
            return failed
    return GuardResult.pass_(NAME)


def _check_update(parsed, spec: TableSpec) -> GuardResult:
    assignments = parsed.assignments
    cols = list(assignments.keys())
    if not cols:
        return GuardResult.block(NAME, RULE_SCHEMA, "UPDATE 未解析到 SET 列", risk="medium")
    failed = _columns_and_types(spec, cols, assignments)
    if failed:
        return failed
    return GuardResult.pass_(NAME)


def _columns_and_types(
    spec: TableSpec,
    write_cols: list[str],
    assignments: dict,
) -> GuardResult | None:
    unknown = [c for c in write_cols if c not in spec.columns]
    if unknown:
        return GuardResult.block(
            NAME,
            RULE_HALLUCINATION,
            (
                f"Schema hallucination: unknown column(s) {unknown} on table "
                f"{spec.name}; known columns {sorted(spec.columns)}"
            ),
            risk="medium",
            evidence={"unknown_columns": unknown, "table": spec.name},
        )

    for col in write_cols:
        node = assignments.get(col)
        expected = spec.columns[col]
        if node is not None and not type_ok(expected, node):
            got = literal_value(node)
            return GuardResult.block(
                NAME,
                RULE_SCHEMA,
                f"列 {col} 类型不匹配: 期望 {expected}，实际值 {got!r}",
                risk="medium",
                evidence={"column": col, "expected": expected, "value": got},
            )

    skip = spec.pii_columns | spec.restricted_columns
    not_allowed = [c for c in write_cols if c not in spec.allowed_write_columns and c not in skip]
    if not_allowed:
        return GuardResult.block(
            NAME,
            RULE_SCHEMA,
            f"列 {not_allowed} 不在允许写入列表 {sorted(spec.allowed_write_columns)}",
            risk="medium",
            evidence={"not_allowed": not_allowed},
        )
    return None


def _cte_aliases(stmt) -> set[str]:
    """Names introduced by WITH … AS (…); not catalog tables."""
    names: set[str] = set()
    if stmt is None:
        return names
    from write_gate.idents import ident

    for cte in stmt.find_all(exp.CTE):
        alias = getattr(cte, "alias_or_name", None)
        if alias:
            names.add(str(alias).lower())
            continue
        alias_node = cte.args.get("alias")
        if alias_node is not None:
            name = ident(alias_node) or ident(getattr(alias_node, "this", None))
            if name:
                names.add(name)
    return names


def _check_select_hallucination(parsed, ctx) -> GuardResult:
    """Block SELECT on unknown tables/columns (schema hallucination).

    CTE aliases are ignored. Honors ``allow_unknown_tables`` /
    ``allow_unknown_columns`` policy knobs. ``SELECT *`` only validates tables.
    """
    policy = ctx.policy
    allow_unknown_tables = bool(getattr(policy, "allow_unknown_tables", False))
    allow_unknown_columns = bool(getattr(policy, "allow_unknown_columns", False))

    catalog = ctx.catalog
    tables = list(getattr(parsed, "tables_referenced", None) or [])
    if parsed.table and parsed.table not in tables:
        tables.insert(0, parsed.table)

    cte_names = _cte_aliases(parsed.statement)
    physical = [t for t in tables if t not in cte_names]

    if not allow_unknown_tables:
        unknown_tables = [t for t in physical if catalog.table(t) is None]
        if unknown_tables:
            return GuardResult.block(
                NAME,
                RULE_HALLUCINATION,
                (
                    f"Schema hallucination: unknown table(s) {unknown_tables} "
                    f"not in catalog allowlist {sorted(catalog.tables)}"
                ),
                risk="medium",
                evidence={
                    "unknown_tables": unknown_tables,
                    "known_tables": sorted(catalog.tables),
                    "cte_aliases": sorted(cte_names),
                },
            )

    if parsed.star or allow_unknown_columns:
        return GuardResult.pass_(NAME)

    findings = getattr(parsed, "findings", None)
    cols = list(getattr(findings, "columns", None) or parsed.select_columns or [])
    if not cols or not physical:
        return GuardResult.pass_(NAME)

    known: set[str] = set()
    for tname in physical:
        spec = catalog.table(tname)
        if spec is not None:
            known |= set(spec.columns.keys())
    if not known:
        return GuardResult.pass_(NAME)

    unknown_cols = [c for c in cols if c not in known]
    if unknown_cols:
        return GuardResult.block(
            NAME,
            RULE_HALLUCINATION,
            (
                f"Schema hallucination: unknown column(s) {unknown_cols} "
                f"for tables {physical}; known columns {sorted(known)}"
            ),
            risk="medium",
            evidence={"unknown_columns": unknown_cols, "tables": physical},
        )
    return GuardResult.pass_(NAME)
