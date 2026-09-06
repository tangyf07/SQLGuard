"""Parse a single SQL statement into a structured form (sqlglot AST, no LLM)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Any

import sqlglot
from sqlglot import exp

from write_gate.ast_patterns import AstFindings, analyze_statement
from write_gate.decision import RULE_SCHEMA, RULE_UNSUPPORTED
from write_gate.idents import ident, literal_value

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

WRITE_TYPE_NAMES = (
    "Insert",
    "Update",
    "Delete",
    "Merge",
    "Create",
    "Drop",
    "Alter",
    "AlterTable",
    "Command",
    "Copy",
    "TruncateTable",
    "Replace",
)

DDL_TYPE_NAMES = (
    "Create",
    "Drop",
    "Alter",
    "AlterTable",
    "TruncateTable",
    "Command",
)


@dataclass
class ParsedSQL:
    sql: str
    statement: exp.Expression | None = None
    operation: str = "unknown"  # select | insert | update | delete | ddl | unknown
    table: str | None = None
    table_alias: str | None = None
    columns: list[str] = field(default_factory=list)
    insert_columns: list[str] = field(default_factory=list)
    write_columns: list[str] = field(default_factory=list)
    select_columns: list[str] = field(default_factory=list)
    star: bool = False
    where: exp.Expression | None = None
    has_where: bool = False
    assignments: dict[str, exp.Expression | None] = field(default_factory=dict)
    insert_rows: list[list[exp.Expression]] | None = None
    error: str | None = None
    error_rule: str = RULE_SCHEMA
    findings: AstFindings = field(default_factory=AstFindings)
    tables_referenced: list[str] = field(default_factory=list)
    dangerous_flags: list[str] = field(default_factory=list)



def expected_kind(col_type: str) -> str:
    t = col_type.upper()
    if t in {"INTEGER", "INT", "BIGINT", "SMALLINT", "TINYINT"}:
        return "INTEGER"
    if t in {"DOUBLE", "FLOAT", "REAL", "DECIMAL", "NUMERIC"}:
        return "DOUBLE"
    if t in {"DATE", "TIMESTAMP"}:
        return "DATE"
    return "VARCHAR"


def type_ok(expected: str, node: exp.Expression | None) -> bool:
    if node is None or isinstance(node, exp.Null):
        return True
    kind = expected_kind(expected)
    value = literal_value(node)
    if kind == "INTEGER":
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == "DOUBLE":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if kind == "DATE":
        text = str(value)
        if not _DATE_RE.match(text):
            return False
        try:
            date.fromisoformat(text)
            return True
        except ValueError:
            return False
    return True


def parse_date(value: Any) -> date | None:
    if value is None:
        return None
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    text = str(value)
    if not _DATE_RE.match(text):
        return None
    try:
        return date.fromisoformat(text)
    except ValueError:
        return None


def _write_types() -> tuple[type, ...]:
    return tuple(getattr(exp, n) for n in WRITE_TYPE_NAMES if hasattr(exp, n))


def _ddl_types() -> tuple[type, ...]:
    return tuple(getattr(exp, n) for n in DDL_TYPE_NAMES if hasattr(exp, n))


def _has_select_into(stmt: exp.Expression) -> bool:
    """PostgreSQL SELECT ... INTO is a write (creates a table), not read-only."""
    if isinstance(stmt, exp.Select) and stmt.args.get("into") is not None:
        return True
    into_cls = getattr(exp, "Into", None)
    if into_cls is None:
        return False
    return any(isinstance(n, into_cls) for n in stmt.find_all(into_cls))


def _nested_dml_nodes(stmt: exp.Expression) -> list[exp.Expression]:
    """DML nested under any root (SELECT or INSERT/UPDATE/DELETE).

    Catches data-modifying CTEs such as::

        WITH d AS (DELETE FROM orders RETURNING *)
        INSERT INTO orders(...) VALUES(...);

    The root statement itself is excluded; only nested DML nodes are returned.
    """
    write_types = _write_types()
    if not write_types:
        return []
    return [n for n in stmt.find_all(*write_types) if n is not stmt]


def is_read_only(stmt: exp.Expression) -> bool:
    write_types = _write_types()
    if write_types and isinstance(stmt, write_types):
        return False
    if _has_select_into(stmt):
        return False
    if _nested_dml_nodes(stmt):
        return False
    if isinstance(stmt, (exp.Select, exp.Union, exp.Except, exp.Intersect)):
        return True
    return isinstance(stmt, exp.Query) and not isinstance(stmt, write_types)


def _is_unsupported_dialect_feature(stmt: exp.Expression) -> str | None:
    """Return a short feature name if stmt is outside the support matrix."""
    # MERGE / COPY / REPLACE / Command are ambiguous or dialect-specific writes.
    for name, cls_name in (
        ("MERGE", "Merge"),
        ("COPY", "Copy"),
        ("REPLACE", "Replace"),
        ("COMMAND", "Command"),
    ):
        cls = getattr(exp, cls_name, None)
        if cls is not None and isinstance(stmt, cls):
            return name
    return None


def unsupported_read_reason(stmt: exp.Expression) -> tuple[str, str] | None:
    """Explicit reject reasons for structures that must never silent-ALLOW.

    Covers both read-shaped and write-root statements. Anything dangerous /
    ambiguous that is not on the SQL support matrix → unsupported_sql (not ALLOW).
    """
    feature = _is_unsupported_dialect_feature(stmt)
    if feature:
        return (
            RULE_UNSUPPORTED,
            (
                f"{feature} is outside the sql-write-gate support matrix; "
                "rejected (unsupported_sql)"
            ),
        )
    if _has_select_into(stmt):
        return (
            RULE_UNSUPPORTED,
            "SELECT INTO is not supported as read-only; rejected (unsupported_sql)",
        )
    nested = _nested_dml_nodes(stmt)
    if nested:
        kinds = sorted({type(n).__name__ for n in nested})
        return (
            RULE_UNSUPPORTED,
            (
                "Data-modifying CTE / nested DML "
                f"({', '.join(kinds)}) under the statement root is not supported; "
                "rejected (unsupported_sql)"
            ),
        )
    return None


# Back-compat alias used by older call sites / docs.
unsupported_sql_reason = unsupported_read_reason


def classify_operation(stmt: exp.Expression) -> str:
    if isinstance(stmt, exp.Insert):
        return "insert"
    if isinstance(stmt, exp.Update):
        return "update"
    if isinstance(stmt, exp.Delete):
        return "delete"
    ddl_types = _ddl_types()
    if ddl_types and isinstance(stmt, ddl_types):
        return "ddl"
    if isinstance(stmt, exp.Merge):
        return "ddl"
    if _has_select_into(stmt):
        return "ddl"
    nested = _nested_dml_nodes(stmt)
    if nested:
        # Prefer the nested DML kind for policy; schema/unsupported still reject.
        inner = nested[0]
        if isinstance(inner, exp.Insert):
            return "insert"
        if isinstance(inner, exp.Update):
            return "update"
        if isinstance(inner, exp.Delete):
            return "delete"
        return "ddl"
    if is_read_only(stmt):
        return "select"
    return "ddl"


def _table_from_select(stmt: exp.Expression) -> str | None:
    from_ = stmt.args.get("from_") or stmt.args.get("from")
    if from_ is None:
        return None
    this = from_.this if isinstance(from_, exp.From) else from_
    return ident(this)


def _table_from_truncate(stmt: exp.Expression) -> str | None:
    for item in stmt.expressions or []:
        name = ident(item)
        if name:
            return name
    return ident(stmt.this)


def extract_table(stmt: exp.Expression) -> str | None:
    if isinstance(stmt, exp.TruncateTable) or type(stmt).__name__ == "TruncateTable":
        return _table_from_truncate(stmt)
    if isinstance(stmt, (exp.Select, exp.Union, exp.Except, exp.Intersect)):
        return _table_from_select(stmt)
    if isinstance(stmt, exp.Query):
        return _table_from_select(stmt)
    return ident(stmt.this)


def extract_where(stmt: exp.Expression) -> exp.Expression | None:
    where = stmt.args.get("where")
    if where is None:
        return None
    if isinstance(where, exp.Where):
        return where.this
    return where


def where_sql(where: exp.Expression | None, dialect: str = "duckdb") -> str | None:
    if where is None:
        return None
    if isinstance(where, exp.Where):
        return where.this.sql(dialect=dialect) if where.this else None
    return where.sql(dialect=dialect)


def _column_names_in_expression(node: exp.Expression) -> list[str]:
    """Column identifiers referenced inside a projection / expression tree."""
    cols: list[str] = []
    for col in node.find_all(exp.Column):
        name = ident(col)
        if name and name != "*":
            cols.append(name)
    return cols


def _projection_columns(expressions: list[exp.Expression] | None) -> tuple[list[str], bool]:
    cols: list[str] = []
    star = False
    for item in expressions or []:
        if isinstance(item, exp.Star):
            star = True
            continue
        if isinstance(item, exp.Column) and getattr(item, "is_star", False):
            star = True
            continue
        # Prefer underlying column refs (covers concat(email, phone) AS contact).
        nested = _column_names_in_expression(item)
        if nested:
            cols.extend(nested)
            continue
        if isinstance(item, exp.Alias):
            name = ident(item.this) or ident(item)
        else:
            name = ident(item)
        if name and name != "*":
            cols.append(name)
        elif name == "*":
            star = True
    return cols, star


def _select_columns(stmt: exp.Expression) -> tuple[list[str], bool]:
    """Collect projected / referenced columns for PII checks (CTE, UNION, exprs)."""
    cols: list[str] = []
    star = False

    # UNION / EXCEPT / INTERSECT: walk both sides.
    if isinstance(stmt, (exp.Union, exp.Except, exp.Intersect)):
        for side in (stmt.this, stmt.expression):
            if side is None:
                continue
            c, s = _select_columns(side)
            cols.extend(c)
            star = star or s
        return list(dict.fromkeys(cols)), star

    # WITH ... AS (...): include CTE bodies so SELECT * FROM cte still sees PII.
    for cte in stmt.find_all(exp.CTE):
        body = cte.this
        if body is None:
            continue
        c, s = _select_columns(body)
        cols.extend(c)
        star = star or s

    if isinstance(stmt, exp.Select):
        c, s = _projection_columns(stmt.expressions)
        cols.extend(c)
        star = star or s
    elif hasattr(stmt, "expressions"):
        c, s = _projection_columns(stmt.expressions)
        cols.extend(c)
        star = star or s

    return list(dict.fromkeys(cols)), star


def table_alias(stmt: exp.Expression) -> str | None:
    """Alias on the target table of UPDATE/DELETE (for COUNT estimates)."""
    target = stmt.this if isinstance(stmt, (exp.Update, exp.Delete)) else None
    if isinstance(target, exp.Table):
        alias = target.args.get("alias")
        if isinstance(alias, exp.TableAlias):
            return ident(alias.this) or ident(alias)
        if alias is not None:
            return ident(alias)
        return target.alias if getattr(target, "alias", None) else None
    return None


def conflict_update_columns(stmt: exp.Insert) -> list[str]:
    """Columns written by ON CONFLICT ... DO UPDATE SET (UPSERT)."""
    conflict = stmt.args.get("conflict")
    if conflict is None:
        return []
    cols: list[str] = []
    for item in conflict.expressions or []:
        if isinstance(item, exp.EQ):
            name = ident(item.this)
            if name:
                cols.append(name)
        else:
            name = ident(item)
            if name:
                cols.append(name)
    return cols


def insert_columns(stmt: exp.Insert, fallback: list[str] | None = None) -> list[str]:
    target = stmt.this
    if isinstance(target, exp.Schema) and target.expressions:
        return [ident(c) or "" for c in target.expressions]
    return list(fallback or [])


def insert_rows(stmt: exp.Insert) -> list[list[exp.Expression]] | None:
    values = stmt.expression
    if isinstance(values, exp.Values):
        rows: list[list[exp.Expression]] = []
        for tup in values.expressions:
            if isinstance(tup, exp.Tuple):
                rows.append(list(tup.expressions))
            else:
                rows.append([tup])
        return rows
    return None


def update_assignments(stmt: exp.Update) -> dict[str, exp.Expression | None]:
    out: dict[str, exp.Expression | None] = {}
    for item in stmt.expressions:
        if isinstance(item, exp.EQ):
            name = ident(item.this)
            if name:
                out[name] = item.expression
    return out


def partition_dates_from_where(
    where: exp.Expression | None, part: str | None
) -> list[date | None]:
    """Collect partition date literals from WHERE (= / IN / inequalities / BETWEEN).

    For past-open ranges (``dt < X``, ``dt <= X``) a sentinel ``date.min`` is
    included so callers without a cutoff still fail closed. Prefer
    ``expired_partition_touch`` when a cutoff is available.
    """
    if where is None or not part:
        return []
    dates: list[date | None] = []

    def visit(node: exp.Expression) -> None:
        hit = _constraint_dates(node, part)
        if hit is not None:
            dates.extend(hit)
            return
        for child in node.iter_expressions():
            visit(child)

    visit(where)
    return dates


def _constraint_dates(node: exp.Expression, part: str) -> list[date | None] | None:
    """If node is a partition constraint, return dates it implies; else None."""
    if isinstance(node, exp.In) and ident(node.this) == part:
        return [parse_date(literal_value(item)) for item in node.expressions]
    if isinstance(node, exp.Between) and ident(node.this) == part:
        low = parse_date(literal_value(node.args.get("low")))
        high = parse_date(literal_value(node.args.get("high")))
        out: list[date | None] = [low, high]
        if low is None:
            out.append(date.min)
        return out
    if isinstance(node, exp.EQ):
        left, right = node.this, node.expression
        if ident(left) == part:
            return [parse_date(literal_value(right))]
        if ident(right) == part:
            return [parse_date(literal_value(left))]
        return None
    if isinstance(node, (exp.LT, exp.LTE, exp.GT, exp.GTE)):
        return _inequality_dates(node, part)
    return None


def _inequality_dates(node: exp.Expression, part: str) -> list[date | None] | None:
    left, right = node.this, node.expression
    if ident(left) == part:
        lit = parse_date(literal_value(right))
        op = type(node)
    elif ident(right) == part:
        lit = parse_date(literal_value(left))
        op = {exp.LT: exp.GT, exp.LTE: exp.GTE, exp.GT: exp.LT, exp.GTE: exp.LTE}[type(node)]
    else:
        return None
    # Past-open always contributes sentinel; bound kept for messaging.
    out: list[date | None] = []
    if lit is not None:
        out.append(lit)
    if op in (exp.LT, exp.LTE):
        out.append(date.min)
    elif lit is None:
        out.append(date.min)
    return out or [None]


def expired_partition_touch(
    where: exp.Expression | None,
    part: str | None,
    cutoff: date,
) -> date | None:
    """Return one expired partition date if WHERE can match rows before cutoff.

    Boolean structure is respected:
    - AND → intersect match sets (so ``dt >= cutoff AND dt < upper`` may be fresh)
    - OR  → union (a branch that ignores the partition opens all dates)
    - NOT → complement (``NOT (dt >= cutoff)`` touches expired)

    If the partition column is never mentioned, return None so blast-radius owns
    scope. Unparseable partition predicates fail closed.
    """
    if where is None or not part:
        return None
    if not _mentions_partition(where, part):
        return None
    match = _partition_match(where, part)
    if match is _MATCH_UNKNOWN:
        return date.min
    if match is _MATCH_EMPTY:
        return None
    if match is _MATCH_FULL:
        # Partition mentioned but match covers all dates (e.g. OR with
        # unconstrained branch) → fail closed.
        return date.min
    hits: list[date] = []
    for lo, hi in match:
        if _range_intersects_expired(lo, hi, cutoff):
            if lo is not None and lo < cutoff:
                hits.append(lo)
            else:
                hits.append(date.min)
    return min(hits) if hits else None


def _mentions_partition(node: exp.Expression, part: str) -> bool:
    if ident(node) == part:
        return True
    if isinstance(node, exp.Column) and ident(node) == part:
        return True
    return any(_mentions_partition(c, part) for c in node.iter_expressions())


# Match-set sentinels for partition analysis (not user-visible).
_MATCH_FULL = object()
_MATCH_EMPTY = object()
_MATCH_UNKNOWN = object()


def _range_intersects_expired(
    lo: date | None, hi: date | None, cutoff: date
) -> bool:
    """True if [lo, hi) intersects (-inf, cutoff) i.e. can match d < cutoff."""
    if lo is not None and hi is not None and lo >= hi:
        return False
    end = cutoff if hi is None else (hi if hi < cutoff else cutoff)
    if lo is None:
        return True
    return lo < end


def _intersect_ranges(
    left: list[tuple[date | None, date | None]],
    right: list[tuple[date | None, date | None]],
) -> list[tuple[date | None, date | None]]:
    out: list[tuple[date | None, date | None]] = []
    for a_lo, a_hi in left:
        for b_lo, b_hi in right:
            # max lo (None = -inf)
            if a_lo is None:
                lo = b_lo
            elif b_lo is None:
                lo = a_lo
            else:
                lo = max(a_lo, b_lo)
            # min hi (None = +inf)
            if a_hi is None:
                hi = b_hi
            elif b_hi is None:
                hi = a_hi
            else:
                hi = min(a_hi, b_hi)
            if lo is not None and hi is not None and lo >= hi:
                continue
            out.append((lo, hi))
    return out


def _complement_ranges(
    ranges: list[tuple[date | None, date | None]],
) -> list[tuple[date | None, date | None]]:
    """Complement of a union of [lo, hi) relative to (-inf, +inf)."""
    if not ranges:
        return [(None, None)]
    # Normalize / merge overlapping then punch holes.
    norm = _merge_ranges(ranges)
    out: list[tuple[date | None, date | None]] = []
    cursor: date | None = None  # start of current gap (-inf)
    for lo, hi in norm:
        # gap [cursor, lo)
        if lo is None:
            # covers from -inf; no left gap
            pass
        else:
            if cursor is None or cursor < lo:
                out.append((cursor, lo))
        # advance cursor to hi
        if hi is None:
            return out  # covered through +inf
        if cursor is None or (hi is not None and (cursor is None or cursor < hi)):
            cursor = hi
    out.append((cursor, None))
    return out


def _merge_ranges(
    ranges: list[tuple[date | None, date | None]],
) -> list[tuple[date | None, date | None]]:
    def sort_key(r: tuple[date | None, date | None]):
        lo, _hi = r
        return (lo is not None, lo or date.min)

    ordered = sorted(ranges, key=sort_key)
    merged: list[tuple[date | None, date | None]] = []
    for lo, hi in ordered:
        if not merged:
            merged.append((lo, hi))
            continue
        m_lo, m_hi = merged[-1]
        if m_hi is not None and lo is not None and lo > m_hi:
            merged.append((lo, hi))
            continue
        new_lo = None if m_lo is None or lo is None else min(m_lo, lo)
        new_hi = None if m_hi is None or hi is None else max(m_hi, hi)
        merged[-1] = (new_lo, new_hi)
    return merged


def _and_match(a, b):
    if a is _MATCH_UNKNOWN or b is _MATCH_UNKNOWN:
        return _MATCH_UNKNOWN
    if a is _MATCH_EMPTY or b is _MATCH_EMPTY:
        return _MATCH_EMPTY
    if a is _MATCH_FULL:
        return b
    if b is _MATCH_FULL:
        return a
    inter = _intersect_ranges(a, b)
    return inter if inter else _MATCH_EMPTY


def _or_match(a, b):
    if a is _MATCH_UNKNOWN or b is _MATCH_UNKNOWN:
        return _MATCH_UNKNOWN
    if a is _MATCH_FULL or b is _MATCH_FULL:
        return _MATCH_FULL
    if a is _MATCH_EMPTY:
        return b
    if b is _MATCH_EMPTY:
        return a
    return _merge_ranges([*a, *b])


def _not_match(inner):
    if inner is _MATCH_UNKNOWN:
        return _MATCH_UNKNOWN
    if inner is _MATCH_FULL:
        return _MATCH_EMPTY
    if inner is _MATCH_EMPTY:
        return _MATCH_FULL
    comp = _complement_ranges(inner)
    return comp if comp else _MATCH_EMPTY


def _day_after(d: date) -> date | None:
    try:
        return d + timedelta(days=1)
    except OverflowError:
        return None


def _atomic_partition_match(
    node: exp.Expression, part: str
):
    """If node constrains ``part``, return match set; else None (not a constraint)."""
    if isinstance(node, exp.In) and ident(node.this) == part:
        ranges: list[tuple[date | None, date | None]] = []
        for item in node.expressions:
            d = parse_date(literal_value(item))
            if d is None:
                return _MATCH_UNKNOWN
            nxt = _day_after(d)
            ranges.append((d, nxt))
        return _merge_ranges(ranges) if ranges else _MATCH_EMPTY
    if isinstance(node, exp.Between) and ident(node.this) == part:
        low = parse_date(literal_value(node.args.get("low")))
        high = parse_date(literal_value(node.args.get("high")))
        if low is None and high is None:
            return _MATCH_UNKNOWN
        hi = _day_after(high) if high is not None else None
        return [(low, hi)]
    if isinstance(node, exp.EQ):
        left, right = node.this, node.expression
        if ident(left) == part:
            d = parse_date(literal_value(right))
        elif ident(right) == part:
            d = parse_date(literal_value(left))
        else:
            return None
        if d is None:
            return _MATCH_UNKNOWN
        return [(d, _day_after(d))]
    if isinstance(node, (exp.LT, exp.LTE, exp.GT, exp.GTE, exp.NEQ)):
        left, right = node.this, node.expression
        if ident(left) == part:
            lit = parse_date(literal_value(right))
            op = type(node)
        elif ident(right) == part:
            lit = parse_date(literal_value(left))
            op = {
                exp.LT: exp.GT,
                exp.LTE: exp.GTE,
                exp.GT: exp.LT,
                exp.GTE: exp.LTE,
                exp.NEQ: exp.NEQ,
            }[type(node)]
        else:
            return None
        if lit is None and op is not exp.NEQ:
            return _MATCH_UNKNOWN
        if op is exp.LT:
            return [(None, lit)]
        if op is exp.LTE:
            return [(None, _day_after(lit))]
        if op is exp.GT:
            return [(_day_after(lit), None)]
        if op is exp.GTE:
            return [(lit, None)]
        if op is exp.NEQ:
            if lit is None:
                return _MATCH_UNKNOWN
            # all dates except lit
            return _complement_ranges([(lit, _day_after(lit))])
    return None


def _partition_match(node: exp.Expression, part: str):
    """Match-set of dates satisfying ``node`` for partition column ``part``."""
    if isinstance(node, exp.Paren):
        return _partition_match(node.this, part) if node.this is not None else _MATCH_FULL
    if isinstance(node, exp.Not):
        inner = node.this
        if inner is None:
            return _MATCH_UNKNOWN
        return _not_match(_partition_match(inner, part))
    if isinstance(node, exp.And):
        return _and_match(
            _partition_match(node.this, part),
            _partition_match(node.expression, part),
        )
    if isinstance(node, exp.Or):
        return _or_match(
            _partition_match(node.this, part),
            _partition_match(node.expression, part),
        )

    atomic = _atomic_partition_match(node, part)
    if atomic is not None:
        return atomic

    # Non-partition predicate: unconstrained on the partition column.
    # If the node still nests partition constraints (e.g. function wrappers),
    # walk children with AND semantics only when every child is present; otherwise FULL.
    children = list(node.iter_expressions())
    if not children:
        return _MATCH_FULL
    # If any descendant is a partition constraint buried under an unknown node,
    # fail closed when we cannot interpret the wrapper.
    if _mentions_partition(node, part):
        return _MATCH_UNKNOWN
    return _MATCH_FULL



def partition_dates_from_assignments(
    assignments: dict[str, exp.Expression | None] | None, part: str | None
) -> list[date | None]:
    """Partition dates written by UPDATE SET (e.g. SET dt = '2026-08-01')."""
    if not part or not assignments:
        return []
    if part not in assignments:
        return []
    return [parse_date(literal_value(assignments[part]))]


def partition_dates_from_insert(
    cols: list[str], rows: list[list[exp.Expression]], part: str | None
) -> list[date | None]:
    if not part:
        return []
    dates: list[date | None] = []
    for row in rows:
        row_map = dict(zip(cols, row))
        if part not in row_map:
            dates.append(None)
        else:
            dates.append(parse_date(literal_value(row_map[part])))
    return dates


def parse(sql: str, dialect: str = "duckdb") -> ParsedSQL:
    original = sql
    stripped = sql.strip().rstrip(";").strip()
    parsed = ParsedSQL(sql=original)
    if not stripped:
        parsed.error = "SQL 为空，无法执行"
        return parsed

    read_dialect = dialect or "duckdb"
    try:
        statements = sqlglot.parse(stripped, read=read_dialect)
    except sqlglot.errors.ParseError as exc:
        if read_dialect != "duckdb":
            try:
                statements = sqlglot.parse(stripped, read="duckdb")
            except sqlglot.errors.ParseError as exc2:
                parsed.error = f"SQL 无法解析: {exc2}"
                return parsed
        else:
            parsed.error = f"SQL 无法解析: {exc}"
            return parsed

    statements = [s for s in statements if s is not None]
    if not statements:
        parsed.error = "SQL 无法解析为空语句"
        return parsed
    if len(statements) != 1:
        parsed.error = (
            f"一次只允许一条语句，收到 {len(statements)} 条; "
            "multi-statement SQL rejected (unsupported_sql)"
        )
        parsed.error_rule = RULE_UNSUPPORTED
        return parsed

    stmt = statements[0]
    parsed.statement = stmt

    unsupported = unsupported_read_reason(stmt)
    if unsupported:
        rule, reason = unsupported
        parsed.error = reason
        parsed.error_rule = rule
        parsed.operation = classify_operation(stmt)
        parsed.table = extract_table(stmt)
        return parsed

    parsed.operation = classify_operation(stmt)
    parsed.table = extract_table(stmt)
    parsed.table_alias = table_alias(stmt)
    parsed.where = extract_where(stmt)
    parsed.has_where = parsed.where is not None

    if isinstance(stmt, exp.Insert):
        cols = insert_columns(stmt)
        conflict_cols = conflict_update_columns(stmt)
        # UPSERT: insert_columns = INSERT target list (VALUES arity);
        # write_columns = insert + ON CONFLICT DO UPDATE SET (PII/schema writes).
        write_cols = list(dict.fromkeys([*cols, *conflict_cols]))
        parsed.insert_columns = list(cols)
        parsed.write_columns = write_cols
        parsed.columns = list(cols)
        parsed.insert_rows = insert_rows(stmt)
        parsed.assignments = {}
        if conflict_cols:
            # Keep SET expressions for type checks when present.
            conflict = stmt.args.get("conflict")
            for item in (conflict.expressions or [] if conflict is not None else []):
                if isinstance(item, exp.EQ):
                    name = ident(item.this)
                    if name:
                        parsed.assignments[name] = item.expression
    elif isinstance(stmt, exp.Update):
        assignments = update_assignments(stmt)
        parsed.assignments = assignments
        parsed.write_columns = list(assignments.keys())
        parsed.columns = list(assignments.keys())
    elif is_read_only(stmt):
        cols, star = _select_columns(stmt)
        parsed.select_columns = cols
        parsed.columns = cols
        parsed.star = star

    # Stronger AST analysis (joins, tautology WHERE, referenced objects).
    findings = analyze_statement(
        stmt,
        operation=parsed.operation,
        has_where=parsed.has_where,
        where=parsed.where,
    )
    parsed.findings = findings
    parsed.tables_referenced = list(findings.tables)
    parsed.dangerous_flags = list(findings.dangerous_flags)
    # Treat tautology WHERE as missing for downstream destructive guards.
    if findings.tautology_where and parsed.operation in {"update", "delete"}:
        parsed.has_where = False
    return parsed
