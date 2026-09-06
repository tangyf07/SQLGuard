"""Optional EXPLAIN / cost estimation via adapters. Offline-safe degrade."""

from __future__ import annotations

from typing import Any

from write_gate.adapters.base import BACKEND_DUCKDB, BACKEND_MYSQL, BACKEND_POSTGRES, BACKEND_SQLITE


def estimate_cost(
    conn: Any | None,
    sql: str,
    *,
    backend: str = BACKEND_DUCKDB,
) -> tuple[float | None, str | None, str | None]:
    """Return (cost, plan_text, skip_reason).

    When ``conn`` is missing or EXPLAIN fails, degrade gracefully with a skip
    reason — never raise into the gate path.
    """
    if conn is None:
        return None, None, "no connection"
    try:
        if backend == BACKEND_POSTGRES:
            return _pg_cost(conn, sql)
        if backend == BACKEND_MYSQL:
            return _mysql_cost(conn, sql)
        if backend == BACKEND_SQLITE:
            return _sqlite_cost(conn, sql)
        return _duckdb_cost(conn, sql)
    except Exception as exc:  # noqa: BLE001 — degrade only
        return None, None, f"explain failed: {exc}"


def _duckdb_cost(conn: Any, sql: str) -> tuple[float | None, str | None, str | None]:
    # DuckDB: EXPLAIN; no numeric cost — use plan length as soft signal.
    cur = conn.execute(f"EXPLAIN {sql}")
    rows = cur.fetchall()
    plan = "\n".join(str(r[0]) if len(r) == 1 else str(r) for r in rows)
    # Heuristic: longer plans / SEQ_SCAN hints → higher soft cost
    cost = float(len(plan))
    if "SEQ_SCAN" in plan.upper() or "FULL" in plan.upper():
        cost *= 1.5
    return cost, plan[:2000], None


def _pg_cost(conn: Any, sql: str) -> tuple[float | None, str | None, str | None]:
    cur = conn.execute(f"EXPLAIN (FORMAT JSON) {sql}")
    rows = cur.fetchall()
    plan = str(rows[0][0]) if rows else ""
    cost = _extract_pg_total_cost(plan)
    return cost, plan[:2000], None


def _extract_pg_total_cost(plan: str) -> float | None:
    import json
    import re

    try:
        data = json.loads(plan) if plan.lstrip().startswith("[") else None
    except json.JSONDecodeError:
        data = None
    if isinstance(data, list) and data:
        node = data[0].get("Plan") if isinstance(data[0], dict) else None
        if isinstance(node, dict) and "Total Cost" in node:
            return float(node["Total Cost"])
    m = re.search(r"cost=\d+\.\d+\.\.(\d+\.\d+)", plan)
    if m:
        return float(m.group(1))
    return float(len(plan)) if plan else None


def _mysql_cost(conn: Any, sql: str) -> tuple[float | None, str | None, str | None]:
    cur = conn.execute(f"EXPLAIN {sql}")
    rows = cur.fetchall()
    plan = "\n".join(str(r) for r in rows)
    # rows column is typically index 8 or named — soft sum
    cost = 0.0
    for r in rows:
        try:
            # PyMySQL dict or tuple
            if isinstance(r, dict):
                cost += float(r.get("rows") or 0)
            elif len(r) > 8 and r[8] is not None:
                cost += float(r[8])
        except (TypeError, ValueError):
            continue
    return (cost if cost else float(len(plan))), plan[:2000], None


def _sqlite_cost(conn: Any, sql: str) -> tuple[float | None, str | None, str | None]:
    cur = conn.execute(f"EXPLAIN QUERY PLAN {sql}")
    rows = cur.fetchall()
    plan = "\n".join(str(r) for r in rows)
    cost = float(len(rows) * 10 + len(plan))
    if "SCAN" in plan.upper() and "USING" not in plan.upper():
        cost *= 2
    return cost, plan[:2000], None
