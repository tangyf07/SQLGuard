"""MCP tool functions: execute ALLOW SQL via WriteGate.

query_sql / write_sql call WriteGate.execute (not raw DuckDB). BLOCK and
REQUIRE_APPROVAL already return None and do not write. Honor database= /
DATABASE_URL the same way as the CLI.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from write_gate.decision import ACTION_ALLOW
from write_gate.wrapper import WriteGate

QUERY_ROW_CAP = 50  # legacy default; runtime result_row_limit preferred (v0.23)


def _as_path(value: str | Path | None) -> Path | None:
    if value is None:
        return None
    return Path(value)


def _gate(
    *,
    database: str | None = None,
    db_path: str | Path | None = None,
    catalog_path: str | Path | None = None,
    policy_path: str | Path | None = None,
    approvals_path: str | Path | None = None,
    agent: str = "mcp",
) -> WriteGate:
    return WriteGate(
        database=database,
        db_path=_as_path(db_path),
        catalog_path=_as_path(catalog_path),
        policy_path=_as_path(policy_path),
        approvals_path=_as_path(approvals_path),
        agent=agent or "mcp",
    )


def _json_cell(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    iso = getattr(value, "isoformat", None)
    if callable(iso):
        return iso()
    return str(value)


def _fetch_rows(result: Any, *, cap: int) -> list[list[Any]]:
    if result is None:
        return []
    fetched = None
    fetchmany = getattr(result, "fetchmany", None)
    if callable(fetchmany):
        try:
            fetched = fetchmany(cap)
        except Exception:
            fetched = None
    if fetched is None:
        fetchall = getattr(result, "fetchall", None)
        if not callable(fetchall):
            return []
        try:
            fetched = fetchall()[:cap]
        except Exception:
            return []
    rows: list[list[Any]] = []
    for row in fetched:
        rows.append([_json_cell(c) for c in row])
    return rows


def _rowcount(result: Any) -> int | None:
    if result is None:
        return None
    rc = getattr(result, "rowcount", None)
    if isinstance(rc, int) and rc >= 0:
        return rc
    return None


def decision_payload(
    decision: Any,
    *,
    executed: bool = False,
    rowcount: int | None = None,
    rows: list[list[Any]] | None = None,
) -> dict[str, Any]:
    """JSON-serializable gate result for MCP tools / python -c demos."""
    payload: dict[str, Any] = {
        "action": decision.action,
        "rule_id": decision.rule_id,
        "reason": decision.reason,
        "operation": decision.operation,
        "table": decision.table,
        "risk": decision.risk,
        "risk_score": getattr(decision, "risk_score", 0),
        "risk_factors": list(getattr(decision, "risk_factors", None) or []),
        "executed": bool(executed),
        "product": "SQLGuard",
    }
    if getattr(decision, "approval_id", None):
        payload["approval_id"] = decision.approval_id
    if rowcount is not None:
        payload["rowcount"] = rowcount
    if rows is not None:
        payload["rows"] = rows
    return payload


def _execute(
    sql: str,
    *,
    include_rows: bool,
    database: str | None = None,
    db_path: str | Path | None = None,
    catalog_path: str | Path | None = None,
    policy_path: str | Path | None = None,
    approvals_path: str | Path | None = None,
    agent: str = "mcp",
) -> dict[str, Any]:
    with _gate(
        database=database,
        db_path=db_path,
        catalog_path=catalog_path,
        policy_path=policy_path,
        approvals_path=approvals_path,
        agent=agent,
    ) as gate:
        decision, result = gate.execute(sql)
        executed = decision.action == ACTION_ALLOW and result is not None
        rows = None
        rowcount = None
        truncated = False
        if executed:
            rowcount = _rowcount(result)
            if include_rows:
                from write_gate.results import materialize_result
                from write_gate.runtime import load_runtime_settings

                cfg = load_runtime_settings()
                lim = cfg.result_row_limit if cfg.result_row_limit > 0 else QUERY_ROW_CAP
                mat = materialize_result(result, settings=cfg, row_limit=lim)
                if mat is not None:
                    rows = list(mat.get("rows") or [])
                    truncated = bool(mat.get("truncated"))
                    if rowcount is None:
                        rowcount = mat.get("rowcount", len(rows))
    payload = decision_payload(decision, executed=executed, rowcount=rowcount, rows=rows)
    if include_rows and executed:
        payload["truncated"] = truncated
    return payload


def query_sql(
    sql: str,
    *,
    database: str | None = None,
    db_path: str | Path | None = None,
    catalog_path: str | Path | None = None,
    policy_path: str | Path | None = None,
    approvals_path: str | Path | None = None,
    agent: str = "mcp",
) -> dict[str, Any]:
    """Gate then (on ALLOW) execute SQL via WriteGate.execute.

    SELECT results include a capped ``rows`` list. BLOCK / REQUIRE_APPROVAL
    do not run user SQL. REQUIRE_APPROVAL is queued (approval_id).
    """
    return _execute(
        sql,
        include_rows=True,
        database=database,
        db_path=db_path,
        catalog_path=catalog_path,
        policy_path=policy_path,
        approvals_path=approvals_path,
        agent=agent,
    )


def write_sql(
    sql: str,
    *,
    database: str | None = None,
    db_path: str | Path | None = None,
    catalog_path: str | Path | None = None,
    policy_path: str | Path | None = None,
    approvals_path: str | Path | None = None,
    agent: str = "mcp",
) -> dict[str, Any]:
    """Gate then (on ALLOW) execute INSERT/UPDATE/DELETE/DDL via WriteGate.execute.

    BLOCK / REQUIRE_APPROVAL return executed=false and do not write.
    REQUIRE_APPROVAL is queued (approval_id); approve <id> later to write.
    """
    return _execute(
        sql,
        include_rows=False,
        database=database,
        db_path=db_path,
        catalog_path=catalog_path,
        policy_path=policy_path,
        approvals_path=approvals_path,
        agent=agent,
    )


def datapilot_check(
    sql: str,
    *,
    database: str | None = None,
    db_path: str | Path | None = None,
    catalog_path: str | Path | None = None,
    policy_path: str | Path | None = None,
    agent: str = "mcp",
    actor: str | None = None,
    model_id: str | None = None,
    prompt_summary: str | None = None,
) -> dict[str, Any]:
    """DataPilot BLOCK/EXECUTE check (never writes)."""
    from write_gate.datapilot import block_or_execute

    return block_or_execute(
        sql,
        execute=False,
        database=database,
        db_path=str(db_path) if db_path else None,
        catalog_path=str(catalog_path) if catalog_path else None,
        policy_path=str(policy_path) if policy_path else None,
        agent=agent,
        actor=actor,
        model_id=model_id,
        prompt_summary=prompt_summary,
    )


def datapilot_execute(
    sql: str,
    *,
    database: str | None = None,
    db_path: str | Path | None = None,
    catalog_path: str | Path | None = None,
    policy_path: str | Path | None = None,
    agent: str = "mcp",
    actor: str | None = None,
    model_id: str | None = None,
    prompt_summary: str | None = None,
) -> dict[str, Any]:
    """DataPilot EXECUTE path — runs SQL only when gate returns ALLOW."""
    from write_gate.datapilot import block_or_execute

    return block_or_execute(
        sql,
        execute=True,
        database=database,
        db_path=str(db_path) if db_path else None,
        catalog_path=str(catalog_path) if catalog_path else None,
        policy_path=str(policy_path) if policy_path else None,
        agent=agent,
        actor=actor,
        model_id=model_id,
        prompt_summary=prompt_summary,
    )
