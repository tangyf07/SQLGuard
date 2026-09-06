"""MCP stdio server. FastMCP is lazy-imported so mcp_tools tests need no SDK."""

from __future__ import annotations

from typing import Any


def _fastmcp():
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:  # optional extra
        raise ImportError('pip install -e ".[mcp]"') from exc
    return FastMCP


def create_server(
    *,
    database: str | None = None,
    db: str | None = None,
    catalog: str | None = None,
    policy: str | None = None,
    agent: str = "mcp",
):
    """Build a FastMCP server exposing query/write + DataPilot BLOCK/EXECUTE."""
    from write_gate.mcp_tools import datapilot_check, datapilot_execute
    from write_gate.mcp_tools import query_sql as check_query
    from write_gate.mcp_tools import write_sql as check_write

    FastMCP = _fastmcp()
    mcp = FastMCP("sql-write-gate")
    gate_kwargs = {
        "database": database,
        "db_path": db,
        "catalog_path": catalog,
        "policy_path": policy,
        "agent": agent or "mcp",
    }

    @mcp.tool()
    def query_sql(sql: str) -> dict[str, Any]:
        """Evaluate a SELECT (or any SQL) through sql-write-gate. ALLOW executes."""
        return check_query(sql, **gate_kwargs)

    @mcp.tool()
    def write_sql(sql: str) -> dict[str, Any]:
        """Evaluate INSERT/UPDATE/DELETE/DDL through sql-write-gate. ALLOW executes."""
        return check_write(sql, **gate_kwargs)

    @mcp.tool()
    def datapilot_block_or_execute(
        sql: str,
        execute: bool = False,
        actor: str | None = None,
        model_id: str | None = None,
        prompt_summary: str | None = None,
    ) -> dict[str, Any]:
        """Stable DataPilot API: returns datapilot=BLOCK|EXECUTE|APPROVAL.

        When execute=false (default), only evaluates. When execute=true, runs
        SQL only if the gate returns ALLOW.
        """
        fn = datapilot_execute if execute else datapilot_check
        return fn(
            sql,
            actor=actor,
            model_id=model_id,
            prompt_summary=prompt_summary,
            **gate_kwargs,
        )

    return mcp


def run_server(
    *,
    database: str | None = None,
    db: str | None = None,
    catalog: str | None = None,
    policy: str | None = None,
    agent: str = "mcp",
) -> None:
    """Start the MCP server on stdio (mcp.run())."""
    mcp = create_server(
        database=database,
        db=db,
        catalog=catalog,
        policy=policy,
        agent=agent,
    )
    mcp.run()


if __name__ == "__main__":
    run_server()
