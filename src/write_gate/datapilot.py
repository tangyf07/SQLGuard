"""Stable DataPilot BLOCK / EXECUTE API for agents (MCP / CLI / thin HTTP).

Maps gate Decisions to a two-verb surface:
  - BLOCK   — do not run SQL (covers Decision BLOCK)
  - EXECUTE — SQL is safe to run / was run (covers Decision ALLOW)
  - APPROVAL — human queue (REQUIRE_APPROVAL); not auto-executed

``check`` never writes. ``execute`` runs only on ALLOW.
"""

from __future__ import annotations

import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import urlparse

from write_gate.decision import ACTION_ALLOW, ACTION_APPROVAL, ACTION_BLOCK, Decision
from write_gate.wrapper import WriteGate

DATAPILOT_BLOCK = "BLOCK"
DATAPILOT_EXECUTE = "EXECUTE"
DATAPILOT_APPROVAL = "APPROVAL"


def to_datapilot_action(decision: Decision) -> str:
    if decision.action == ACTION_ALLOW:
        return DATAPILOT_EXECUTE
    if decision.action == ACTION_APPROVAL:
        return DATAPILOT_APPROVAL
    return DATAPILOT_BLOCK


def datapilot_payload(
    decision: Decision,
    *,
    executed: bool = False,
    latency_ms: float | None = None,
    rows: list[list[Any]] | None = None,
    rowcount: int | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Stable JSON shape for DataPilot clients."""
    payload: dict[str, Any] = {
        "datapilot": to_datapilot_action(decision),
        "action": decision.action,  # ALLOW / BLOCK / REQUIRE_APPROVAL
        "executed": bool(executed),
        "rule_id": decision.rule_id,
        "reason": decision.reason,
        "operation": decision.operation,
        "table": decision.table,
        "risk": decision.risk,
        "risk_score": getattr(decision, "risk_score", 0),
        "risk_factors": list(getattr(decision, "risk_factors", []) or []),
        "sql": decision.sql,
        "evidence": decision.evidence,
        "estimated_rows": decision.estimated_rows,
    }
    if decision.approval_id:
        payload["approval_id"] = decision.approval_id
    if latency_ms is not None:
        payload["latency_ms"] = round(float(latency_ms), 3)
    if rowcount is not None:
        payload["rowcount"] = rowcount
    if rows is not None:
        payload["rows"] = rows
    if extra:
        payload.update(extra)
    return payload


def block_or_execute(
    sql: str,
    *,
    execute: bool = False,
    gate: WriteGate | None = None,
    database: str | None = None,
    db_path: str | None = None,
    catalog_path: str | None = None,
    policy_path: str | None = None,
    agent: str = "datapilot",
    actor: str | None = None,
    model_id: str | None = None,
    prompt_summary: str | None = None,
) -> dict[str, Any]:
    """Evaluate SQL; optionally execute on ALLOW.

    Returns DataPilot payload. Never raises on BLOCK.
    """
    owns = gate is None
    t0 = time.perf_counter()
    g = gate or WriteGate(
        database=database,
        db_path=db_path,
        catalog_path=catalog_path,
        policy_path=policy_path,
        agent=agent or "datapilot",
        actor=actor or agent,
        model_id=model_id,
        prompt_summary=prompt_summary,
    )
    if actor:
        g.actor = actor
    if model_id is not None:
        g.model_id = model_id
    if prompt_summary is not None:
        g.prompt_summary = prompt_summary
    try:
        if execute:
            decision, result = g.execute(sql)
            executed = decision.action == ACTION_ALLOW and result is not None
            rows = None
            rowcount = None
            if executed and result is not None:
                try:
                    from write_gate.results import materialize_result
                    from write_gate.runtime import load_runtime_settings

                    mat = materialize_result(result, settings=load_runtime_settings())
                    if mat is not None:
                        rows = list(mat.get("rows") or [])
                        rowcount = mat.get("rowcount", len(rows))
                except Exception:
                    rowcount = getattr(result, "rowcount", None)
            latency = (time.perf_counter() - t0) * 1000.0
            return datapilot_payload(
                decision,
                executed=executed,
                latency_ms=latency,
                rows=rows,
                rowcount=rowcount,
            )
        decision = g.check(sql)
        latency = (time.perf_counter() - t0) * 1000.0
        return datapilot_payload(decision, executed=False, latency_ms=latency)
    finally:
        if owns:
            close = getattr(g, "close", None)
            if callable(close):
                close()


def serve_http(
    host: str = "127.0.0.1",
    port: int = 8787,
    *,
    database: str | None = None,
    policy_path: str | None = None,
    catalog_path: str | None = None,
) -> None:
    """Minimal HTTP DataPilot: POST /v1/datapilot {\"sql\", \"execute\": bool}."""

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args) -> None:  # quieter
            return

        def _json(self, code: int, body: dict[str, Any]) -> None:
            raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            if path in {"/", "/health", "/v1/health"}:
                self._json(200, {"ok": True, "service": "sql-write-gate-datapilot"})
                return
            self._json(404, {"error": "not_found"})

        def do_POST(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            if path not in {"/v1/datapilot", "/datapilot", "/v1/block-or-execute"}:
                self._json(404, {"error": "not_found"})
                return
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b"{}"
            try:
                body = json.loads(raw.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                self._json(400, {"error": "invalid_json"})
                return
            sql = str(body.get("sql") or "")
            if not sql.strip():
                self._json(400, {"error": "sql_required"})
                return
            result = block_or_execute(
                sql,
                execute=bool(body.get("execute", False)),
                database=body.get("database") or database,
                policy_path=body.get("policy_path") or policy_path,
                catalog_path=body.get("catalog_path") or catalog_path,
                actor=body.get("actor"),
                model_id=body.get("model_id"),
                prompt_summary=body.get("prompt_summary"),
                agent=str(body.get("agent") or "datapilot-http"),
            )
            self._json(200, result)

    httpd = HTTPServer((host, port), Handler)
    print(f"DataPilot HTTP on http://{host}:{port}/v1/datapilot", flush=True)
    httpd.serve_forever()
