"""DataPilot HTTP API: clear BLOCK / EXECUTE surface (stdlib http.server).

Contract (JSON)::

    POST /v1/check     {"sql": "...", "actor"?, "model_id"?, "prompt_summary"?}
    POST /v1/execute   same body — gate then execute on ALLOW only
    GET  /healthz      {"ok": true, "product": "SQLGuard", "version": "..."}

Responses always include ``action`` (ALLOW|BLOCK|REQUIRE_APPROVAL),
``risk_score``, ``risk_factors``, ``rule_id``, ``reason``, and for execute
``executed`` (bool). DataPilot should treat anything other than ALLOW as
non-executing; REQUIRE_APPROVAL may include ``approval_id``.
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from write_gate import __version__
from write_gate.decision import ACTION_ALLOW
from write_gate.wrapper import WriteGate


def decision_response(
    decision: Any,
    *,
    executed: bool = False,
    rows: list | None = None,
    rowcount: int | None = None,
) -> dict[str, Any]:
    from write_gate.datapilot import to_datapilot_action

    payload = decision.to_dict()
    payload["executed"] = bool(executed)
    payload["product"] = "SQLGuard"
    payload["datapilot"] = to_datapilot_action(decision)  # BLOCK | EXECUTE | APPROVAL
    if rows is not None:
        payload["rows"] = rows
    if rowcount is not None:
        payload["rowcount"] = rowcount
    return payload


def _gate_from_body(body: dict[str, Any], *, defaults: dict[str, Any]) -> WriteGate:
    return WriteGate(
        database=body.get("database") or defaults.get("database"),
        db_path=body.get("db_path") or defaults.get("db_path"),
        catalog_path=body.get("catalog") or defaults.get("catalog"),
        policy_path=body.get("policy") or defaults.get("policy"),
        agent=body.get("agent") or defaults.get("agent") or "datapilot",
        actor=body.get("actor") or body.get("agent") or "datapilot",
        model_id=body.get("model_id"),
        prompt_summary=body.get("prompt_summary"),
    )


def handle_datapilot_request(
    method: str,
    path: str,
    body: dict[str, Any] | None,
    *,
    defaults: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any]]:
    """Pure request handler used by the HTTP server and unit tests."""
    defaults = defaults or {}
    parsed = urlparse(path)
    route = parsed.path.rstrip("/") or "/"

    if method == "GET" and route in {"/healthz", "/v1/healthz"}:
        return 200, {
            "ok": True,
            "product": "SQLGuard",
            "version": __version__,
            "package": "sql-write-gate",
        }

    if method != "POST" or route not in {"/v1/check", "/v1/execute", "/v1/block"}:
        return 404, {"error": "not_found", "path": route}

    body = body or {}
    sql = body.get("sql")
    if not sql or not isinstance(sql, str):
        return 400, {"error": "missing_sql", "action": "BLOCK"}

    # /v1/block is an alias that always evaluates (same as check) — DataPilot
    # may call it when it only wants a verdict without execute intent.
    do_execute = route == "/v1/execute"
    with _gate_from_body(body, defaults=defaults) as gate:
        if do_execute:
            decision, result = gate.execute(sql)
            executed = decision.action == ACTION_ALLOW and result is not None
            rows = None
            rowcount = None
            if executed and result is not None:
                try:
                    from write_gate.results import materialize_result

                    mat = materialize_result(result)
                    if mat:
                        rows = mat.get("rows")
                        rowcount = mat.get("rowcount")
                except Exception:
                    rowcount = getattr(result, "rowcount", None)
            return 200, decision_response(
                decision, executed=executed, rows=rows, rowcount=rowcount
            )
        decision = gate.check(sql)
        return 200, decision_response(decision, executed=False)


class DataPilotHandler(BaseHTTPRequestHandler):
    server_defaults: dict[str, Any] = {}

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        sys.stderr.write("sqlguard-api: " + (fmt % args) + "\n")

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            return {}
        return data if isinstance(data, dict) else {}

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        status, payload = handle_datapilot_request(
            "GET", self.path, None, defaults=self.server_defaults
        )
        self._send(status, payload)

    def do_POST(self) -> None:  # noqa: N802
        status, payload = handle_datapilot_request(
            "POST",
            self.path,
            self._read_json(),
            defaults=self.server_defaults,
        )
        self._send(status, payload)


def serve(
    host: str = "127.0.0.1",
    port: int = 8787,
    *,
    defaults: dict[str, Any] | None = None,
) -> ThreadingHTTPServer:
    """Start DataPilot HTTP server (blocking via serve_forever in caller)."""
    DataPilotHandler.server_defaults = defaults or {}
    httpd = ThreadingHTTPServer((host, port), DataPilotHandler)
    return httpd


def run_serve_cli(
    host: str = "127.0.0.1",
    port: int = 8787,
    *,
    defaults: dict[str, Any] | None = None,
) -> int:
    httpd = serve(host, port, defaults=defaults)
    sys.stderr.write(
        f"SQLGuard DataPilot API listening on http://{host}:{port} "
        f"(POST /v1/check|/v1/execute)\n"
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\nshutting down\n")
    finally:
        httpd.server_close()
    return 0
