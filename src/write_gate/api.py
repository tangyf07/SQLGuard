"""DataPilot HTTP API: clear BLOCK / EXECUTE surface (stdlib http.server).

Contract (JSON)::

    POST /v1/check      {"sql": "...", "actor"?, "model_id"?, "prompt_summary"?}
    POST /v1/block      alias of /v1/check (evaluate only)
    POST /v1/execute    same body — gate then execute on ALLOW only
    POST /v1/datapilot  alias of /v1/execute (1.1 semantics unchanged)
    GET  /healthz       {"ok": true, "product": "SQLGuard", "version": "..."}

Trust boundary (P0):
  - ``serve`` locks database / policy / catalog / environment at startup.
  - Request bodies may only supply sql / actor / model_id / prompt_summary.
  - Body fields that would override policy/catalog/database/db_path/environment
    are rejected (400).
  - Non-loopback binds (including 0.0.0.0 / ::) require authentication;
    binding all-interfaces without a token is refused at startup.

Responses always include ``action`` (ALLOW|BLOCK|REQUIRE_APPROVAL),
``risk_score``, ``risk_factors``, ``rule_id``, ``reason``, and for execute
``executed`` (bool). DataPilot should treat anything other than ALLOW as
non-executing; REQUIRE_APPROVAL may include ``approval_id``.
"""

from __future__ import annotations

import hmac
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from write_gate import __version__
from write_gate.decision import ACTION_ALLOW
from write_gate.wrapper import WriteGate

# Body may only carry request metadata + SQL. Server locks the rest at start.
ALLOWED_BODY_KEYS = frozenset({"sql", "actor", "model_id", "prompt_summary"})
FORBIDDEN_OVERRIDE_KEYS = frozenset(
    {
        "policy",
        "catalog",
        "database",
        "db_path",
        "db",
        "environment",
        "policy_path",
        "catalog_path",
    }
)

ENV_HTTP_TOKEN = "SQL_WRITE_GATE_HTTP_TOKEN"
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
ALL_INTERFACES_HOSTS = frozenset({"0.0.0.0", "::", "[::]", "*"})


class ServeBindError(ValueError):
    """Refused HTTP bind (missing auth on non-loopback / all-interfaces)."""


def is_loopback_host(host: str | None) -> bool:
    h = (host or "").strip().lower()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    return h in LOOPBACK_HOSTS


def is_all_interfaces_host(host: str | None) -> bool:
    h = (host or "").strip().lower()
    return h in ALL_INTERFACES_HOSTS


def resolve_http_auth_token(explicit: str | None = None) -> str | None:
    """Return serve auth token from explicit arg or ``SQL_WRITE_GATE_HTTP_TOKEN``."""
    if explicit is not None and str(explicit).strip():
        return str(explicit).strip()
    env = os.environ.get(ENV_HTTP_TOKEN, "")
    return env.strip() or None


def validate_serve_bind(host: str, auth_token: str | None) -> None:
    """Refuse unsafe binds. Non-loopback (incl. 0.0.0.0) requires auth."""
    if is_loopback_host(host):
        return
    if auth_token:
        return
    if is_all_interfaces_host(host):
        raise ServeBindError(
            f"refusing to bind {host!r} without authentication "
            f"(set --auth-token or {ENV_HTTP_TOKEN})"
        )
    raise ServeBindError(
        f"non-loopback bind {host!r} requires authentication "
        f"(set --auth-token or {ENV_HTTP_TOKEN})"
    )


def extract_request_token(headers: Any) -> str | None:
    """Read Bearer token or X-SQLGuard-Token from request headers."""
    if headers is None:
        return None
    auth = headers.get("Authorization") or headers.get("authorization") or ""
    if isinstance(auth, str) and auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        return token or None
    custom = headers.get("X-SQLGuard-Token") or headers.get("x-sqlguard-token")
    if custom is not None and str(custom).strip():
        return str(custom).strip()
    return None


def authorize_http_request(
    *,
    auth_token: str | None,
    headers: Any = None,
    presented: str | None = None,
) -> bool:
    """True when no server token is configured, or presented token matches."""
    if not auth_token:
        return True
    got = presented if presented is not None else extract_request_token(headers)
    if got is None:
        return False
    return hmac.compare_digest(got, auth_token)


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


def _reject_body_overrides(body: dict[str, Any]) -> dict[str, Any] | None:
    """Return an error payload if body tries to override server-locked fields."""
    bad = sorted(k for k in body if k in FORBIDDEN_OVERRIDE_KEYS)
    if not bad:
        return None
    return {
        "error": "trust_boundary_violation",
        "action": "BLOCK",
        "rejected_fields": bad,
        "detail": (
            "HTTP serve locks policy/catalog/database/environment at startup; "
            "request body may only include sql, actor, model_id, prompt_summary"
        ),
    }


def _gate_from_locked(
    body: dict[str, Any],
    *,
    defaults: dict[str, Any],
) -> WriteGate:
    """Build WriteGate from server-locked defaults; body only supplies actor metadata."""
    return WriteGate(
        database=defaults.get("database"),
        db_path=defaults.get("db_path"),
        catalog_path=defaults.get("catalog"),
        policy_path=defaults.get("policy"),
        agent=defaults.get("agent") or "datapilot",
        actor=body.get("actor") or defaults.get("agent") or "datapilot",
        model_id=body.get("model_id"),
        prompt_summary=body.get("prompt_summary"),
    )


def handle_datapilot_request(
    method: str,
    path: str,
    body: dict[str, Any] | None,
    *,
    defaults: dict[str, Any] | None = None,
    auth_token: str | None = None,
    headers: Any = None,
    presented_token: str | None = None,
    require_auth: bool | None = None,
) -> tuple[int, dict[str, Any]]:
    """Pure request handler used by the HTTP server and unit tests.

    ``defaults`` are server-locked at serve start (database/policy/catalog/…).
    """
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

    # Auth: when a server token is configured, every non-health route needs it.
    # Non-loopback binds refuse to start without a token (see validate_serve_bind).
    must_auth = require_auth if require_auth is not None else bool(auth_token)
    if must_auth and method != "GET":
        ok = bool(auth_token) and authorize_http_request(
            auth_token=auth_token,
            headers=headers,
            presented=presented_token,
        )
        if not ok:
            return 401, {
                "error": "unauthorized",
                "action": "BLOCK",
                "detail": "valid Authorization: Bearer <token> or X-SQLGuard-Token required",
            }

    if method != "POST" or route not in {
        "/v1/check",
        "/v1/execute",
        "/v1/block",
        "/v1/datapilot",
    }:
        return 404, {"error": "not_found", "path": route}

    body = body or {}
    override_err = _reject_body_overrides(body)
    if override_err is not None:
        return 400, override_err

    sql = body.get("sql")
    if not sql or not isinstance(sql, str):
        return 400, {"error": "missing_sql", "action": "BLOCK"}

    # /v1/block → check (evaluate only); /v1/datapilot → execute (ALLOW only).
    do_execute = route in {"/v1/execute", "/v1/datapilot"}
    with _gate_from_locked(body, defaults=defaults) as gate:
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
    server_auth_token: str | None = None

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
            "GET",
            self.path,
            None,
            defaults=self.server_defaults,
            auth_token=self.server_auth_token,
            headers=self.headers,
        )
        self._send(status, payload)

    def do_POST(self) -> None:  # noqa: N802
        status, payload = handle_datapilot_request(
            "POST",
            self.path,
            self._read_json(),
            defaults=self.server_defaults,
            auth_token=self.server_auth_token,
            headers=self.headers,
        )
        self._send(status, payload)


def lock_serve_defaults(defaults: dict[str, Any] | None) -> dict[str, Any]:
    """Freeze server-side database/policy/catalog/environment for the process."""
    locked = dict(defaults or {})
    # Resolve environment from the locked policy so body cannot influence it.
    policy_path = locked.get("policy")
    environment = locked.get("environment")
    if environment is None and policy_path:
        try:
            from write_gate.config import load_policy

            environment = load_policy(policy_path).environment
        except Exception:
            environment = None
    if environment is None:
        try:
            from write_gate.config import load_policy

            environment = load_policy(None).environment
        except Exception:
            environment = "production"
    locked["environment"] = environment
    # Drop any accidental mutable aliases; only locked keys are used by the gate.
    return locked


def serve(
    host: str = "127.0.0.1",
    port: int = 8787,
    *,
    defaults: dict[str, Any] | None = None,
    auth_token: str | None = None,
) -> ThreadingHTTPServer:
    """Start DataPilot HTTP server (blocking via serve_forever in caller)."""
    token = resolve_http_auth_token(auth_token)
    validate_serve_bind(host, token)
    DataPilotHandler.server_defaults = lock_serve_defaults(defaults)
    DataPilotHandler.server_auth_token = token
    httpd = ThreadingHTTPServer((host, port), DataPilotHandler)
    return httpd


def run_serve_cli(
    host: str = "127.0.0.1",
    port: int = 8787,
    *,
    defaults: dict[str, Any] | None = None,
    auth_token: str | None = None,
) -> int:
    try:
        httpd = serve(host, port, defaults=defaults, auth_token=auth_token)
    except ServeBindError as exc:
        sys.stderr.write(f"sqlguard serve: {exc}\n")
        return 2
    locked = DataPilotHandler.server_defaults
    sys.stderr.write(
        f"SQLGuard DataPilot API listening on http://{host}:{port} "
        f"(POST /v1/check|/v1/block|/v1/execute|/v1/datapilot); "
        f"policy/catalog/database/environment locked at startup "
        f"(environment={locked.get('environment')!r}"
        f"{'; auth=on' if DataPilotHandler.server_auth_token else ''})\n"
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\nshutting down\n")
    finally:
        httpd.server_close()
    return 0
