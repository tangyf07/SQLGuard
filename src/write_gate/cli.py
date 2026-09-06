"""CLI: sql-write-gate check|exec|audit|hook|mcp|proxy|approve|reject|resolve|pending|init."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from write_gate.approvals import (
    STATUS_FAILED,
    STATUS_PENDING,
    STATUS_SUCCEEDED,
    STATUS_UNKNOWN,
    ApprovalError,
    force_unknown_check,
    get_approval,
    is_terminal_success,
    list_pending,
    mark_rejected,
    resolve_approval,
)
from write_gate.trust import TrustError, require_approval_trust
from write_gate.audit import (
    format_audit_table,
    read_audit,
    resolve_trusted_database_url,
    url_has_redacted_password,
)
from write_gate.decision import ACTION_ALLOW, ACTION_APPROVAL, ACTION_BLOCK, Decision
from write_gate.paths import default_approvals_path, default_audit_path
from write_gate.wrapper import WriteGate


def _headline(action: str) -> str:
    if action == ACTION_BLOCK:
        return "BLOCKED"
    if action == ACTION_APPROVAL:
        return "APPROVAL REQUIRED"
    return "ALLOWED"


def format_decision(decision: Decision) -> str:
    lines = [
        _headline(decision.action),
        f"Risk: {_safe(decision.risk)}",
        f"Risk score: {getattr(decision, 'risk_score', 0)}",
        f"Operation: {_safe(decision.operation).upper()}",
        f"Table: {_safe(decision.table)}",
        f"Rule: {_safe(decision.rule_id)}",
        f"Reason: {_safe(decision.reason)}",
    ]
    factors = getattr(decision, "risk_factors", None) or []
    if factors:
        lines.append(f"Risk factors: {', '.join(factors)}")
    if decision.estimated_rows is not None:
        lines.append(f"Estimated rows: {decision.estimated_rows}")
    if decision.approval_id:
        lines.append(f"Approval id: {decision.approval_id}")
    return "\n".join(lines)


def _safe(value: object) -> str:
    if value is None or value == "":
        return "-"
    return str(value)


def _approvals_path(args: argparse.Namespace) -> Path:
    raw = getattr(args, "approvals", None)
    return Path(raw) if raw else default_approvals_path()



def _require_trust_or_exit() -> int | None:
    """Gate approve/resolve/reject behind trusted-executor token. None = ok."""
    try:
        require_approval_trust()
    except TrustError as exc:
        sys.stderr.write(str(exc) + "\n")
        return 1
    return None


def _gate_from_args(args: argparse.Namespace) -> WriteGate:
    agent = getattr(args, "agent", None) or "cli"
    return WriteGate(
        db_path=Path(args.db) if getattr(args, "db", None) else None,
        database=getattr(args, "database", None),
        catalog_path=Path(args.catalog) if getattr(args, "catalog", None) else None,
        policy_path=Path(args.policy) if getattr(args, "policy", None) else None,
        approvals_path=_approvals_path(args),
        agent=agent,
        actor=getattr(args, "actor", None) or agent,
        model_id=getattr(args, "model_id", None),
        prompt_summary=getattr(args, "prompt_summary", None),
    )


def _gate_from_record(rec, *, approvals_path: Path, agent: str = "approve") -> WriteGate:
    database = rec.database
    if database and url_has_redacted_password(database):
        resolved = resolve_trusted_database_url(
            database,
            config_id=getattr(rec, "database_config_id", None),
        )
        if resolved:
            database = resolved
        # else leave redacted; WriteGate._connect refuses *** and explains
    gate = WriteGate(
        database=database,
        db_path=Path(rec.db_path) if rec.db_path else None,
        catalog_path=Path(rec.catalog_path) if rec.catalog_path else None,
        policy_path=Path(rec.policy_path) if rec.policy_path else None,
        approvals_path=approvals_path,
        agent=agent,
    )
    gate.database_config_id = getattr(rec, "database_config_id", None)
    return gate

def _serialize_cell(value: object) -> object:
    """Make DB cell values JSON-serializable (dates, decimals, bytes)."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    iso = getattr(value, "isoformat", None)
    if callable(iso):
        try:
            return iso()
        except Exception:
            pass
    try:
        from decimal import Decimal

        if isinstance(value, Decimal):
            return float(value)
    except Exception:
        pass
    return str(value)


def _materialize_result(result) -> dict[str, object] | None:
    """Fetch rows before the connection closes; return serializable payload bits.

    v0.23: caps rows/bytes via runtime settings; default truncate + truncated=true.
    """
    from write_gate.results import ResultOversizeError, materialize_result

    try:
        return materialize_result(result)
    except ResultOversizeError:
        raise


def _print_decision(decision: Decision, *, as_json: bool, result=None) -> int:
    if as_json:
        payload = decision.to_dict()
        if result is not None and decision.allowed:
            materialized = _materialize_result(result)
            if materialized is not None:
                if "rows" in materialized:
                    payload["rows"] = materialized["rows"]
                if "rowcount" in materialized:
                    payload["rowcount"] = materialized["rowcount"]
                if "truncated" in materialized:
                    payload["truncated"] = materialized["truncated"]
        json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(format_decision(decision) + "\n")
    if decision.action == ACTION_ALLOW:
        return 0
    if decision.action == ACTION_APPROVAL:
        return 1
    return 2

def _add_shared(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--policy", help="Path to policy.yaml (default: ./policy.yaml)")
    parser.add_argument("--catalog", help="Path to catalog.json")
    parser.add_argument("--db", help="Path to DuckDB warehouse")
    parser.add_argument(
        "--database",
        help=(
            "DuckDB file path or postgres:// / mysql:// / mysql+pymysql:// / "
            "sqlite:/// / sqlite+aiosqlite:// URL "
            "(default: DATABASE_URL, then local DuckDB)"
        ),
    )
    parser.add_argument("--agent", default="cli", help="Audit agent name")
    parser.add_argument("--actor", default=None, help="Audit actor (DataPilot / human id)")
    parser.add_argument("--model-id", dest="model_id", default=None, help="Model id for audit")
    parser.add_argument(
        "--prompt-summary",
        dest="prompt_summary",
        default=None,
        help="Short prompt summary for audit (truncated)",
    )
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    parser.add_argument(
        "--approvals",
        help="Approvals path (JSONL mirror; SQLite source of truth is sibling .sqlite; default: .logs/approvals.jsonl)",
    )


def build_parser() -> argparse.ArgumentParser:
    shared = argparse.ArgumentParser(add_help=False)
    _add_shared(shared)
    parser = argparse.ArgumentParser(
        prog="sql-write-gate",
        description="Policy firewall for AI agents writing to databases (no LLM, no API key)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    check_p = sub.add_parser("check", help="Evaluate SQL without executing", parents=[shared])
    check_p.add_argument("sql", help="One SQL statement")

    exec_p = sub.add_parser("exec", help="Evaluate then execute if ALLOW", parents=[shared])
    exec_p.add_argument("sql", help="One SQL statement")

    audit_p = sub.add_parser("audit", help="Print recent audit log rows")
    audit_p.add_argument("--limit", type=int, default=20, help="How many recent rows")
    audit_p.add_argument("--audit-path", default=None, help="Override audit jsonl path")

    hook_p = sub.add_parser(
        "hook",
        help="PreToolUse: block raw DB CLIs; never execute SQL",
        parents=[shared],
    )
    hook_p.add_argument(
        "--command",
        dest="hook_command",
        default=None,
        help="Bash command (tests / override stdin JSON)",
    )
    hook_p.add_argument(
        "--sql",
        dest="hook_sql",
        default=None,
        help="Raw SQL to evaluate (tests; still never executed)",
    )

    sub.add_parser(
        "mcp",
        help="Start MCP stdio server (query_sql / write_sql; ALLOW executes)",
        parents=[shared],
    )

    proxy_p = sub.add_parser(
        "proxy",
        help="Front a real DB: gate SQL then execute if ALLOW",
        parents=[shared],
    )
    proxy_p.add_argument(
        "--sql",
        dest="proxy_sql",
        default=None,
        help="One SQL statement then exit",
    )
    proxy_p.add_argument(
        "--once",
        action="store_true",
        help="Exit after one statement (default when --sql is set; stdin also exits on EOF)",
    )
    proxy_p.add_argument(
        "--listen",
        default=None,
        metavar="HOST:PORT",
        help="Text protocol: one SQL per connection then close (tests: 127.0.0.1:0)",
    )

    queue = argparse.ArgumentParser(add_help=False)
    queue.add_argument(
        "--approvals",
        help="Approvals path (JSONL mirror; SQLite source of truth is sibling .sqlite; default: .logs/approvals.jsonl)",
    )
    queue.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    approve_p = sub.add_parser(
        "approve",
        help="Execute a pending/failed approval id (requires SQL_WRITE_GATE_APPROVAL_TOKEN; re-runs guards)",
        parents=[queue],
    )
    approve_p.add_argument("approval_id", help="Approval id")
    approve_p.add_argument(
        "--allow-unknown-retry",
        action="store_true",
        help=(
            "Explicitly reclaim an unknown outcome and re-execute AFTER manual DB "
            "verify (never automatic; documents risk of double-write)"
        ),
    )
    approve_p.add_argument(
        "--force-unknown-check",
        action="store_true",
        help=(
            "Run crash-recovery TTL check and print status without executing "
            "(stuck executing → unknown when TTL expires)"
        ),
    )

    reject_p = sub.add_parser(
        "reject",
        help="Reject a pending/failed/unknown approval id (requires SQL_WRITE_GATE_APPROVAL_TOKEN)",
        parents=[queue],
    )
    reject_p.add_argument("approval_id", help="Approval id")

    resolve_p = sub.add_parser(
        "resolve",
        help=(
            "Mark unknown/failed after manual DB verify without re-executing "
            "(requires SQL_WRITE_GATE_APPROVAL_TOKEN; succeeded|failed|rejected)"
        ),
        parents=[queue],
    )
    resolve_p.add_argument("approval_id", help="Approval id")
    resolve_p.add_argument(
        "--as",
        dest="resolve_as",
        required=True,
        choices=["succeeded", "failed", "rejected", "confirm-succeeded"],
        help="Human-resolved terminal status (confirm-succeeded aliases succeeded)",
    )
    resolve_p.add_argument(
        "--note",
        default=None,
        help="Optional note recorded on the approval (e.g. how DB was verified)",
    )

    sub.add_parser(
        "pending",
        help="List pending approval ids",
        parents=[queue],
    )

    serve_p = sub.add_parser(
        "serve",
        help="SQLGuard DataPilot HTTP API (POST /v1/check|/v1/execute)",
        parents=[shared],
    )
    serve_p.add_argument("--host", default="127.0.0.1", help="Bind host")
    serve_p.add_argument("--port", type=int, default=8787, help="Bind port")

    dp = sub.add_parser(
        "datapilot",
        help="DataPilot BLOCK/EXECUTE evaluate (optional --execute)",
        parents=[shared],
    )
    dp.add_argument("sql", help="One SQL statement")
    dp.add_argument(
        "--execute",
        action="store_true",
        help="Execute on ALLOW (default: check-only)",
    )

    init_p = sub.add_parser(
        "init",
        help="Scaffold policy.yaml, catalog.json, GETTING_STARTED.md",
    )
    init_p.add_argument(
        "--dir",
        default=".",
        help="Target directory (default: current directory)",
    )
    init_p.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing starter files",
    )
    return parser


def _read_hook_stdin() -> str:
    if sys.stdin.isatty():
        return ""
    return sys.stdin.read()


def _cmd_hook(args: argparse.Namespace) -> int:
    from write_gate.hooks import run_hook

    agent = getattr(args, "agent", None)
    if not agent or agent == "cli":
        agent = "hook"
    stdin_text = None
    if not args.hook_command and not args.hook_sql:
        stdin_text = _read_hook_stdin()
    return run_hook(
        bash_command=args.hook_command,
        sql=args.hook_sql,
        stdin_text=stdin_text,
        database=getattr(args, "database", None),
        db=getattr(args, "db", None),
        catalog=getattr(args, "catalog", None),
        policy=getattr(args, "policy", None),
        agent=agent,
    )


def _cmd_mcp(args: argparse.Namespace) -> int:
    try:
        from write_gate.mcp_server import run_server
    except ImportError:
        sys.stderr.write('pip install -e ".[mcp]"\n')
        return 1
    agent = getattr(args, "agent", None)
    if not agent or agent == "cli":
        agent = "mcp"
    try:
        run_server(
            database=getattr(args, "database", None),
            db=getattr(args, "db", None),
            catalog=getattr(args, "catalog", None),
            policy=getattr(args, "policy", None),
            agent=agent,
        )
    except ImportError:
        sys.stderr.write('pip install -e ".[mcp]"\n')
        return 1
    return 0


def _cmd_proxy(args: argparse.Namespace) -> int:
    from write_gate.proxy import run_cli

    agent = getattr(args, "agent", None)
    if not agent or agent == "cli":
        args.agent = "proxy"
    with _gate_from_args(args) as gate:
        return run_cli(
            gate,
            sql=getattr(args, "proxy_sql", None),
            listen=getattr(args, "listen", None),
            once=bool(getattr(args, "once", False)),
            as_json=bool(getattr(args, "json", False)),
        )


def _cmd_approve(args: argparse.Namespace) -> int:
    denied = _require_trust_or_exit()
    if denied is not None:
        return denied
    path = _approvals_path(args)
    if bool(getattr(args, "force_unknown_check", False)):
        try:
            rec = force_unknown_check(args.approval_id, path=path)
        except ApprovalError as exc:
            sys.stderr.write(str(exc) + "\n")
            return 1
        payload = {
            "id": rec.id,
            "status": rec.status,
            "outcome_note": rec.outcome_note,
            "error_class": rec.error_class,
            "executing_at": rec.executing_at,
            "hint": (
                "If status is unknown: verify target DB, then "
                "`resolve --as succeeded|failed|rejected` or "
                "`approve --allow-unknown-retry` (never automatic)."
            ),
        }
        if args.json:
            json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
            sys.stdout.write("\n")
        else:
            sys.stdout.write(
                f"STATUS {rec.status}\n"
                f"Approval id: {rec.id}\n"
                f"Note: {rec.outcome_note or '-'}\n"
                f"{payload['hint']}\n"
            )
        return 0

    rec = get_approval(args.approval_id, path=path)
    if rec is None:
        sys.stderr.write(f"approval not found or not pending: {args.approval_id}\n")
        return 1
    allow_retry = bool(getattr(args, "allow_unknown_retry", False))
    allowed = {STATUS_PENDING, STATUS_FAILED, STATUS_SUCCEEDED, "approved"}
    if allow_retry:
        allowed.add(STATUS_UNKNOWN)
    if is_terminal_success(rec.status):
        pass  # idempotent path inside gate.approve
    elif rec.status not in allowed:
        sys.stderr.write(
            f"approval not claimable (status={rec.status}): {args.approval_id}\n"
            "Use `approve --force-unknown-check`, `resolve --as …`, or "
            "`approve --allow-unknown-retry` after manual verify.\n"
        )
        return 1
    materialized = None
    with _gate_from_record(rec, approvals_path=path, agent="approve") as gate:
        try:
            decision, result = gate.approve(
                rec.id,
                allow_unknown_retry=allow_retry,
            )
            # Materialize rows before closing the connection (R3).
            materialized = _materialize_result(result)
        except ApprovalError as exc:
            sys.stderr.write(str(exc) + "\n")
            return 1
    return _print_decision(decision, as_json=bool(args.json), result=materialized)


def _cmd_reject(args: argparse.Namespace) -> int:
    denied = _require_trust_or_exit()
    if denied is not None:
        return denied
    path = _approvals_path(args)
    rec = get_approval(args.approval_id, path=path)
    if rec is None or rec.status not in {STATUS_PENDING, STATUS_FAILED, STATUS_UNKNOWN}:
        sys.stderr.write(f"approval not found or not pending: {args.approval_id}\n")
        return 1
    try:
        rec = mark_rejected(rec.id, path=path)
    except ApprovalError as exc:
        sys.stderr.write(str(exc) + "\n")
        return 1
    if args.json:
        json.dump(rec.to_dict(), sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(f"REJECTED\nApproval id: {rec.id}\n")
    return 0


def _cmd_resolve(args: argparse.Namespace) -> int:
    denied = _require_trust_or_exit()
    if denied is not None:
        return denied
    path = _approvals_path(args)
    try:
        rec = resolve_approval(
            args.approval_id,
            as_status=str(args.resolve_as),
            path=path,
            outcome_note=getattr(args, "note", None),
        )
    except ApprovalError as exc:
        sys.stderr.write(str(exc) + "\n")
        return 1
    if args.json:
        json.dump(rec.to_dict(), sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(
            f"RESOLVED\nApproval id: {rec.id}\nStatus: {rec.status}\n"
        )
    return 0


def _cmd_pending(args: argparse.Namespace) -> int:
    path = _approvals_path(args)
    rows = list_pending(path=path)
    if args.json:
        json.dump([r.to_dict() for r in rows], sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
        return 0
    if not rows:
        sys.stdout.write("(no pending approvals)\n")
        return 0
    for rec in rows:
        decision = rec.decision if isinstance(rec.decision, dict) else {}
        op = decision.get("operation") or "-"
        table = decision.get("table") or "-"
        sys.stdout.write(f"{rec.id}  {rec.status}  {op}  {table}\n")
    return 0


def _cmd_init(args: argparse.Namespace) -> int:
    from write_gate.init import format_init_report, init_project

    result = init_project(args.dir, force=bool(args.force))
    sys.stdout.write(format_init_report(result, args.dir))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "audit":
        path = Path(args.audit_path) if args.audit_path else default_audit_path()
        rows = read_audit(path, limit=args.limit)
        sys.stdout.write(format_audit_table(rows) + "\n")
        return 0

    if args.command == "hook":
        return _cmd_hook(args)

    if args.command == "mcp":
        return _cmd_mcp(args)

    if args.command == "proxy":
        return _cmd_proxy(args)

    if args.command == "approve":
        return _cmd_approve(args)

    if args.command == "reject":
        return _cmd_reject(args)

    if args.command == "resolve":
        return _cmd_resolve(args)

    if args.command == "pending":
        return _cmd_pending(args)

    if args.command == "init":
        return _cmd_init(args)

    if args.command == "datapilot":
        from write_gate.datapilot import block_or_execute

        payload = block_or_execute(
            args.sql,
            execute=bool(args.execute),
            database=getattr(args, "database", None),
            db_path=getattr(args, "db", None),
            catalog_path=getattr(args, "catalog", None),
            policy_path=getattr(args, "policy", None),
            agent=getattr(args, "agent", None) or "datapilot",
            actor=getattr(args, "actor", None),
            model_id=getattr(args, "model_id", None),
            prompt_summary=getattr(args, "prompt_summary", None),
        )
        if args.json:
            json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
            sys.stdout.write("\n")
        else:
            lines = [
                str(payload["datapilot"]),
                f"Action: {payload['action']}",
                f"Rule: {payload.get('rule_id')}",
                f"Risk score: {payload.get('risk_score')}",
                f"Reason: {payload.get('reason')}",
                f"executed: {'yes' if payload.get('executed') else 'no'}",
            ]
            sys.stdout.write("\n".join(lines) + "\n")
        if payload["datapilot"] == "EXECUTE" and (
            not args.execute or payload.get("executed")
        ):
            return 0
        if payload["datapilot"] == "APPROVAL":
            return 1
        return 2

    if args.command == "serve":
        from write_gate.api import run_serve_cli

        defaults = {
            "database": getattr(args, "database", None),
            "db_path": getattr(args, "db", None),
            "catalog": getattr(args, "catalog", None),
            "policy": getattr(args, "policy", None),
            "agent": getattr(args, "agent", None) or "datapilot",
        }
        return run_serve_cli(
            host=args.host,
            port=args.port,
            defaults=defaults,
        )

    with _gate_from_args(args) as gate:
        if args.command == "check":
            decision = gate.check(args.sql)
            result = None
        else:
            decision, result = gate.execute(args.sql)
            result = _materialize_result(result)
    return _print_decision(decision, as_json=bool(args.json), result=result)


if __name__ == "__main__":
    raise SystemExit(main())
