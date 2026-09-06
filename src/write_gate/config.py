"""Load policy.yaml (environment, per-operation rules, blast-radius limits)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from write_gate.paths import default_policy_path

VALID_RULES = {"allow", "block", "approval"}
VALID_OPS = ("select", "insert", "update", "delete", "ddl")

PRODUCTION_DEFAULTS: dict[str, Any] = {
    "environment": "production",
    "rules": {
        "select": "allow",
        "insert": "approval",
        "update": "approval",
        "delete": "block",
        "ddl": "block",
    },
    "limits": {
        "update_rows": 100,
        "delete_rows": 50,
    },
}

DEMO_DEFAULTS: dict[str, Any] = {
    "environment": "demo",
    "rules": {
        "select": "allow",
        "insert": "allow",
        "update": "allow",
        "delete": "allow",
        "ddl": "block",
    },
    "limits": {
        "update_rows": 10000,
        "delete_rows": 10000,
    },
}


@dataclass(frozen=True)
class Policy:
    environment: str
    rules: dict[str, str] = field(default_factory=dict)
    update_rows: int = 100
    delete_rows: int = 50
    # v0.23 ops knobs (also overridable via SQL_WRITE_GATE_* env vars)
    statement_timeout_sec: float | None = None
    result_row_limit: int | None = None
    result_byte_limit: int | None = None
    audit_max_bytes: int | None = None
    audit_rotate_daily: bool | None = None
    # SQLGuard 1.1 — GameStream-style table permissions + hallucination knobs
    table_permissions: dict[str, list[str]] = field(default_factory=dict)
    permissions_enforced: bool = False
    allow_unknown_tables: bool = False
    allow_unknown_columns: bool = False
    default_table_ops: list[str] | None = None
    explain_cost_threshold: float | None = None
    enable_explain: bool = False

    def rule_for(self, operation: str) -> str:
        op = (operation or "ddl").lower()
        return self.rules.get(op, "block")

    def row_limit(self, operation: str) -> int | None:
        if operation == "update":
            return self.update_rows
        if operation == "delete":
            return self.delete_rows
        return None

    def with_env_approvals_cleared(self) -> "Policy":
        """Human approve clears environment 'approval' rules only (block stays)."""
        rules = {
            op: ("allow" if rule == "approval" else rule)
            for op, rule in self.rules.items()
        }
        return Policy(
            environment=self.environment,
            rules=rules,
            update_rows=self.update_rows,
            delete_rows=self.delete_rows,
            statement_timeout_sec=self.statement_timeout_sec,
            result_row_limit=self.result_row_limit,
            result_byte_limit=self.result_byte_limit,
            audit_max_bytes=self.audit_max_bytes,
            audit_rotate_daily=self.audit_rotate_daily,
            table_permissions=dict(self.table_permissions),
            permissions_enforced=self.permissions_enforced,
            allow_unknown_tables=self.allow_unknown_tables,
            allow_unknown_columns=self.allow_unknown_columns,
            default_table_ops=(None if self.default_table_ops is None else list(self.default_table_ops)),
            explain_cost_threshold=self.explain_cost_threshold,
            enable_explain=self.enable_explain,
        )


def _normalize_rules(raw: Any) -> dict[str, str]:
    src = dict(PRODUCTION_DEFAULTS["rules"])
    if isinstance(raw, dict):
        for key, value in raw.items():
            k = str(key).lower()
            v = str(value).lower()
            if k in VALID_OPS and v in VALID_RULES:
                src[k] = v
    return {k: src[k] for k in VALID_OPS}


def policy_from_dict(raw: dict[str, Any] | None = None) -> Policy:
    data = raw or {}
    limits = data.get("limits") or {}
    timeout = data.get("statement_timeout_sec", limits.get("statement_timeout_sec"))
    result_rows = limits.get("result_rows", limits.get("result_row_limit"))
    result_bytes = limits.get("result_bytes", limits.get("result_byte_limit"))
    audit_max = limits.get("audit_max_bytes", data.get("audit_max_bytes"))
    audit_daily = limits.get("audit_rotate_daily", data.get("audit_rotate_daily"))
    table_perms, enforced = _parse_permissions(data)
    hallu = data.get("hallucination") or data.get("schema") or {}
    if not isinstance(hallu, dict):
        hallu = {}
    explain_thr = limits.get("explain_cost_threshold", data.get("explain_cost_threshold"))
    enable_explain = data.get("enable_explain", limits.get("enable_explain", False))
    return Policy(
        environment=str(data.get("environment") or PRODUCTION_DEFAULTS["environment"]),
        rules=_normalize_rules(data.get("rules")),
        update_rows=int(limits.get("update_rows", PRODUCTION_DEFAULTS["limits"]["update_rows"])),
        delete_rows=int(limits.get("delete_rows", PRODUCTION_DEFAULTS["limits"]["delete_rows"])),
        statement_timeout_sec=(None if timeout is None else float(timeout)),
        result_row_limit=(None if result_rows is None else int(result_rows)),
        result_byte_limit=(None if result_bytes is None else int(result_bytes)),
        audit_max_bytes=(None if audit_max is None else int(audit_max)),
        audit_rotate_daily=(None if audit_daily is None else bool(audit_daily)),
        table_permissions=table_perms,
        permissions_enforced=enforced,
        allow_unknown_tables=bool(hallu.get("allow_unknown_tables", data.get("allow_unknown_tables", False))),
        allow_unknown_columns=bool(hallu.get("allow_unknown_columns", data.get("allow_unknown_columns", False))),
        default_table_ops=([str(x).lower() for x in (data.get("permissions") or {}).get("default_ops")] if isinstance(data.get("permissions"), dict) and (data.get("permissions") or {}).get("default_ops") is not None else None),
        explain_cost_threshold=(None if explain_thr is None else float(explain_thr)),
        enable_explain=bool(enable_explain),
    )



def _parse_permissions(data: dict[str, Any]) -> tuple[dict[str, list[str]], bool]:
    """Parse permissions: tables map and/or allow_tables list."""
    raw = data.get("permissions") or {}
    if not isinstance(raw, dict):
        return {}, False
    table_perms: dict[str, list[str]] = {}
    tables = raw.get("tables") or raw.get("table_permissions") or {}
    if isinstance(tables, dict):
        for k, v in tables.items():
            key = str(k).lower()
            if isinstance(v, (list, tuple, set)):
                table_perms[key] = [str(x).lower() for x in v]
            elif isinstance(v, str):
                table_perms[key] = [v.lower()]
            elif v is True:
                table_perms[key] = ["select", "insert", "update", "delete"]
    allow_tables = raw.get("allow_tables")
    if isinstance(allow_tables, list):
        default_ops = raw.get("default_ops") or ["select", "insert", "update", "delete"]
        ops = [str(x).lower() for x in default_ops]
        for name in allow_tables:
            table_perms.setdefault(str(name).lower(), list(ops))
    enforced = bool(raw.get("enforced", raw.get("enforce", bool(table_perms))))
    return table_perms, enforced


def load_policy(path: Path | str | None = None) -> Policy:
    policy_path = Path(path) if path else default_policy_path()
    if not policy_path.exists():
        return policy_from_dict(PRODUCTION_DEFAULTS)
    with policy_path.open(encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    if not isinstance(raw, dict):
        return policy_from_dict(PRODUCTION_DEFAULTS)
    return policy_from_dict(raw)


def production_policy() -> Policy:
    return policy_from_dict(PRODUCTION_DEFAULTS)


def demo_policy() -> Policy:
    return policy_from_dict(DEMO_DEFAULTS)
