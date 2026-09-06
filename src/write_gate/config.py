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
    )


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
