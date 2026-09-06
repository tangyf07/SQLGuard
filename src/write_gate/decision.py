"""Unified decision model for the write gate."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

ACTION_ALLOW = "ALLOW"
ACTION_BLOCK = "BLOCK"
ACTION_APPROVAL = "REQUIRE_APPROVAL"

RISK_LOW = "low"
RISK_MEDIUM = "medium"
RISK_CRITICAL = "critical"

VERDICT_PASS = "PASS"
VERDICT_WARN = "WARN"
VERDICT_APPROVAL = "APPROVAL"
VERDICT_BLOCK = "BLOCK"

RULE_OK = "ok"
RULE_PII = "pii_column"
RULE_RESTRICTED = "restricted_column"
RULE_EXPIRED = "expired_partition"
RULE_SCHEMA = "schema_mismatch"
RULE_DELETE_NO_WHERE = "delete_without_where"
RULE_UPDATE_NO_WHERE = "update_without_where"
RULE_DROP_TABLE = "drop_table"
RULE_TRUNCATE = "truncate_table"
RULE_ALTER_TABLE = "alter_table"
RULE_BLAST = "blast_radius_exceeded"
RULE_BLAST_UNKNOWN = "blast_radius_unknown"
RULE_UNSUPPORTED = "unsupported_sql"
RULE_AMBIGUOUS_READ = "ambiguous_read"
RULE_ENV = "environment_policy"
RULE_RAW_DB_CLI = "raw_db_cli"

RULE_CARTESIAN = "cartesian_join"
RULE_FULL_TABLE = "full_table_write"
RULE_PERMISSION = "table_permission"
RULE_HALLUCINATION = "schema_hallucination"
RULE_EXPLAIN_COST = "explain_cost"


@dataclass
class GuardResult:
    """One guard's verdict. Engine reduces a list of these to a Decision."""

    name: str
    verdict: str = VERDICT_PASS
    rule_id: str | None = None
    reason: str = ""
    risk: str = RISK_LOW
    evidence: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def pass_(cls, name: str, **kwargs: Any) -> "GuardResult":
        return cls(name=name, verdict=VERDICT_PASS, **kwargs)

    @classmethod
    def warn(cls, name: str, rule_id: str, reason: str, **kwargs: Any) -> "GuardResult":
        return cls(
            name=name,
            verdict=VERDICT_WARN,
            rule_id=rule_id,
            reason=reason,
            risk=kwargs.pop("risk", RISK_MEDIUM),
            **kwargs,
        )

    @classmethod
    def approval(
        cls,
        name: str,
        rule_id: str,
        reason: str,
        *,
        risk: str = RISK_MEDIUM,
        evidence: dict[str, Any] | None = None,
    ) -> "GuardResult":
        return cls(
            name=name,
            verdict=VERDICT_APPROVAL,
            rule_id=rule_id,
            reason=reason,
            risk=risk,
            evidence=evidence or {},
        )

    @classmethod
    def block(
        cls,
        name: str,
        rule_id: str,
        reason: str,
        *,
        risk: str = RISK_CRITICAL,
        evidence: dict[str, Any] | None = None,
    ) -> "GuardResult":
        return cls(
            name=name,
            verdict=VERDICT_BLOCK,
            rule_id=rule_id,
            reason=reason,
            risk=risk,
            evidence=evidence or {},
        )


@dataclass
class Decision:
    """Final engine decision. `allowed` stays True only for ALLOW (execute path)."""

    action: str
    risk: str
    rule_id: str
    reason: str
    evidence: dict[str, Any] = field(default_factory=dict)
    sql: str = ""
    operation: str | None = None
    table: str | None = None
    estimated_rows: int | None = None
    approval_id: str | None = None
    risk_score: int = 0  # 0–100 numeric risk (SQLGuard)
    risk_factors: list[str] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.action == ACTION_ALLOW

    @property
    def message(self) -> str:
        return self.reason

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "allowed": self.allowed,
            "rule_id": self.rule_id,
            "message": self.reason,
            "sql": self.sql,
            "action": self.action,
            "risk": self.risk,
            "reason": self.reason,
            "evidence": self.evidence,
            "operation": self.operation,
            "table": self.table,
            "estimated_rows": self.estimated_rows,
            "approval_id": self.approval_id,
            "risk_score": self.risk_score,
            "risk_factors": list(self.risk_factors),
        }
        return payload


# Backward-compatible alias used by existing tests / demo.
Evidence = Decision
