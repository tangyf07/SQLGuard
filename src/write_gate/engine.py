"""Policy engine: run guards, reduce to a single Decision.

any BLOCK → BLOCK; else any APPROVAL → REQUIRE_APPROVAL; else ALLOW.
Guard order prefers specific dangerous-SQL rules over environment policy.

Guards are loaded from ``write_gate.registry.default_registry`` so third-party
rules can register without forking this module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from write_gate.adapters.base import BACKEND_DUCKDB, sqlglot_dialect
from write_gate.catalog import Catalog
from write_gate.config import Policy, production_policy
from write_gate.decision import (
    ACTION_ALLOW,
    ACTION_APPROVAL,
    ACTION_BLOCK,
    RISK_LOW,
    RULE_OK,
    VERDICT_APPROVAL,
    VERDICT_BLOCK,
    Decision,
    GuardResult,
)
from write_gate.parser import ParsedSQL, parse
from write_gate.registry import default_registry
from write_gate.risk import score_from_results

GuardFn = Callable[["Context"], GuardResult]


@dataclass
class Context:
    sql: str
    parsed: ParsedSQL
    catalog: Catalog
    policy: Policy
    conn: Any | None = None
    dialect: str = BACKEND_DUCKDB
    human_approved: bool = False
    guard_results: list[GuardResult] = field(default_factory=list)


def evaluate(
    sql: str,
    catalog: Catalog,
    policy: Policy | None = None,
    conn: Any | None = None,
    dialect: str = BACKEND_DUCKDB,
    *,
    human_approved: bool = False,
    registry=None,
) -> Decision:
    parsed = parse(sql, dialect=sqlglot_dialect(dialect))
    ctx = Context(
        sql=sql,
        parsed=parsed,
        catalog=catalog,
        policy=policy or production_policy(),
        conn=conn,
        dialect=dialect,
        human_approved=human_approved,
    )
    reg = registry if registry is not None else default_registry()
    results = reg.run(ctx)
    ctx.guard_results = results
    return reduce(ctx, results)


def _guards_list() -> list[GuardFn]:
    return default_registry().functions()


def __getattr__(name: str):
    """Lazy GUARDS list so callers see the live registry."""
    if name == 'GUARDS':
        return _guards_list()
    raise AttributeError(name)


def reduce(ctx: Context, results: list[GuardResult]) -> Decision:
    parsed = ctx.parsed
    estimated = _first_estimated(results)
    evidence_acc: dict[str, Any] = {}
    for result in results:
        if result.evidence:
            evidence_acc[result.name] = result.evidence

    blocks = [r for r in results if r.verdict == VERDICT_BLOCK]
    approvals = [r for r in results if r.verdict == VERDICT_APPROVAL]

    if blocks:
        chosen = blocks[0]
        action = ACTION_BLOCK
        decision = Decision(
            action=action,
            risk=chosen.risk,
            rule_id=chosen.rule_id or RULE_OK,
            reason=chosen.reason,
            evidence={**evidence_acc, **chosen.evidence},
            sql=ctx.sql,
            operation=parsed.operation,
            table=parsed.table,
            estimated_rows=estimated if estimated is not None else chosen.evidence.get("estimated_rows"),
        )
    elif approvals:
        chosen = approvals[0]
        action = ACTION_APPROVAL
        decision = Decision(
            action=action,
            risk=chosen.risk,
            rule_id=chosen.rule_id or RULE_OK,
            reason=chosen.reason,
            evidence={**evidence_acc, **chosen.evidence},
            sql=ctx.sql,
            operation=parsed.operation,
            table=parsed.table,
            estimated_rows=estimated if estimated is not None else chosen.evidence.get("estimated_rows"),
        )
    else:
        action = ACTION_ALLOW
        decision = Decision(
            action=action,
            risk=RISK_LOW,
            rule_id=RULE_OK,
            reason=_allow_reason(parsed),
            evidence=evidence_acc,
            sql=ctx.sql,
            operation=parsed.operation,
            table=parsed.table,
            estimated_rows=estimated,
        )

    explain_ev = evidence_acc.get("explain_cost") or {}
    score, factors = score_from_results(
        action=decision.action,
        operation=parsed.operation,
        results=results,
        dangerous_flags=getattr(parsed, "dangerous_flags", None),
        explain_cost=explain_ev.get("cost"),
        explain_cost_threshold=getattr(ctx.policy, "explain_cost_threshold", None),
    )
    decision.risk_score = score
    decision.risk_factors = factors
    return decision


def _first_estimated(results: list[GuardResult]) -> int | None:
    for result in results:
        value = result.evidence.get("estimated_rows") if result.evidence else None
        if isinstance(value, int):
            return value
    return None


def _allow_reason(parsed: ParsedSQL) -> str:
    if parsed.operation == "select":
        return "只读 SELECT，绕过写库门禁"
    table = parsed.table or "?"
    if parsed.operation == "insert":
        return f"写入通过门禁: 表 {table}，列 {parsed.write_columns}，分区未过期且不含 PII"
    if parsed.operation == "update":
        return f"UPDATE 通过门禁: 表 {table}，列 {parsed.write_columns}"
    if parsed.operation == "delete":
        return f"DELETE 通过门禁: 表 {table}"
    return f"{parsed.operation.upper()} 通过门禁: 表 {table}"
