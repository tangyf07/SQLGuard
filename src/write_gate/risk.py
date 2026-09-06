"""Numeric risk score (0–100) with contributing factors for SQLGuard Decisions."""

from __future__ import annotations

from typing import Any, Iterable

from write_gate.decision import (
    ACTION_ALLOW,
    ACTION_APPROVAL,
    ACTION_BLOCK,
    RISK_CRITICAL,
    RISK_MEDIUM,
    VERDICT_APPROVAL,
    VERDICT_BLOCK,
    GuardResult,
)

# Base weights (capped later). Factors are additive then clamped to 0..100.
_FACTOR_WEIGHTS: dict[str, int] = {
    "block": 80,
    "approval": 35,
    "ddl": 50,
    "delete": 40,
    "update": 25,
    "insert": 10,
    "missing_where": 45,
    "tautology_where": 45,
    "full_table_write": 50,
    "cartesian_join": 40,
    "pii": 30,
    "restricted": 50,
    "expired_partition": 35,
    "blast_radius": 40,
    "blast_unknown": 45,
    "schema_hallucination": 55,
    "permission_denied": 60,
    "explain_cost_high": 25,
    "environment_block": 50,
    "unsupported_sql": 55,
}


def _add(factors: list[str], name: str) -> None:
    if name not in factors:
        factors.append(name)


def score_from_results(
    *,
    action: str,
    operation: str | None,
    results: Iterable[GuardResult],
    dangerous_flags: Iterable[str] | None = None,
    explain_cost: float | None = None,
    explain_cost_threshold: float | None = None,
) -> tuple[int, list[str]]:
    """Compute (risk_score, risk_factors) from guard results + AST flags."""
    factors: list[str] = []
    total = 0

    if action == ACTION_BLOCK:
        _add(factors, "block")
        total += _FACTOR_WEIGHTS["block"]
    elif action == ACTION_APPROVAL:
        _add(factors, "approval")
        total += _FACTOR_WEIGHTS["approval"]

    op = (operation or "").lower()
    if op in _FACTOR_WEIGHTS:
        _add(factors, op)
        total += _FACTOR_WEIGHTS[op]

    for flag in dangerous_flags or []:
        key = str(flag)
        if key in _FACTOR_WEIGHTS:
            _add(factors, key)
            total += _FACTOR_WEIGHTS[key]

    for result in results:
        rid = result.rule_id or ""
        if result.verdict == VERDICT_BLOCK:
            if rid in {"delete_without_where", "update_without_where", "full_table_write"}:
                _add(factors, "missing_where")
                total += _FACTOR_WEIGHTS["missing_where"]
            elif rid == "cartesian_join":
                _add(factors, "cartesian_join")
                total += _FACTOR_WEIGHTS["cartesian_join"]
            elif rid in {"schema_hallucination", "schema_mismatch"}:
                if "unknown" in (result.reason or "").lower() or rid == "schema_hallucination":
                    _add(factors, "schema_hallucination")
                    total += _FACTOR_WEIGHTS["schema_hallucination"]
            elif rid == "table_permission":
                _add(factors, "permission_denied")
                total += _FACTOR_WEIGHTS["permission_denied"]
            elif rid == "pii_column":
                _add(factors, "pii")
                total += _FACTOR_WEIGHTS["pii"]
            elif rid == "restricted_column":
                _add(factors, "restricted")
                total += _FACTOR_WEIGHTS["restricted"]
            elif rid == "expired_partition":
                _add(factors, "expired_partition")
                total += _FACTOR_WEIGHTS["expired_partition"]
            elif rid == "blast_radius_exceeded":
                _add(factors, "blast_radius")
                total += _FACTOR_WEIGHTS["blast_radius"]
            elif rid == "blast_radius_unknown":
                _add(factors, "blast_unknown")
                total += _FACTOR_WEIGHTS["blast_unknown"]
            elif rid == "environment_policy":
                _add(factors, "environment_block")
                total += _FACTOR_WEIGHTS["environment_block"]
            elif rid == "unsupported_sql":
                _add(factors, "unsupported_sql")
                total += _FACTOR_WEIGHTS["unsupported_sql"]
            elif rid in {"drop_table", "truncate_table", "alter_table"}:
                _add(factors, "ddl")
                total += _FACTOR_WEIGHTS["ddl"]
        elif result.verdict == VERDICT_APPROVAL:
            if "approval" not in factors:
                _add(factors, "approval")
                total += 15  # smaller bump when already counted

    if (
        explain_cost is not None
        and explain_cost_threshold is not None
        and explain_cost >= explain_cost_threshold
    ):
        _add(factors, "explain_cost_high")
        total += _FACTOR_WEIGHTS["explain_cost_high"]

    score = max(0, min(100, int(total)))
    # Ensure BLOCK is never scored trivially low
    if action == ACTION_BLOCK and score < 50:
        score = 50
    if action == ACTION_ALLOW and not factors:
        score = 5 if op in {"insert", "update", "delete"} else 0
    return score, factors


def qualitative_from_score(score: int) -> str:
    if score >= 70:
        return RISK_CRITICAL
    if score >= 35:
        return RISK_MEDIUM
    return "low"


def attach_explain_evidence(
    evidence: dict[str, Any],
    *,
    cost: float | None,
    plan: str | None,
    skipped: str | None,
) -> dict[str, Any]:
    blob: dict[str, Any] = dict(evidence)
    explain: dict[str, Any] = {}
    if cost is not None:
        explain["cost"] = cost
    if plan is not None:
        explain["plan"] = plan
    if skipped is not None:
        explain["skipped"] = skipped
    if explain:
        blob["explain"] = explain
    return blob
