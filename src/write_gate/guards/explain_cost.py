"""Optional EXPLAIN cost guard. Skips cleanly when no connection (offline OK)."""

from __future__ import annotations

from write_gate.decision import RULE_EXPLAIN_COST, RISK_MEDIUM, GuardResult
from write_gate.explain import estimate_cost

NAME = "explain_cost"


def check_explain_cost(ctx) -> GuardResult:
    parsed = ctx.parsed
    if parsed.statement is None or parsed.error:
        return GuardResult.pass_(NAME)

    enabled = bool(getattr(ctx.policy, "enable_explain", False))
    threshold = getattr(ctx.policy, "explain_cost_threshold", None)
    if not enabled and threshold is None:
        return GuardResult.pass_(
            NAME,
            evidence={"skipped": True, "reason": "explain disabled / no threshold"},
        )
    if threshold is None:
        # enabled but no threshold → collect evidence only
        threshold = float("inf")

    conn = getattr(ctx, "conn", None)
    cost, plan, skipped = estimate_cost(conn, ctx.sql, backend=getattr(ctx, "dialect", "duckdb"))
    evidence = {
        "threshold": threshold,
        "cost": cost,
        "skipped": skipped,
    }
    if plan is not None:
        evidence["plan_preview"] = plan[:500]
    if skipped or cost is None:
        return GuardResult.pass_(NAME, evidence=evidence)
    if float(cost) >= float(threshold):
        return GuardResult.block(
            NAME,
            RULE_EXPLAIN_COST,
            (
                f"EXPLAIN cost {cost} exceeds policy threshold {threshold}; "
                "blocked (optional cost guard)"
            ),
            risk=RISK_MEDIUM,
            evidence=evidence,
        )
    return GuardResult.pass_(NAME, evidence=evidence)
