"""AST pattern guard: cartesian / missing-predicate JOINs.

Missing WHERE / tautology WHERE on UPDATE/DELETE are handled by the
destructive guard after ``parser`` clears ``has_where`` for tautologies.
"""

from __future__ import annotations

from write_gate.decision import RULE_CARTESIAN, GuardResult

NAME = "ast_patterns"


def check_ast_patterns(ctx) -> GuardResult:
    parsed = ctx.parsed
    if parsed.statement is None or parsed.error:
        return GuardResult.pass_(NAME)

    findings = getattr(parsed, "findings", None)
    evidence = findings.to_evidence() if findings is not None else {}

    if findings is not None and findings.cartesian_joins:
        tables = [j.right_table or "?" for j in findings.cartesian_joins]
        kinds = sorted({j.kind for j in findings.cartesian_joins})
        return GuardResult.block(
            NAME,
            RULE_CARTESIAN,
            (
                "Dangerous JOIN without predicates "
                f"(cartesian / {', '.join(kinds)}) involving {tables}; "
                "blocked by AST analysis"
            ),
            evidence=evidence,
        )

    return GuardResult.pass_(NAME, evidence=evidence)
