"""Policy-driven table/operation permissions (GameStream-style allowlists)."""

from __future__ import annotations

from write_gate.decision import RULE_PERMISSION, GuardResult

NAME = "permissions"


def check_permissions(ctx) -> GuardResult:
    parsed = ctx.parsed
    if parsed.statement is None or parsed.error:
        return GuardResult.pass_(NAME)

    policy = ctx.policy
    perms = getattr(policy, "table_permissions", None) or {}
    # No permissions map configured → pass (environment / schema still apply).
    if not perms and not getattr(policy, "permissions_enforced", False):
        return GuardResult.pass_(NAME)

    operation = parsed.operation if parsed.operation != "unknown" else "ddl"
    tables = list(getattr(parsed, "tables_referenced", None) or [])
    if parsed.table and parsed.table not in tables:
        tables.insert(0, parsed.table)
    if not tables:
        # DDL without parseable table still subject to default deny when enforced
        if getattr(policy, "permissions_enforced", False) and operation != "select":
            return GuardResult.block(
                NAME,
                RULE_PERMISSION,
                f"{operation.upper()} denied: no target table resolved under permissions policy",
                evidence={"operation": operation, "tables": []},
            )
        return GuardResult.pass_(NAME)

    default_ops = getattr(policy, "default_table_ops", None)
    for table in tables:
        allowed = perms.get(table)
        if allowed is None:
            if getattr(policy, "allow_unknown_tables", False):
                continue
            if not perms and default_ops is None:
                continue
            # Enforced catalog: unknown table relative to permissions map
            if getattr(policy, "permissions_enforced", False) or perms:
                return GuardResult.block(
                    NAME,
                    RULE_PERMISSION,
                    (
                        f"Table {table} is not in the permissions allowlist; "
                        f"{operation.upper()} denied (GameStream-style policy)"
                    ),
                    evidence={
                        "table": table,
                        "operation": operation,
                        "allowed_tables": sorted(perms.keys()),
                    },
                )
            continue
        ops = {str(o).lower() for o in allowed}
        if operation not in ops and "*" not in ops and "all" not in ops:
            return GuardResult.block(
                NAME,
                RULE_PERMISSION,
                (
                    f"{operation.upper()} on {table} denied by table permissions "
                    f"(allowed: {sorted(ops)})"
                ),
                evidence={
                    "table": table,
                    "operation": operation,
                    "allowed_ops": sorted(ops),
                },
            )
    return GuardResult.pass_(
        NAME,
        evidence={"tables": tables, "operation": operation, "checked": True},
    )
