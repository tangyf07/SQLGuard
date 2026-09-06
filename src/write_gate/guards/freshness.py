"""Freshness guard: expired partitions and stale/non-writable tables."""

from __future__ import annotations

from datetime import date

from write_gate.decision import RULE_EXPIRED, RULE_SCHEMA, RISK_MEDIUM, GuardResult
from write_gate.parser import (
    expired_partition_touch,
    partition_dates_from_assignments,
    partition_dates_from_insert,
)

NAME = "freshness"


def check_freshness(ctx) -> GuardResult:
    parsed = ctx.parsed
    if parsed.statement is None or parsed.error:
        return GuardResult.pass_(NAME)
    if parsed.operation not in {"insert", "update", "delete"}:
        return GuardResult.pass_(NAME)

    table_name = parsed.table
    if not table_name:
        return GuardResult.pass_(NAME)
    spec = ctx.catalog.table(table_name)
    if spec is None:
        return GuardResult.pass_(NAME)

    if spec.stale or not spec.writable:
        return GuardResult.block(
            NAME,
            RULE_EXPIRED,
            f"表 {spec.name} 已标记为 stale/不可写，拒绝全部写入",
            risk=RISK_MEDIUM,
            evidence={"table": spec.name, "stale": spec.stale, "writable": spec.writable},
        )

    part = spec.partition_column
    if not part:
        return GuardResult.pass_(NAME)

    cutoff = ctx.catalog.cutoff_date
    dates: list[date | None] = []

    if parsed.operation == "insert":
        rows = parsed.insert_rows or []
        cols = (
            list(getattr(parsed, "insert_columns", None) or [])
            or list(parsed.columns)
            or list(parsed.write_columns)
        )
        dates.extend(partition_dates_from_insert(cols, rows, part))
        # UPSERT: ON CONFLICT DO UPDATE SET may write partition cols — do not
        # return early after INSERT VALUES dates alone.
        dates.extend(partition_dates_from_assignments(parsed.assignments, part))
        return _evaluate_dates(
            spec,
            ctx.catalog,
            dates,
            missing_ok=False,
            missing_message=f"INSERT 必须显式写出分区列 {part}",
        )

    # Range-aware WHERE: AND/OR/NOT + < / <= / > / >= / BETWEEN / = / IN.
    touched = expired_partition_touch(parsed.where, part, cutoff)
    if touched is not None:
        dates.append(touched)

    # Writing a new expired partition date via UPDATE SET dt = ...
    if parsed.operation == "update":
        dates.extend(partition_dates_from_assignments(parsed.assignments, part))

    # UPDATE/DELETE: if WHERE can touch an expired partition, block.
    # If WHERE exists but does not mention the partition, let blast_radius handle scope.
    return _evaluate_dates(
        spec,
        ctx.catalog,
        dates,
        missing_ok=True,
        missing_message=(
            f"{parsed.operation.upper()} 必须在 WHERE 中约束分区列 {part}，避免误写过期分区"
        ),
    )


def _evaluate_dates(
    spec,
    catalog,
    partition_dates: list[date | None],
    *,
    missing_ok: bool,
    missing_message: str,
) -> GuardResult:
    present = [d for d in partition_dates if d is not None]
    if not present and not missing_ok:
        return GuardResult.block(
            NAME,
            RULE_SCHEMA,
            missing_message,
            risk=RISK_MEDIUM,
            evidence={"partition_column": spec.partition_column},
        )
    cutoff = catalog.cutoff_date
    expired = [d for d in present if d < cutoff]
    if expired:
        worst = min(expired)
        shown = worst.isoformat() if worst.year > 1 else f"(range before {cutoff.isoformat()})"
        return GuardResult.block(
            NAME,
            RULE_EXPIRED,
            (
                f"分区 {spec.partition_column}={shown} 早于新鲜度截止日期 "
                f"{cutoff.isoformat()}（as_of={catalog.as_of_date.isoformat()}, "
                f"freshness_days={catalog.freshness_days}），拒绝写入"
            ),
            risk=RISK_MEDIUM,
            evidence={
                "partition_column": spec.partition_column,
                "partition_value": shown,
                "cutoff": cutoff.isoformat(),
            },
        )
    return GuardResult.pass_(NAME)
