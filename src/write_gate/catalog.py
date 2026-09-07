"""Load the static warehouse catalog (tables, PII columns, freshness cutoff)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from write_gate.paths import default_catalog_path


@dataclass(frozen=True)
class TableSpec:
    name: str
    writable: bool
    stale: bool
    partition_column: str | None
    columns: dict[str, str]
    allowed_write_columns: frozenset[str]
    pii_columns: frozenset[str]
    restricted_columns: frozenset[str]


@dataclass(frozen=True)
class Catalog:
    as_of_date: date
    freshness_days: int
    tables: dict[str, TableSpec]

    @property
    def cutoff_date(self) -> date:
        """Oldest partition still considered fresh (inclusive).

        as_of=2026-09-02, freshness_days=7 → cutoff=2026-08-26.
        dt < cutoff is expired ("older than 7 days").
        """
        return self.as_of_date - timedelta(days=self.freshness_days)

    def table(self, name: str) -> TableSpec | None:
        """Exact catalog key only — no silent bare fallback for ``schema.table``.

        Bare names (``orders``, ``ads_dau_di``) still match when that is the key.
        Qualified refs like ``other.orders`` must be present under that exact key.
        """
        return self.tables.get(name.lower())


def _table_spec(name: str, raw: dict[str, Any]) -> TableSpec:
    columns = {str(k).lower(): str(v).upper() for k, v in raw.get("columns", {}).items()}
    allowed = frozenset(c.lower() for c in raw.get("allowed_write_columns", []))
    pii = frozenset(c.lower() for c in raw.get("pii_columns", []))
    restricted = frozenset(c.lower() for c in raw.get("restricted_columns", []))
    # Conventional restricted names if the catalog lists those columns.
    for extra in ("id_card", "card_number"):
        if extra in columns:
            restricted = restricted | {extra}
    part = raw.get("partition_column")
    return TableSpec(
        name=name.lower(),
        writable=bool(raw.get("writable", True)),
        stale=bool(raw.get("stale", False)),
        partition_column=str(part).lower() if part else None,
        columns=columns,
        allowed_write_columns=allowed,
        pii_columns=pii,
        restricted_columns=restricted,
    )


def load_catalog(path: Path | None = None) -> Catalog:
    catalog_path = Path(path) if path else default_catalog_path()
    with catalog_path.open(encoding="utf-8") as fh:
        raw = json.load(fh)
    tables = {
        name.lower(): _table_spec(name, spec)
        for name, spec in raw.get("tables", {}).items()
    }
    return Catalog(
        as_of_date=date.fromisoformat(raw["as_of_date"]),
        freshness_days=int(raw["freshness_days"]),
        tables=tables,
    )
