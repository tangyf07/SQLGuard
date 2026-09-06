"""Result row/byte caps for SELECT / approve materialization (v0.23 / v1.0.1).

Default behavior: **truncate** oversized results and set ``truncated=true``.
This prevents unbounded MCP/CLI drag-down while keeping partial useful data.
Operators who prefer hard reject can set ``SQL_WRITE_GATE_RESULT_OVERSIZE=block``.

v1.0.1 **hard byte limit**: the final serialized rows payload must be ≤
``byte_limit``, or the gate raises ``ResultOversizeError`` (block mode /
unshrinkable row). A single oversized row is **never** returned intact.
"""

from __future__ import annotations

import json
import os
from typing import Any

from write_gate.runtime import (
    DEFAULT_RESULT_ROW_LIMIT,
    RuntimeSettings,
    load_runtime_settings,
)

ENV_RESULT_OVERSIZE = "SQL_WRITE_GATE_RESULT_OVERSIZE"  # truncate (default) | block


class ResultOversizeError(RuntimeError):
    """Raised when oversize mode is ``block`` and the result exceeds caps."""


def _serialize_cell(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    iso = getattr(value, "isoformat", None)
    if callable(iso):
        try:
            return iso()
        except Exception:
            pass
    return str(value)


def _row_bytes(row: list[Any]) -> int:
    try:
        return len(json.dumps(row, ensure_ascii=False, default=str).encode("utf-8"))
    except Exception:
        return sum(len(str(c)) for c in row)


def oversize_mode() -> str:
    raw = os.environ.get(ENV_RESULT_OVERSIZE, "truncate").strip().lower()
    if raw in {"block", "reject", "error"}:
        return "block"
    return "truncate"


def _shrink_row_to_byte_limit(row: list[Any], byte_limit: int) -> list[Any]:
    """Return a copy of ``row`` whose serialized size is ≤ ``byte_limit``.

    Prefer trimming the longest string cell; fall back to dropping trailing
    cells. Raises ``ResultOversizeError`` only if even a minimal placeholder
    cannot fit (pathological tiny limits).
    """
    if byte_limit <= 0:
        return list(row)
    out = [_serialize_cell(c) for c in row]
    if _row_bytes(out) <= byte_limit:
        return out

    # Iteratively trim longest string cells.
    for _ in range(64):
        if _row_bytes(out) <= byte_limit:
            return out
        str_idxs = [i for i, c in enumerate(out) if isinstance(c, str) and c]
        if not str_idxs:
            break
        idx = max(str_idxs, key=lambda i: len(out[i]))
        cur = out[idx]
        # Binary-search a prefix that fits when substituted.
        lo, hi = 0, len(cur)
        best = None
        while lo <= hi:
            mid = (lo + hi) // 2
            candidate = list(out)
            suffix = "…" if mid < len(cur) else ""
            candidate[idx] = cur[:mid] + suffix
            if _row_bytes(candidate) <= byte_limit:
                best = candidate
                lo = mid + 1
            else:
                hi = mid - 1
        if best is None:
            # Drop this cell entirely and continue.
            out[idx] = ""
            continue
        out = best
        # If we only emptied the cell, loop to trim another.
        if _row_bytes(out) <= byte_limit:
            return out

    # Drop trailing cells until it fits.
    while out and _row_bytes(out) > byte_limit:
        out = out[:-1]
    if _row_bytes(out) <= byte_limit:
        return out

    # Last resort: single empty placeholder list.
    if _row_bytes([]) <= byte_limit:
        return []
    raise ResultOversizeError(
        f"single row exceeds byte_limit={byte_limit} and cannot be shrunk"
    )


def materialize_result(
    result: Any,
    *,
    settings: RuntimeSettings | None = None,
    row_limit: int | None = None,
    byte_limit: int | None = None,
) -> dict[str, Any] | None:
    """Fetch rows with caps; return serializable payload.

    Always includes ``truncated`` (bool) when rows are present.
    Hard byte limit (v1.0.1): serialized rows stay within ``byte_limit``, or
    ``ResultOversizeError`` is raised in ``block`` mode / unshrinkable cases.
    """
    if result is None:
        return None
    if isinstance(result, dict) and ("rows" in result or "rowcount" in result):
        # Already materialized — still enforce caps.
        rows = list(result.get("rows") or [])
        cfg = settings or load_runtime_settings()
        lim = row_limit if row_limit is not None else cfg.result_row_limit
        blim = byte_limit if byte_limit is not None else cfg.result_byte_limit
        capped, truncated = _cap_rows(rows, row_limit=lim, byte_limit=blim)
        out: dict[str, Any] = {
            "rows": capped,
            "rowcount": result.get("rowcount", len(capped)),
            "truncated": truncated or bool(result.get("truncated")),
        }
        if truncated and oversize_mode() == "block":
            raise ResultOversizeError(
                f"result exceeds row/byte limit "
                f"(rows={lim or '∞'}, bytes={blim or '∞'})"
            )
        return out

    cfg = settings or load_runtime_settings()
    lim = row_limit if row_limit is not None else cfg.result_row_limit
    blim = byte_limit if byte_limit is not None else cfg.result_byte_limit
    # Prefer fetchmany when capped so we do not pull unbounded sets into memory.
    fetch_cap = lim if lim and lim > 0 else None
    fetched: list[Any] | None = None
    if fetch_cap is not None:
        fetchmany = getattr(result, "fetchmany", None)
        if callable(fetchmany):
            try:
                # Fetch one extra to detect truncation.
                fetched = list(fetchmany(fetch_cap + 1))
            except Exception:
                fetched = None
    if fetched is None:
        fetchall = getattr(result, "fetchall", None)
        if not callable(fetchall):
            return {"rowcount": getattr(result, "rowcount", None), "truncated": False}
        try:
            fetched = list(fetchall())
        except Exception:
            return {"rowcount": getattr(result, "rowcount", None), "truncated": False}

    material: list[list[Any]] = []
    for row in fetched:
        if isinstance(row, (list, tuple)):
            material.append([_serialize_cell(c) for c in row])
        else:
            material.append([_serialize_cell(row)])

    capped, truncated = _cap_rows(material, row_limit=lim, byte_limit=blim)
    if truncated and oversize_mode() == "block":
        raise ResultOversizeError(
            f"result exceeds row/byte limit "
            f"(rows={lim or '∞'}, bytes={blim or '∞'})"
        )
    rc = getattr(result, "rowcount", None)
    if not isinstance(rc, int) or rc < 0:
        rc = len(material) if not truncated else len(capped)
    return {"rows": capped, "rowcount": rc, "truncated": truncated}


def _cap_rows(
    rows: list[list[Any]],
    *,
    row_limit: int,
    byte_limit: int,
) -> tuple[list[list[Any]], bool]:
    truncated = False
    out = rows
    if row_limit and row_limit > 0 and len(out) > row_limit:
        out = out[:row_limit]
        truncated = True
    if byte_limit and byte_limit > 0:
        kept: list[list[Any]] = []
        total = 0
        for row in out:
            nb = _row_bytes(row)
            if kept and total + nb > byte_limit:
                truncated = True
                break
            if not kept and nb > byte_limit:
                # v1.0.1 hard limit: never emit the oversized row intact.
                if oversize_mode() == "block":
                    truncated = True
                    break
                shrunk = _shrink_row_to_byte_limit(row, byte_limit)
                kept.append(shrunk)
                truncated = True
                break
            kept.append(row)
            total += nb
        if len(kept) < len(out):
            truncated = True
        out = kept
        # Enforce invariant: serialized kept rows ≤ byte_limit.
        payload = 0
        enforced: list[list[Any]] = []
        for row in out:
            nb = _row_bytes(row)
            if enforced and payload + nb > byte_limit:
                truncated = True
                break
            if not enforced and nb > byte_limit:
                truncated = True
                if oversize_mode() == "block":
                    break
                row = _shrink_row_to_byte_limit(row, byte_limit)
                nb = _row_bytes(row)
                if nb > byte_limit:
                    raise ResultOversizeError(
                        f"result exceeds byte_limit={byte_limit}"
                    )
            enforced.append(row)
            payload += nb
        out = enforced
    return out, truncated


def resolve_row_limit(settings: RuntimeSettings | None = None) -> int:
    cfg = settings or load_runtime_settings()
    if cfg.result_row_limit > 0:
        return cfg.result_row_limit
    # Fall back to legacy MCP default when limit disabled (0).
    return DEFAULT_RESULT_ROW_LIMIT
