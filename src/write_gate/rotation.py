"""Size- and day-based rotation for JSONL audit / approvals mirror (v0.23).

SQLite approvals remain the source of truth — this only rotates append-only
JSONL files under ``.logs``. Rotation renames ``name.jsonl`` →
``name.jsonl.YYYYMMDD`` (daily) or ``name.jsonl.1`` (size), then opens a fresh
file. Never deletes the active SQLite ``*.sqlite`` store.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from write_gate.runtime import (
    DEFAULT_AUDIT_MAX_BYTES,
    RuntimeSettings,
    load_runtime_settings,
)

# Marker sibling: ``audit.jsonl.rotated_day`` stores YYYYMMDD of last daily cut.
_DAY_MARKER_SUFFIX = ".rotated_day"


def _utc_day() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d")


def _unique_dest(base: Path) -> Path:
    """Pick ``base`` or ``base.1`` / ``base.2`` … if the name already exists."""
    if not base.exists():
        return base
    n = 1
    while True:
        candidate = Path(f"{base}.{n}")
        if not candidate.exists():
            return candidate
        n += 1


def should_rotate(
    path: Path | str,
    *,
    settings: RuntimeSettings | None = None,
    max_bytes: int | None = None,
    rotate_daily: bool | None = None,
) -> bool:
    """True when size and/or daily policy says the active JSONL should roll."""
    dest = Path(path)
    if not dest.exists() or not dest.is_file():
        return False
    cfg = settings or load_runtime_settings()
    size_limit = max_bytes if max_bytes is not None else cfg.audit_max_bytes
    daily = cfg.audit_rotate_daily if rotate_daily is None else rotate_daily

    try:
        size = dest.stat().st_size
    except OSError:
        return False

    if size_limit and size_limit > 0 and size >= size_limit:
        return True

    if daily and size > 0:
        marker = Path(str(dest) + _DAY_MARKER_SUFFIX)
        today = _utc_day()
        if not marker.exists():
            try:
                marker.write_text(today, encoding="utf-8")
            except OSError:
                pass
            return False
        try:
            stamped = marker.read_text(encoding="utf-8").strip()
        except OSError:
            stamped = ""
        if stamped and stamped != today:
            return True
    return False


def rotate_file(path: Path | str, *, reason: str = "size") -> Path | None:
    """Rename active JSONL aside; return archived path or None if nothing done.

    Safe for audit.jsonl and approvals.jsonl mirrors. Callers must not point
    this at the SQLite ``approvals.sqlite`` SoT.
    """
    dest = Path(path)
    if not dest.exists() or not dest.is_file():
        return None
    if dest.suffix.lower() in {".sqlite", ".db", ".sqlite3"}:
        return None
    day = _utc_day()
    if reason == "daily":
        archived = _unique_dest(Path(f"{dest}.{day}"))
    else:
        archived = _unique_dest(Path(f"{dest}.1"))
    dest.replace(archived)
    marker = Path(str(dest) + _DAY_MARKER_SUFFIX)
    try:
        marker.write_text(day, encoding="utf-8")
    except OSError:
        pass
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not dest.exists():
        dest.write_text("", encoding="utf-8")
    return archived


def maybe_rotate(
    path: Path | str,
    *,
    settings: RuntimeSettings | None = None,
    max_bytes: int | None = None,
    rotate_daily: bool | None = None,
) -> Path | None:
    """Rotate when policy triggers; return archived path or None."""
    dest = Path(path)
    cfg = settings or load_runtime_settings()
    size_limit = max_bytes if max_bytes is not None else cfg.audit_max_bytes
    daily = cfg.audit_rotate_daily if rotate_daily is None else rotate_daily

    if not dest.exists():
        return None

    try:
        size = dest.stat().st_size
    except OSError:
        return None

    reason: str | None = None
    if size_limit and size_limit > 0 and size >= size_limit:
        reason = "size"
    elif daily and should_rotate(
        dest, settings=cfg, max_bytes=0, rotate_daily=True
    ):
        reason = "daily"

    if reason is None:
        return None
    return rotate_file(dest, reason=reason)


def rotation_settings_from_env() -> tuple[int, bool]:
    """Back-compat helper: (max_bytes, rotate_daily)."""
    cfg = load_runtime_settings()
    return cfg.audit_max_bytes or DEFAULT_AUDIT_MAX_BYTES, cfg.audit_rotate_daily
