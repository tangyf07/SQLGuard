"""v1.0.1: prompt timeout return + hard byte-limit enforcement."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from write_gate import __version__
from write_gate.approvals import STATUS_UNKNOWN, classify_execute_error
from write_gate.results import (
    ResultOversizeError,
    _row_bytes,
    materialize_result,
    oversize_mode,
)
from write_gate.timeouts import StatementTimeoutError, run_with_timeout

ROOT = Path(__file__).resolve().parents[1]


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def fetchall(self):
        return list(self._rows)

    def fetchmany(self, n):
        return list(self._rows[:n])


# --- Version -----------------------------------------------------------------


def test_version_is_101():
    # Pinned suite for the 1.0.1 fixes; current tree may be newer (1.1.x).
    parts = [int(x) for x in __version__.split(".")[:3]]
    assert parts >= [1, 0, 1], __version__
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "## [1.0.1]" in text


def test_changelog_has_101():
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "## [1.0.1]" in text
    assert "## [1.0.0]" in text  # do not drop 1.0.0 history


# --- Fix 1: timeout returns on time ------------------------------------------


def test_timeout_returns_promptly_not_worker_duration():
    """Regression: limit 0.05s must not wait ~0.5s for pool shutdown."""

    def slow():
        time.sleep(0.5)
        return "done"

    t0 = time.perf_counter()
    with pytest.raises(StatementTimeoutError) as ei:
        run_with_timeout(slow, timeout_sec=0.05, label="slow")
    elapsed = time.perf_counter() - t0

    assert ei.value.indeterminate is True
    assert ei.value.timeout_sec == 0.05
    # Must be far below the worker sleep class (0.5s); allow small scheduling slack.
    assert elapsed < 0.2, f"timeout returned too late: {elapsed:.3f}s"
    # Also sanity: should be near the deadline, not instantaneous false-positive.
    assert elapsed >= 0.04


def test_timeout_indeterminate_still_maps_unknown():
    exc = StatementTimeoutError("t", timeout_sec=0.05, indeterminate=True)
    assert classify_execute_error(exc) == STATUS_UNKNOWN


def test_timeout_docs_mention_wall_clock_and_cancel():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    trouble = (ROOT / "docs" / "troubleshooting.md").read_text(encoding="utf-8")
    blob = readme + "\n" + trouble
    assert "wall-clock" in blob.lower() or "wall clock" in blob.lower()
    assert "indeterminate" in blob.lower() or "unknown" in blob.lower()
    assert "cancel" in blob.lower() or "daemon" in blob.lower() or "worker" in blob.lower()


# --- Fix 2: hard byte limit --------------------------------------------------


def test_byte_limit_does_not_emit_huge_row_intact(monkeypatch):
    monkeypatch.delenv("SQL_WRITE_GATE_RESULT_OVERSIZE", raising=False)
    assert oversize_mode() == "truncate"
    huge = "x" * 100_000
    out = materialize_result(_FakeResult([[huge]]), byte_limit=100)
    assert out is not None
    assert out["truncated"] is True
    rows = out["rows"]
    # Must not return the 100000-byte row intact.
    raw = json.dumps(rows, ensure_ascii=False).encode("utf-8")
    assert len(raw) <= 100 + 32  # small slack for JSON brackets if measured on rows only
    assert _row_bytes(rows[0]) <= 100 if rows else True
    joined = "".join(str(c) for row in rows for c in row)
    assert "x" * 1000 not in joined


def test_byte_limit_payload_within_limit(monkeypatch):
    monkeypatch.delenv("SQL_WRITE_GATE_RESULT_OVERSIZE", raising=False)
    rows_in = [["a" * 40], ["b" * 40], ["c" * 40]]
    out = materialize_result(_FakeResult(rows_in), byte_limit=100, row_limit=100)
    assert out is not None
    total = sum(_row_bytes(r) for r in out["rows"])
    assert total <= 100
    assert out["truncated"] is True


def test_byte_limit_block_mode_raises_on_oversize_row(monkeypatch):
    monkeypatch.setenv("SQL_WRITE_GATE_RESULT_OVERSIZE", "block")
    assert oversize_mode() == "block"
    with pytest.raises(ResultOversizeError):
        materialize_result(_FakeResult([["z" * 100_000]]), byte_limit=100)


def test_byte_limit_docs():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    trouble = (ROOT / "docs" / "troubleshooting.md").read_text(encoding="utf-8")
    blob = readme + "\n" + trouble
    assert "byte" in blob.lower()
    assert "RESULT_BYTE_LIMIT" in blob or "result_byte" in blob.lower()
    assert "hard" in blob.lower() or "≤" in blob or "<=" in blob or "within" in blob.lower()
