"""Windows support policy: flock fail-closed; SQLite drive-letter paths."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from write_gate.adapters.sqlite import _parse_sqlite_path
from write_gate.approvals import (
    ApprovalError,
    _FLOCK_REQUIRED_MSG,
    _file_lock,
    _import_fcntl,
    claim_for_execute,
    enqueue_approval,
)
from write_gate.decision import ACTION_APPROVAL, Decision


def _decision(sql: str = "SELECT 1") -> Decision:
    return Decision(
        action=ACTION_APPROVAL,
        risk="medium",
        rule_id="environment_policy",
        reason="needs approval",
        sql=sql,
        operation="select",
    )


def test_import_fcntl_fail_closed_when_missing():
    """Simulate non-Unix: ImportError → ApprovalError (never silent pass)."""
    import builtins

    real_import = builtins.__import__

    def _no_fcntl(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "fcntl" or (isinstance(name, str) and name.startswith("fcntl.")):
            raise ImportError("simulated missing fcntl (Windows)")
        return real_import(name, globals, locals, fromlist, level)

    saved = sys.modules.pop("fcntl", None)
    try:
        with patch("builtins.__import__", _no_fcntl):
            with pytest.raises(ApprovalError, match="fcntl.flock"):
                _import_fcntl()
    finally:
        if saved is not None:
            sys.modules["fcntl"] = saved


def test_flock_unavailable_fail_closed_on_enqueue(tmp_path):
    path = tmp_path / "approvals.jsonl"
    with patch(
        "write_gate.approvals._import_fcntl",
        side_effect=ApprovalError(_FLOCK_REQUIRED_MSG),
    ):
        with pytest.raises(ApprovalError, match="fcntl.flock"):
            enqueue_approval(sql="SELECT 1", decision=_decision(), path=path)
    assert not path.exists() or path.read_text(encoding="utf-8").strip() == ""


def test_flock_unavailable_fail_closed_on_claim(tmp_path):
    path = tmp_path / "approvals.jsonl"
    rec = enqueue_approval(sql="SELECT 1", decision=_decision(), path=path)
    with patch(
        "write_gate.approvals._import_fcntl",
        side_effect=ApprovalError(_FLOCK_REQUIRED_MSG),
    ):
        with pytest.raises(ApprovalError, match="fcntl.flock"):
            claim_for_execute(rec.id, path=path)


def test_file_lock_oserror_fail_closed(tmp_path):
    path = tmp_path / "approvals.jsonl"

    class Boom:
        LOCK_EX = 2
        LOCK_UN = 8

        @staticmethod
        def flock(*_a, **_k):
            raise OSError("flock denied")

    with patch("write_gate.approvals._import_fcntl", return_value=Boom()):
        with pytest.raises(ApprovalError, match="flock failed|refusing"):
            with _file_lock(path):
                pass


@pytest.mark.parametrize(
    "url,expected",
    [
        ("sqlite:////tmp/x.db", "/tmp/x.db"),
        ("sqlite:///C:/temp/x.db", "C:/temp/x.db"),
        ("sqlite:////C:/temp/x.db", "C:/temp/x.db"),
        ("sqlite+aiosqlite:///D:/data/wg.db", "D:/data/wg.db"),
        ("sqlite:///:memory:", ":memory:"),
    ],
)
def test_sqlite_path_windows_and_unix(url, expected):
    assert _parse_sqlite_path(url) == expected


def test_sqlite_live_absolute_path_portable(tmp_path):
    """Absolute path URL works on Unix and Windows (no hard-coded ////tmp)."""
    abs_path = (tmp_path / "live.db").resolve()
    as_posix = abs_path.as_posix()
    url = f"sqlite:///{as_posix}"
    from write_gate.adapters import sqlite as sqlite_mod
    from write_gate.adapters.sqlite import ORDERS_DDL
    from write_gate.config import demo_policy
    from write_gate.wrapper import WriteGate

    parsed = _parse_sqlite_path(url)
    assert Path(parsed).resolve() == abs_path

    raw = sqlite_mod.connect(url)
    raw.execute(ORDERS_DDL)
    raw.close()

    gate = WriteGate(
        database=url,
        policy=demo_policy(),
        audit_path=tmp_path / "audit.jsonl",
    )
    ev, result = gate.execute(
        "INSERT INTO orders (order_id, user_id, amount, dt, status) "
        "VALUES (900001, 42, 18.50, '2026-09-01', 'paid')"
    )
    assert ev.action == "ALLOW"
    assert result is not None
