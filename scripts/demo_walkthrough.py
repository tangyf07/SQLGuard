#!/usr/bin/env python3
"""CLI walkthrough: check / hook / mcp / proxy / approve / audit.

Invoked from `make demo` after the three DuckDB write cases. Unexpected
BLOCK/ALLOW/pending verdicts exit non-zero. Approve uses an isolated
warehouse copy so the demo warehouse is not polluted.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from write_gate.mcp_tools import query_sql, write_sql  # noqa: E402
from write_gate.paths import DB_PATH, EXAMPLES_POLICY_PATH  # noqa: E402

DELETE_SQL = "DELETE FROM orders"
HOOK_COMMAND = "psql -c DELETE FROM orders"
APPROVE_SQL = (
    "INSERT INTO orders (order_id, user_id, amount, dt, status) "
    "VALUES (900091, 42, 18.50, '2026-09-01', 'paid')"
)
SELECT_APPROVED_SQL = "SELECT order_id FROM orders WHERE order_id = 900091"
AUDIT_HEADERS = ("TIME", "SOURCE", "OP", "TABLE", "VERDICT")


def _banner(title: str) -> None:
    line = "=" * 72
    print(line)
    print(title)
    print(line)


def _gate_cmd() -> list[str]:
    exe = ROOT / ".venv" / "bin" / "sql-write-gate"
    if exe.is_file():
        return [str(exe)]
    return [sys.executable, "-m", "write_gate"]


def _fmt_cmd(argv: list[str]) -> str:
    display = [Path(argv[0]).name, *argv[1:]]
    parts: list[str] = []
    for a in display:
        if any(ch in a for ch in " '"):
            parts.append('"' + a.replace('"', '\"') + '"')
        else:
            parts.append(a)
    return ' '.join(parts)


def _run(argv: list[str], *, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    print("$ " + _fmt_cmd(argv))
    proc = subprocess.run(
        argv,
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if proc.stdout:
        print(proc.stdout, end="" if proc.stdout.endswith("\n") else "\n")
    if proc.stderr:
        print(proc.stderr, end="" if proc.stderr.endswith("\n") else "\n")
    print(f"exit {proc.returncode}")
    return proc


def _combined(proc: subprocess.CompletedProcess[str]) -> str:
    return (proc.stdout or "") + (proc.stderr or "")


def _fail(msg: str) -> int:
    sys.stdout.flush()
    print(f"WALKTHROUGH FAIL: {msg}")
    print(f"WALKTHROUGH FAIL: {msg}", file=sys.stderr)
    return 1


def _copy_warehouse(dest_dir: Path) -> Path:
    src = DB_PATH
    if not src.is_file():
        raise FileNotFoundError(f"demo warehouse missing: {src} (run make seed)")
    dest = dest_dir / "warehouse.duckdb"
    shutil.copy2(src, dest)
    wal = src.with_suffix(".duckdb.wal")
    if wal.is_file():
        shutil.copy2(wal, dest.with_suffix(".duckdb.wal"))
    return dest


def _count_order(db_path: Path, order_id: int) -> int:
    if not db_path.is_file():
        return 0
    import duckdb

    conn = duckdb.connect(str(db_path), read_only=True)
    try:
        n = conn.execute(
            "SELECT COUNT(*) FROM orders WHERE order_id = ?", [order_id]
        ).fetchone()[0]
        return int(n)
    finally:
        conn.close()


def _ensure_demo_approval_trust() -> None:
    """Trusted-executor token for approve/resolve in this offline demo."""
    key = ROOT / ".logs" / "approval.key"
    key.parent.mkdir(parents=True, exist_ok=True)
    secret = "sqlguard-demo-approval-secret"
    if not key.is_file():
        key.write_text(secret + "\n", encoding="utf-8")
        try:
            key.chmod(0o600)
        except OSError:
            pass
    else:
        secret = key.read_text(encoding="utf-8").strip() or secret
    os.environ["SQL_WRITE_GATE_APPROVAL_KEY_FILE"] = str(key)
    os.environ["SQL_WRITE_GATE_APPROVAL_TOKEN"] = secret


def main() -> int:
    os.chdir(ROOT)
    _ensure_demo_approval_trust()
    gate = _gate_cmd()
    print(f"walkthrough CLI: {gate[0]}")

    # 1. check DELETE -> BLOCK
    _banner("walkthrough 1 · check DELETE FROM orders")
    proc = _run(gate + ["check", DELETE_SQL])
    text = _combined(proc)
    if proc.returncode != 2 or "BLOCK" not in text:
        return _fail("check DELETE expected BLOCK exit 2")
    if "delete_without_where" not in text:
        return _fail("check DELETE expected rule delete_without_where")

    # 2. hook --command psql -c DELETE -> BLOCK exit 2
    _banner("walkthrough 2 · hook --command psql -c DELETE FROM orders")
    proc = _run(gate + ["hook", "--command", HOOK_COMMAND])
    text = _combined(proc)
    if proc.returncode != 2 or "BLOCK" not in text:
        return _fail("hook DELETE expected BLOCK exit 2")

    # 3. mcp: do not start hanging stdio
    _banner("walkthrough 3 · mcp write_sql DELETE / query_sql SELECT 1")
    try:
        help_proc = subprocess.run(
            gate + ["mcp", "--help"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=5,
        )
        help_text = (help_proc.stdout or "") + (help_proc.stderr or "")
        if help_text.strip():
            print(help_text, end="" if help_text.endswith("\n") else "\n")
    except (subprocess.TimeoutExpired, OSError) as exc:
        print(f"(mcp --help skipped: {exc})")

    blocked = write_sql(DELETE_SQL)
    allowed = query_sql("SELECT 1")
    print(blocked)
    print(allowed)
    if blocked.get("action") != "BLOCK":
        return _fail("mcp write_sql DELETE expected BLOCK")
    if allowed.get("action") != "ALLOW":
        return _fail("mcp query_sql SELECT 1 expected ALLOW")

    # 4. proxy DELETE -> BLOCK
    _banner("walkthrough 4 · proxy --database seed/warehouse.duckdb --sql DELETE")
    proc = _run(
        gate
        + [
            "proxy",
            "--database",
            str(DB_PATH),
            "--sql",
            DELETE_SQL,
        ]
    )
    text = _combined(proc)
    if proc.returncode != 2 or "BLOCK" not in text:
        return _fail("proxy DELETE expected BLOCK exit 2")

    # 5. approve on isolated warehouse copy
    _banner("walkthrough 5 · approve (isolated DuckDB copy, production policy)")
    with tempfile.TemporaryDirectory(prefix="swg-demo-approve-") as tmp_raw:
        tmp = Path(tmp_raw)
        isolated_db = _copy_warehouse(tmp)
        approvals = tmp / "approvals.jsonl"
        exec_argv = gate + [
            "exec",
            "--database",
            str(isolated_db),
            "--policy",
            str(EXAMPLES_POLICY_PATH),
            "--approvals",
            str(approvals),
            "--json",
            APPROVE_SQL,
        ]
        proc = _run(exec_argv)
        text = _combined(proc)
        if proc.returncode != 1:
            return _fail(f"production INSERT expected REQUIRE_APPROVAL exit 1, got {proc.returncode}")
        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return _fail("production INSERT --json was not valid JSON")
        if payload.get("action") != "REQUIRE_APPROVAL":
            return _fail(f"production INSERT expected REQUIRE_APPROVAL, got {payload.get('action')}")
        approval_id = payload.get("approval_id")
        if not approval_id:
            # human output fallback
            match = re.search(r"Approval id:\s*(\S+)", text)
            approval_id = match.group(1) if match else None
        if not approval_id:
            return _fail("production INSERT did not yield a pending approval id")
        print(f"pending id: {approval_id}")

        proc = _run(gate + ["approve", str(approval_id), "--approvals", str(approvals)])
        text = _combined(proc)
        if proc.returncode != 0 or "ALLOWED" not in text:
            return _fail("approve <id> expected ALLOWED exit 0")

        proc = _run(
            gate
            + [
                "exec",
                "--database",
                str(isolated_db),
                "--policy",
                str(EXAMPLES_POLICY_PATH),
                "--approvals",
                str(approvals),
                "--json",
                SELECT_APPROVED_SQL,
            ]
        )
        text = _combined(proc)
        if proc.returncode != 0:
            return _fail("SELECT after approve expected ALLOW exit 0")
        if "ALLOW" not in text:
            return _fail("SELECT after approve expected ALLOW")
        # CLI --json cannot fetch rows after the gate connection closes.
        # Confirm the approved INSERT on the isolated copy.
        n = _count_order(isolated_db, 900091)
        print(f"isolated warehouse order_id=900091 count={n}")
        if n != 1:
            return _fail("SELECT after approve did not find order_id=900091")
        print("SELECT found order_id=900091")

        # 6. audit table from the walkthrough log (default log written by 1–4)
        _banner("walkthrough 6 · audit --audit-path")
        default_audit = ROOT / ".logs" / "audit.jsonl"
        if not default_audit.is_file():
            return _fail(f"audit log missing: {default_audit}")
        proc = _run(
            gate
            + [
                "audit",
                "--audit-path",
                str(default_audit),
                "--limit",
                "20",
            ]
        )
        text = _combined(proc)
        if proc.returncode != 0:
            return _fail("audit expected exit 0")
        for header in AUDIT_HEADERS:
            if header not in text:
                return _fail(f"audit table missing header {header}")

        # isolated approve must not have written 900091 into the demo warehouse
        if _count_order(DB_PATH, 900091) != 0:
            return _fail("approve walkthrough polluted seed/warehouse.duckdb (order_id=900091)")

        if not approvals.is_file():
            return _fail("isolated approvals.jsonl was not written")

    print("demo: CLI walkthrough matched expected verdicts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
