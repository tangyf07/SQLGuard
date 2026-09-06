"""SQLite approval state machine (v0.21). JSONL kept as audit/export mirror.

Source of truth is a transactional SQLite table. Statuses:
  pending → executing → succeeded | failed | unknown  (+ rejected)

Single-host concurrency: fcntl.flock around mutations (fail closed if
unavailable) plus SQLite BEGIN IMMEDIATE for atomic pending→executing claim.
Not a distributed / multi-host lock.
"""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from write_gate.audit import database_config_id, redact_database_url
from write_gate.decision import Decision
from write_gate.paths import default_approvals_path, default_log_dir

STATUS_PENDING = "pending"
STATUS_EXECUTING = "executing"
STATUS_SUCCEEDED = "succeeded"
STATUS_FAILED = "failed"
STATUS_UNKNOWN = "unknown"
STATUS_REJECTED = "rejected"
# Back-compat alias: older releases used "approved" for terminal success.
STATUS_APPROVED = STATUS_SUCCEEDED

_TERMINAL_SUCCESS = frozenset({STATUS_SUCCEEDED, "approved"})
_ID_LEN = 12

# Default TTL for stuck executing → unknown (crash recovery).
_DEFAULT_EXECUTING_TTL_SEC = 120

_LOCK_NOTE = (
    "approvals use flock + SQLite BEGIN IMMEDIATE for single-host concurrency; "
    "not a distributed lock"
)
_FLOCK_REQUIRED_MSG = (
    "concurrent approval requires fcntl.flock (Unix); not available on this "
    "platform — refusing rather than silently degrading (see README support matrix)"
)


class ApprovalError(Exception):
    """Missing, not claimable, invalid approval, or flock unavailable."""


@dataclass
class ApprovalRecord:
    id: str
    status: str
    sql: str
    database: str | None = None  # redacted display only; never reconnect with ***
    database_config_id: str | None = None  # fingerprint for trusted credential binding
    db_path: str | None = None
    policy_path: str | None = None
    catalog_path: str | None = None
    created_at: str = ""
    updated_at: str = ""
    decision: dict[str, Any] = field(default_factory=dict)
    backend: str | None = None
    agent: str | None = None
    error_class: str | None = None
    outcome_note: str | None = None
    executing_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status,
            "sql": self.sql,
            "database": self.database,
            "database_config_id": self.database_config_id,
            "db_path": self.db_path,
            "policy_path": self.policy_path,
            "catalog_path": self.catalog_path,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "decision": self.decision,
            "backend": self.backend,
            "agent": self.agent,
            "error_class": self.error_class,
            "outcome_note": self.outcome_note,
            "executing_at": self.executing_at,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ApprovalRecord":
        decision = raw.get("decision")
        if not isinstance(decision, dict):
            decision = {}
        status = str(raw.get("status") or STATUS_PENDING)
        if status == "approved":
            status = STATUS_SUCCEEDED
        return cls(
            id=str(raw.get("id") or ""),
            status=status,
            sql=str(raw.get("sql") or ""),
            database=raw.get("database"),
            database_config_id=raw.get("database_config_id"),
            db_path=raw.get("db_path"),
            policy_path=raw.get("policy_path"),
            catalog_path=raw.get("catalog_path"),
            created_at=str(raw.get("created_at") or ""),
            updated_at=str(raw.get("updated_at") or ""),
            decision=decision,
            backend=raw.get("backend"),
            agent=raw.get("agent"),
            error_class=raw.get("error_class"),
            outcome_note=raw.get("outcome_note"),
            executing_at=raw.get("executing_at"),
        )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id() -> str:
    return uuid.uuid4().hex[:_ID_LEN]


def _path(path: Path | str | None = None) -> Path:
    """Logical approvals path (often ``*.jsonl``); SQLite is derived from it."""
    return Path(path) if path else default_approvals_path()


def db_path_for(path: Path | str | None = None) -> Path:
    """SQLite file used as the durable source of truth for ``path``."""
    p = _path(path)
    if p.suffix.lower() in {".sqlite", ".db", ".sqlite3"}:
        return p
    return p.with_suffix(".sqlite")


def jsonl_path_for(path: Path | str | None = None) -> Path:
    """JSONL export/mirror path (audit/compat)."""
    p = _path(path)
    if p.suffix.lower() == ".jsonl":
        return p
    if p.suffix.lower() in {".sqlite", ".db", ".sqlite3"}:
        return p.with_suffix(".jsonl")
    return p.with_suffix(p.suffix + ".jsonl") if p.suffix else Path(str(p) + ".jsonl")


def _lock_path(path: Path) -> Path:
    # Keep beside the logical --approvals path (e.g. approvals.jsonl.lock)
    # so existing tests and operators find the same lock file as v0.20.
    p = _path(path)
    return p.with_suffix(p.suffix + ".lock")


def executing_ttl_sec() -> float:
    raw = os.environ.get("SQL_WRITE_GATE_EXECUTING_TTL_SEC", "")
    if raw.strip():
        try:
            return max(1.0, float(raw))
        except ValueError:
            pass
    return float(_DEFAULT_EXECUTING_TTL_SEC)


def _import_fcntl():
    """Return the fcntl module or raise ApprovalError (fail closed)."""
    try:
        import fcntl
    except ImportError as exc:
        raise ApprovalError(_FLOCK_REQUIRED_MSG) from exc
    return fcntl


@contextmanager
def _file_lock(path: Path) -> Iterator[None]:
    """Exclusive flock for the critical section. Fail closed if unavailable."""
    fcntl = _import_fcntl()
    dest = _path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    lock_file = _lock_path(dest)
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    fh = lock_file.open("a+", encoding="utf-8")
    locked = False
    try:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            locked = True
        except OSError as exc:
            raise ApprovalError(
                "fcntl.flock failed; refusing concurrent approval rather than "
                "silently degrading"
            ) from exc
        if not lock_file.read_text(encoding="utf-8").strip():
            fh.write(_LOCK_NOTE + "\n")
            fh.flush()
        yield
    finally:
        if locked:
            try:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            except (OSError, ValueError):
                pass
        fh.close()


def _connect(db_file: Path) -> sqlite3.Connection:
    db_file.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_file), timeout=30.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    return conn


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS approvals (
            id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            sql TEXT NOT NULL,
            database TEXT,
            database_config_id TEXT,
            db_path TEXT,
            policy_path TEXT,
            catalog_path TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            decision_json TEXT NOT NULL DEFAULT '{}',
            backend TEXT,
            agent TEXT,
            error_class TEXT,
            outcome_note TEXT,
            executing_at TEXT
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status)"
    )


def _row_to_record(row: sqlite3.Row | dict[str, Any]) -> ApprovalRecord:
    if isinstance(row, sqlite3.Row):
        raw = dict(row)
    else:
        raw = dict(row)
    decision_raw = raw.pop("decision_json", None)
    if decision_raw is None and "decision" in raw:
        decision = raw.get("decision") or {}
    else:
        try:
            decision = json.loads(decision_raw or "{}")
        except (TypeError, json.JSONDecodeError):
            decision = {}
    if not isinstance(decision, dict):
        decision = {}
    status = str(raw.get("status") or STATUS_PENDING)
    if status == "approved":
        status = STATUS_SUCCEEDED
    return ApprovalRecord(
        id=str(raw.get("id") or ""),
        status=status,
        sql=str(raw.get("sql") or ""),
        database=raw.get("database"),
        database_config_id=raw.get("database_config_id"),
        db_path=raw.get("db_path"),
        policy_path=raw.get("policy_path"),
        catalog_path=raw.get("catalog_path"),
        created_at=str(raw.get("created_at") or ""),
        updated_at=str(raw.get("updated_at") or ""),
        decision=decision,
        backend=raw.get("backend"),
        agent=raw.get("agent"),
        error_class=raw.get("error_class"),
        outcome_note=raw.get("outcome_note"),
        executing_at=raw.get("executing_at"),
    )


def _insert_record(conn: sqlite3.Connection, rec: ApprovalRecord) -> None:
    conn.execute(
        """
        INSERT INTO approvals (
            id, status, sql, database, database_config_id, db_path,
            policy_path, catalog_path, created_at, updated_at, decision_json,
            backend, agent, error_class, outcome_note, executing_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            rec.id,
            rec.status,
            rec.sql,
            rec.database,
            rec.database_config_id,
            rec.db_path,
            rec.policy_path,
            rec.catalog_path,
            rec.created_at,
            rec.updated_at or rec.created_at,
            json.dumps(rec.decision, ensure_ascii=False),
            rec.backend,
            rec.agent,
            rec.error_class,
            rec.outcome_note,
            rec.executing_at,
        ),
    )


def _update_record(conn: sqlite3.Connection, rec: ApprovalRecord) -> None:
    conn.execute(
        """
        UPDATE approvals SET
            status=?, sql=?, database=?, database_config_id=?, db_path=?,
            policy_path=?, catalog_path=?, created_at=?, updated_at=?,
            decision_json=?, backend=?, agent=?, error_class=?,
            outcome_note=?, executing_at=?
        WHERE id=?
        """,
        (
            rec.status,
            rec.sql,
            rec.database,
            rec.database_config_id,
            rec.db_path,
            rec.policy_path,
            rec.catalog_path,
            rec.created_at,
            rec.updated_at,
            json.dumps(rec.decision, ensure_ascii=False),
            rec.backend,
            rec.agent,
            rec.error_class,
            rec.outcome_note,
            rec.executing_at,
            rec.id,
        ),
    )


def _fetch_one(conn: sqlite3.Connection, approval_id: str) -> ApprovalRecord | None:
    cur = conn.execute("SELECT * FROM approvals WHERE id = ?", (str(approval_id),))
    row = cur.fetchone()
    if row is None:
        return None
    return _row_to_record(row)


def _fetch_all(conn: sqlite3.Connection) -> list[ApprovalRecord]:
    cur = conn.execute("SELECT * FROM approvals ORDER BY created_at")
    return [_row_to_record(r) for r in cur.fetchall()]


def _load_jsonl_legacy(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    records: dict[str, dict[str, Any]] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(raw, dict):
            continue
        rec_id = str(raw.get("id") or "")
        if rec_id:
            records[rec_id] = raw
    return records


def _export_jsonl(path: Path, records: list[ApprovalRecord]) -> None:
    """Rewrite JSONL mirror for audit/compat (source of truth remains SQLite)."""
    from write_gate.rotation import maybe_rotate

    jpath = jsonl_path_for(path)
    jpath.parent.mkdir(parents=True, exist_ok=True)
    # Rotate oversized / daily mirror before rewrite; SQLite SoT untouched.
    maybe_rotate(jpath)
    tmp = jpath.with_suffix(jpath.suffix + ".tmp")
    body = "".join(
        json.dumps(rec.to_dict(), ensure_ascii=False) + "\n" for rec in records
    )
    tmp.write_text(body, encoding="utf-8")
    tmp.replace(jpath)


def _migrate_jsonl_if_needed(conn: sqlite3.Connection, path: Path) -> None:
    """One-shot import of legacy JSONL when SQLite table is empty."""
    cur = conn.execute("SELECT COUNT(*) FROM approvals")
    if int(cur.fetchone()[0]) > 0:
        return
    legacy = _load_jsonl_legacy(jsonl_path_for(path))
    if not legacy:
        return
    for raw in legacy.values():
        rec = ApprovalRecord.from_dict(raw)
        if not rec.id:
            continue
        if not rec.updated_at:
            rec.updated_at = rec.created_at or _now()
        _insert_record(conn, rec)


def _parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def _is_stale_executing(rec: ApprovalRecord, *, now: datetime | None = None) -> bool:
    if rec.status != STATUS_EXECUTING:
        return False
    started = _parse_iso(rec.executing_at) or _parse_iso(rec.updated_at)
    if started is None:
        return True
    if started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)
    current = now or datetime.now(timezone.utc)
    age = (current - started).total_seconds()
    return age >= executing_ttl_sec()


def _recover_stale_in_tx(conn: sqlite3.Connection) -> list[str]:
    """Mark stale executing rows as unknown. Caller must hold lock + tx."""
    changed: list[str] = []
    now = datetime.now(timezone.utc)
    for rec in _fetch_all(conn):
        if _is_stale_executing(rec, now=now):
            rec.status = STATUS_UNKNOWN
            rec.updated_at = _now()
            rec.outcome_note = (
                (rec.outcome_note + "; " if rec.outcome_note else "")
                + "executing TTL expired → unknown (crash recovery; not auto-retried)"
            )
            rec.executing_at = None
            _update_record(conn, rec)
            changed.append(rec.id)
    return changed


def is_terminal_success(status: str) -> bool:
    return status in _TERMINAL_SUCCESS or status == STATUS_SUCCEEDED


def classify_execute_error(exc: BaseException) -> str:
    """Map an execute exception to failed vs unknown.

    failed = determined not committed / never sent with known error.
    unknown = timeout/disconnect/indeterminate after the attempt may have
    reached the DB.
    """
    # v0.23 StatementTimeoutError: honor explicit indeterminate flag.
    indeterminate = getattr(exc, "indeterminate", None)
    if indeterminate is False:
        return STATUS_FAILED
    if indeterminate is True:
        return STATUS_UNKNOWN
    name = type(exc).__name__.lower()
    msg = str(exc).lower()
    indeterminate_tokens = (
        "timeout",
        "timed out",
        "timedout",
        "disconnect",
        "disconnected",
        "connection reset",
        "connection aborted",
        "broken pipe",
        "server closed",
        "gone away",
        "lost connection",
        "network",
        "ssl",
        "eof",
        "interfaceerror",
    )
    if "timeout" in name or "interface" in name:
        return STATUS_UNKNOWN
    if any(tok in msg for tok in indeterminate_tokens):
        return STATUS_UNKNOWN
    if "operationalerror" in name and any(
        tok in msg for tok in ("connection", "timeout", "closed", "gone")
    ):
        return STATUS_UNKNOWN
    return STATUS_FAILED


@contextmanager
def _locked_db(path: Path | str | None = None) -> Iterator[tuple[Path, sqlite3.Connection]]:
    dest = _path(path)
    with _file_lock(dest):
        db_file = db_path_for(dest)
        conn = _connect(db_file)
        try:
            _ensure_schema(conn)
            conn.execute("BEGIN IMMEDIATE")
            _migrate_jsonl_if_needed(conn, dest)
            yield dest, conn
            conn.execute("COMMIT")
            _export_jsonl(dest, _fetch_all(conn))
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()


def get_approval(approval_id: str, path: Path | str | None = None) -> ApprovalRecord | None:
    with _locked_db(path) as (_dest, conn):
        _recover_stale_in_tx(conn)
        return _fetch_one(conn, approval_id)


def list_pending(path: Path | str | None = None) -> list[ApprovalRecord]:
    with _locked_db(path) as (_dest, conn):
        _recover_stale_in_tx(conn)
        pending: list[ApprovalRecord] = []
        for rec in _fetch_all(conn):
            if rec.status == STATUS_PENDING and rec.id:
                pending.append(rec)
        pending.sort(key=lambda r: r.created_at)
        return pending


def list_approvals(
    path: Path | str | None = None,
    *,
    statuses: set[str] | None = None,
) -> list[ApprovalRecord]:
    with _locked_db(path) as (_dest, conn):
        _recover_stale_in_tx(conn)
        rows = _fetch_all(conn)
        if statuses is not None:
            rows = [r for r in rows if r.status in statuses]
        return rows


def enqueue_approval(
    *,
    sql: str,
    decision: Decision,
    database: str | None = None,
    db_path: str | None = None,
    policy_path: str | None = None,
    catalog_path: str | None = None,
    path: Path | str | None = None,
    backend: str | None = None,
    agent: str | None = None,
) -> ApprovalRecord:
    with _locked_db(path) as (_dest, conn):
        _recover_stale_in_tx(conn)
        existing_ids = {r.id for r in _fetch_all(conn)}
        approval_id = _new_id()
        while approval_id in existing_ids:
            approval_id = _new_id()
        redacted = redact_database_url(database) if database else None
        now = _now()
        rec = ApprovalRecord(
            id=approval_id,
            status=STATUS_PENDING,
            sql=sql,
            database=redacted,
            database_config_id=database_config_id(database) if database else None,
            db_path=db_path,
            policy_path=str(policy_path) if policy_path else None,
            catalog_path=str(catalog_path) if catalog_path else None,
            created_at=now,
            updated_at=now,
            decision=decision.to_dict(),
            backend=backend,
            agent=agent,
        )
        rec.decision = {**rec.decision, "approval_id": approval_id}
        _insert_record(conn, rec)
    return rec


def set_status(
    approval_id: str,
    status: str,
    path: Path | str | None = None,
    *,
    allow_idempotent_approved: bool = False,
    from_statuses: set[str] | None = None,
    error_class: str | None = None,
    outcome_note: str | None = None,
) -> ApprovalRecord:
    allowed = {
        STATUS_PENDING,
        STATUS_SUCCEEDED,
        STATUS_REJECTED,
        STATUS_EXECUTING,
        STATUS_FAILED,
        STATUS_UNKNOWN,
        "approved",  # accept legacy write targets → normalize
    }
    if status not in allowed:
        raise ApprovalError(f"invalid approval status: {status}")
    if status == "approved":
        status = STATUS_SUCCEEDED
    with _locked_db(path) as (_dest, conn):
        _recover_stale_in_tx(conn)
        rec = _fetch_one(conn, approval_id)
        if not rec:
            raise ApprovalError(f"approval not found: {approval_id}")
        if (
            allow_idempotent_approved
            and is_terminal_success(rec.status)
            and is_terminal_success(status)
        ):
            return rec
        expected = from_statuses if from_statuses is not None else {STATUS_PENDING}
        # Normalize legacy "approved" in expected set.
        expected = {
            STATUS_SUCCEEDED if s == "approved" else s for s in expected
        }
        if rec.status not in expected:
            raise ApprovalError(f"approval not pending: {approval_id}")
        rec.status = status
        rec.updated_at = _now()
        if status == STATUS_EXECUTING:
            rec.executing_at = rec.updated_at
        elif status != STATUS_EXECUTING:
            if status in {
                STATUS_SUCCEEDED,
                STATUS_FAILED,
                STATUS_UNKNOWN,
                STATUS_REJECTED,
                STATUS_PENDING,
            }:
                rec.executing_at = None
        if error_class is not None:
            rec.error_class = error_class
        if outcome_note is not None:
            rec.outcome_note = outcome_note
        _update_record(conn, rec)
    return rec


def claim_for_execute(
    approval_id: str,
    path: Path | str | None = None,
    *,
    recover_failed: bool = True,
    allow_unknown_retry: bool = False,
) -> ApprovalRecord:
    """Atomically claim claimable → ``executing`` under flock + BEGIN IMMEDIATE.

    Claimable by default: ``pending`` (and ``failed`` when recover_failed).
    ``unknown`` is NEVER claimed unless ``allow_unknown_retry`` is set.
    Stuck ``executing`` past TTL becomes ``unknown`` (not silently re-claimed).
    Only the claimer may execute.
    """
    with _locked_db(path) as (_dest, conn):
        _recover_stale_in_tx(conn)
        rec = _fetch_one(conn, approval_id)
        if not rec:
            raise ApprovalError(f"approval not found: {approval_id}")
        if is_terminal_success(rec.status):
            raise ApprovalError(f"approval not pending: {approval_id}")
        if rec.status == STATUS_UNKNOWN and not allow_unknown_retry:
            raise ApprovalError(
                f"approval outcome unknown: {approval_id} — verify the target DB, "
                "then `resolve --as succeeded|failed|rejected` or "
                "`approve --allow-unknown-retry` (never auto-retried)"
            )
        if rec.status == STATUS_EXECUTING:
            raise ApprovalError(f"approval not pending: {approval_id}")
        claimable = {STATUS_PENDING}
        if recover_failed:
            claimable.add(STATUS_FAILED)
        if allow_unknown_retry:
            claimable.add(STATUS_UNKNOWN)
        if rec.status not in claimable:
            raise ApprovalError(f"approval not pending: {approval_id}")
        now = _now()
        rec.status = STATUS_EXECUTING
        rec.updated_at = now
        rec.executing_at = now
        rec.error_class = None
        if allow_unknown_retry and rec.outcome_note:
            rec.outcome_note = (
                rec.outcome_note + "; explicit --allow-unknown-retry reclaim"
            )
        _update_record(conn, rec)
    return rec


def mark_succeeded(approval_id: str, path: Path | str | None = None) -> ApprovalRecord:
    """Mark executing (or pending for back-compat) as succeeded; idempotent."""
    with _locked_db(path) as (_dest, conn):
        _recover_stale_in_tx(conn)
        rec = _fetch_one(conn, approval_id)
        if not rec:
            raise ApprovalError(f"approval not found: {approval_id}")
        if is_terminal_success(rec.status):
            if rec.status != STATUS_SUCCEEDED:
                rec.status = STATUS_SUCCEEDED
                rec.updated_at = _now()
                _update_record(conn, rec)
            return rec
        if rec.status not in {STATUS_EXECUTING, STATUS_PENDING}:
            raise ApprovalError(f"approval not pending: {approval_id}")
        rec.status = STATUS_SUCCEEDED
        rec.updated_at = _now()
        rec.executing_at = None
        _update_record(conn, rec)
    return rec


def mark_approved(approval_id: str, path: Path | str | None = None) -> ApprovalRecord:
    """Back-compat alias for :func:`mark_succeeded`."""
    return mark_succeeded(approval_id, path=path)


def mark_failed(
    approval_id: str,
    path: Path | str | None = None,
    *,
    error_class: str | None = None,
    outcome_note: str | None = None,
) -> ApprovalRecord:
    """Mark executing claim as failed (known not committed / never sent)."""
    return set_status(
        approval_id,
        STATUS_FAILED,
        path=path,
        from_statuses={STATUS_EXECUTING, STATUS_PENDING},
        error_class=error_class,
        outcome_note=outcome_note,
    )


def mark_unknown(
    approval_id: str,
    path: Path | str | None = None,
    *,
    error_class: str | None = None,
    outcome_note: str | None = None,
) -> ApprovalRecord:
    """Mark executing claim as unknown (outcome indeterminate — do not auto-retry)."""
    return set_status(
        approval_id,
        STATUS_UNKNOWN,
        path=path,
        from_statuses={STATUS_EXECUTING, STATUS_PENDING},
        error_class=error_class,
        outcome_note=outcome_note
        or "execute outcome indeterminate (timeout/disconnect/mark failure)",
    )


def release_claim(
    approval_id: str,
    path: Path | str | None = None,
    *,
    to_status: str = STATUS_PENDING,
) -> ApprovalRecord:
    """Return an executing claim to pending (e.g. approve_blocked by guards)."""
    if to_status not in {STATUS_PENDING, STATUS_FAILED}:
        raise ApprovalError(f"invalid release status: {to_status}")
    return set_status(
        approval_id,
        to_status,
        path=path,
        from_statuses={STATUS_EXECUTING},
    )


def mark_rejected(approval_id: str, path: Path | str | None = None) -> ApprovalRecord:
    """Reject a pending/failed/unknown id. Not allowed while executing (fresh)."""
    return set_status(
        approval_id,
        STATUS_REJECTED,
        path=path,
        from_statuses={STATUS_PENDING, STATUS_FAILED, STATUS_UNKNOWN},
    )


def resolve_approval(
    approval_id: str,
    *,
    as_status: str,
    path: Path | str | None = None,
    outcome_note: str | None = None,
) -> ApprovalRecord:
    """Human resolution after manual DB verify (no SQL re-execution).

    Allowed targets: succeeded | failed | rejected.
    Allowed from: unknown (primary), failed, pending (reject only via reject).
    """
    target = as_status.strip().lower()
    if target == "approved":
        target = STATUS_SUCCEEDED
    if target == "confirm-succeeded":
        target = STATUS_SUCCEEDED
    if target not in {STATUS_SUCCEEDED, STATUS_FAILED, STATUS_REJECTED}:
        raise ApprovalError(
            f"resolve --as must be succeeded|failed|rejected (got {as_status!r})"
        )
    with _locked_db(path) as (_dest, conn):
        _recover_stale_in_tx(conn)
        rec = _fetch_one(conn, approval_id)
        if not rec:
            raise ApprovalError(f"approval not found: {approval_id}")
        if is_terminal_success(rec.status) and target == STATUS_SUCCEEDED:
            return rec
        if rec.status == STATUS_REJECTED and target == STATUS_REJECTED:
            return rec
        allowed_from = {STATUS_UNKNOWN, STATUS_FAILED, STATUS_PENDING, STATUS_EXECUTING}
        # Fresh executing: only allow resolve after TTL recovery made it unknown,
        # unless operator forces from executing (manual confirm after crash).
        if rec.status == STATUS_EXECUTING and not _is_stale_executing(rec):
            # Still allow explicit human resolve of a live claim they own.
            pass
        if rec.status not in allowed_from and not is_terminal_success(rec.status):
            raise ApprovalError(
                f"cannot resolve approval {approval_id} from status {rec.status}"
            )
        if is_terminal_success(rec.status) and target != STATUS_SUCCEEDED:
            raise ApprovalError(
                f"approval already succeeded: {approval_id} (idempotent; not rewritten)"
            )
        note = outcome_note or f"human resolve --as {target}"
        rec.status = target
        rec.updated_at = _now()
        rec.executing_at = None
        rec.outcome_note = (
            (rec.outcome_note + "; " if rec.outcome_note else "") + note
        )
        _update_record(conn, rec)
    return rec


def force_unknown_check(
    approval_id: str,
    path: Path | str | None = None,
) -> ApprovalRecord:
    """Surface status after stale-executing recovery (no execute).

    If still ``executing`` within TTL, leave it (another process may own it).
    If TTL expired, status becomes ``unknown``.
    """
    with _locked_db(path) as (_dest, conn):
        _recover_stale_in_tx(conn)
        rec = _fetch_one(conn, approval_id)
        if not rec:
            raise ApprovalError(f"approval not found: {approval_id}")
        return rec


def ensure_log_dir() -> None:
    default_log_dir().mkdir(parents=True, exist_ok=True)
