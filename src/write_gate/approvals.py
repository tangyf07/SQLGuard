"""JSONL approval queue. REQUIRE_APPROVAL SQL is recorded and not executed."""

from __future__ import annotations

import json
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
STATUS_APPROVED = "approved"
STATUS_REJECTED = "rejected"
STATUS_EXECUTING = "executing"
STATUS_FAILED = "failed"

_ID_LEN = 12

# Single-host concurrency: flock around load+atomic replace.
# Cross-host / NFS locking is not supported (not a distributed lock).
# If fcntl.flock is unavailable (e.g. Windows), approval mutations fail closed
# rather than silently degrading concurrent approve safety.
_LOCK_NOTE = (
    "approvals.jsonl uses flock + atomic replace for single-host concurrency; "
    "not a distributed lock"
)
_FLOCK_REQUIRED_MSG = (
    "concurrent approval requires fcntl.flock (Unix); not available on this "
    "platform — refusing rather than silently degrading (see README support matrix)"
)


class ApprovalError(Exception):
    """Missing, not pending, invalid approval, or flock unavailable."""


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
    decision: dict[str, Any] = field(default_factory=dict)
    backend: str | None = None
    agent: str | None = None

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
            "decision": self.decision,
            "backend": self.backend,
            "agent": self.agent,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ApprovalRecord":
        decision = raw.get("decision")
        if not isinstance(decision, dict):
            decision = {}
        return cls(
            id=str(raw.get("id") or ""),
            status=str(raw.get("status") or STATUS_PENDING),
            sql=str(raw.get("sql") or ""),
            database=raw.get("database"),
            database_config_id=raw.get("database_config_id"),
            db_path=raw.get("db_path"),
            policy_path=raw.get("policy_path"),
            catalog_path=raw.get("catalog_path"),
            created_at=str(raw.get("created_at") or ""),
            decision=decision,
            backend=raw.get("backend"),
            agent=raw.get("agent"),
        )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id() -> str:
    return uuid.uuid4().hex[:_ID_LEN]


def _path(path: Path | str | None = None) -> Path:
    return Path(path) if path else default_approvals_path()


def _lock_path(path: Path) -> Path:
    return path.with_suffix(path.suffix + ".lock")


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
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_file = _lock_path(path)
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


def _load(path: Path) -> dict[str, dict[str, Any]]:
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


def _save(path: Path, records: dict[str, dict[str, Any]]) -> None:
    """Atomic replace: write temp then rename over the live file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    body = "".join(json.dumps(rec, ensure_ascii=False) + "\n" for rec in records.values())
    tmp.write_text(body, encoding="utf-8")
    tmp.replace(path)


def get_approval(approval_id: str, path: Path | str | None = None) -> ApprovalRecord | None:
    dest = _path(path)
    with _file_lock(dest):
        raw = _load(dest).get(str(approval_id))
    if not raw:
        return None
    return ApprovalRecord.from_dict(raw)


def list_pending(path: Path | str | None = None) -> list[ApprovalRecord]:
    dest = _path(path)
    with _file_lock(dest):
        loaded = _load(dest)
    pending: list[ApprovalRecord] = []
    for raw in loaded.values():
        rec = ApprovalRecord.from_dict(raw)
        if rec.status == STATUS_PENDING and rec.id:
            pending.append(rec)
    pending.sort(key=lambda r: r.created_at)
    return pending


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
    dest = _path(path)
    with _file_lock(dest):
        records = _load(dest)
        approval_id = _new_id()
        while approval_id in records:
            approval_id = _new_id()
        redacted = redact_database_url(database) if database else None
        rec = ApprovalRecord(
            id=approval_id,
            status=STATUS_PENDING,
            sql=sql,
            database=redacted,
            database_config_id=database_config_id(database) if database else None,
            db_path=db_path,
            policy_path=str(policy_path) if policy_path else None,
            catalog_path=str(catalog_path) if catalog_path else None,
            created_at=_now(),
            decision=decision.to_dict(),
            backend=backend,
            agent=agent,
        )
        # Snapshot includes approval_id once attached on the live decision.
        rec.decision = {**rec.decision, "approval_id": approval_id}
        records[approval_id] = rec.to_dict()
        _save(dest, records)
    return rec


def set_status(
    approval_id: str,
    status: str,
    path: Path | str | None = None,
    *,
    allow_idempotent_approved: bool = False,
    from_statuses: set[str] | None = None,
) -> ApprovalRecord:
    allowed = {
        STATUS_PENDING,
        STATUS_APPROVED,
        STATUS_REJECTED,
        STATUS_EXECUTING,
        STATUS_FAILED,
    }
    if status not in allowed:
        raise ApprovalError(f"invalid approval status: {status}")
    dest = _path(path)
    with _file_lock(dest):
        records = _load(dest)
        raw = records.get(str(approval_id))
        if not raw:
            raise ApprovalError(f"approval not found: {approval_id}")
        rec = ApprovalRecord.from_dict(raw)
        if rec.status == status and status == STATUS_APPROVED and allow_idempotent_approved:
            return rec
        expected = from_statuses if from_statuses is not None else {STATUS_PENDING}
        if rec.status not in expected:
            raise ApprovalError(f"approval not pending: {approval_id}")
        rec.status = status
        records[rec.id] = rec.to_dict()
        _save(dest, records)
    return rec


def claim_for_execute(
    approval_id: str,
    path: Path | str | None = None,
    *,
    recover_failed: bool = True,
) -> ApprovalRecord:
    """Atomically claim ``pending`` (or ``failed``) → ``executing`` under flock.

    Only the claimer may execute. A second approve sees non-pending and must not
    write. Crash recovery: ``failed`` can be reclaimed; stuck ``executing`` is
    not silently stolen by a concurrent approver (use recover_failed path after
    marking failed).
    """
    dest = _path(path)
    with _file_lock(dest):
        records = _load(dest)
        raw = records.get(str(approval_id))
        if not raw:
            raise ApprovalError(f"approval not found: {approval_id}")
        rec = ApprovalRecord.from_dict(raw)
        if rec.status == STATUS_APPROVED:
            raise ApprovalError(f"approval not pending: {approval_id}")
        claimable = {STATUS_PENDING}
        if recover_failed:
            claimable.add(STATUS_FAILED)
        if rec.status not in claimable:
            raise ApprovalError(f"approval not pending: {approval_id}")
        rec.status = STATUS_EXECUTING
        records[rec.id] = rec.to_dict()
        _save(dest, records)
    return rec


def mark_approved(approval_id: str, path: Path | str | None = None) -> ApprovalRecord:
    """Mark executing (or pending for back-compat) as approved; idempotent."""
    dest = _path(path)
    with _file_lock(dest):
        records = _load(dest)
        raw = records.get(str(approval_id))
        if not raw:
            raise ApprovalError(f"approval not found: {approval_id}")
        rec = ApprovalRecord.from_dict(raw)
        if rec.status == STATUS_APPROVED:
            return rec
        if rec.status not in {STATUS_EXECUTING, STATUS_PENDING}:
            raise ApprovalError(f"approval not pending: {approval_id}")
        rec.status = STATUS_APPROVED
        records[rec.id] = rec.to_dict()
        _save(dest, records)
    return rec


def mark_failed(approval_id: str, path: Path | str | None = None) -> ApprovalRecord:
    """Mark executing claim as failed (execute exception / crash recovery)."""
    return set_status(
        approval_id,
        STATUS_FAILED,
        path=path,
        from_statuses={STATUS_EXECUTING, STATUS_PENDING},
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
    """Reject a pending (or failed) id. Not allowed while executing."""
    return set_status(
        approval_id,
        STATUS_REJECTED,
        path=path,
        from_statuses={STATUS_PENDING, STATUS_FAILED},
    )


def ensure_log_dir() -> None:
    default_log_dir().mkdir(parents=True, exist_ok=True)
