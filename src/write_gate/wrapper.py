"""The only SQL write tool. All INSERT/UPDATE/DELETE go through WriteGate.execute."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from write_gate.adapters.base import (
    BACKEND_DUCKDB,
    BACKEND_MYSQL,
    BACKEND_POSTGRES,
    BACKEND_SQLITE,
    resolve_target,
)
from write_gate.approvals import (
    STATUS_EXECUTING,
    STATUS_UNKNOWN,
    ApprovalError,
    claim_for_execute,
    classify_execute_error,
    enqueue_approval,
    get_approval,
    is_terminal_success,
    mark_failed,
    mark_rejected,
    mark_succeeded,
    mark_unknown,
    release_claim,
)
from write_gate.audit import (
    append_audit,
    database_config_id,
    resolve_trusted_database_url,
    url_has_redacted_password,
)
from write_gate.catalog import Catalog, load_catalog
from write_gate.config import Policy, load_policy
from write_gate.decision import ACTION_ALLOW, ACTION_APPROVAL, Decision, Evidence
from write_gate.engine import evaluate
from write_gate.paths import (
    default_approvals_path,
    default_audit_path,
    default_catalog_path,
    default_db_path,
    default_policy_path,
)

__all__ = ["WriteGate", "Evidence", "Decision"]


class WriteGate:
    """Deterministic pre-write gate wrapping DuckDB, PostgreSQL, MySQL, or SQLite."""

    def __init__(
        self,
        db_path: Path | str | None = None,
        catalog_path: Path | None = None,
        catalog: Catalog | None = None,
        conn: Any | None = None,
        policy_path: Path | None = None,
        policy: Policy | None = None,
        audit_path: Path | None = None,
        approvals_path: Path | str | None = None,
        agent: str = "cli",
        database: str | None = None,
        database_url: str | None = None,
    ) -> None:
        backend, target = resolve_target(
            database=database,
            database_url=database_url,
            db_path=db_path,
        )
        self.backend = backend
        self.database = target
        self.db_path = Path(target) if backend == BACKEND_DUCKDB else default_db_path()
        self.catalog_path = Path(catalog_path) if catalog_path else default_catalog_path()
        self.catalog = catalog or load_catalog(self.catalog_path)
        self.policy_path = Path(policy_path) if policy_path else default_policy_path()
        self.policy = policy or load_policy(self.policy_path)
        self.audit_path = Path(audit_path) if audit_path else default_audit_path()
        self.approvals_path = (
            Path(approvals_path) if approvals_path else default_approvals_path()
        )
        self.agent = agent
        self.database_config_id = None
        self._conn = conn
        self._owns_conn = conn is None

    @property
    def conn(self) -> Any:
        if self._conn is None:
            self._conn = self._connect()
        return self._conn

    def _connect(self) -> Any:
        target = self._resolved_database()
        if self.backend == BACKEND_POSTGRES:
            from write_gate.adapters.postgres import connect as pg_connect

            return pg_connect(target)
        if self.backend == BACKEND_MYSQL:
            from write_gate.adapters.mysql import connect as mysql_connect

            return mysql_connect(target)
        if self.backend == BACKEND_SQLITE:
            from write_gate.adapters.sqlite import connect as sqlite_connect

            return sqlite_connect(target)
        from write_gate.adapters.duckdb import connect as duck_connect

        return duck_connect(self.db_path)

    def _resolved_database(self) -> str:
        """Return a connectable database target; never use ``***`` as a password.

        When ``database_config_id`` is set (approval reconnect), the resolved
        target fingerprint must match — never silently swap to a different
        ``DATABASE_URL``.
        """
        raw = self.database
        expected = getattr(self, "database_config_id", None)
        if raw and url_has_redacted_password(raw):
            resolved = resolve_trusted_database_url(
                raw,
                preferred=None,
                config_id=expected,
            )
            if not resolved or url_has_redacted_password(resolved):
                raise ApprovalError(
                    "cannot reconnect with redacted database password (***); "
                    "bind trusted credentials via DATABASE_URL for the same DB target"
                    + (f" (expected {expected})" if expected else "")
                )
            if expected and database_config_id(resolved) != expected:
                raise ApprovalError(
                    f"approval target mismatch: queued for {expected}, "
                    f"resolved {database_config_id(resolved)} — refuse write "
                    "(will not swap to a different DATABASE_URL)"
                )
            return resolved
        if expected:
            got = database_config_id(raw)
            if got != expected:
                raise ApprovalError(
                    f"approval target mismatch: queued for {expected}, "
                    f"current target {got} — refuse write "
                    "(will not swap to a different DATABASE_URL)"
                )
        return raw

    def _bind_approval_target(self, rec) -> None:
        """Rebind this gate to the approval's queued DB fingerprint (fail closed).

        Queue-against-A / env-now-B must never execute against B.
        """
        expected = getattr(rec, "database_config_id", None)
        if not expected:
            # Legacy URL approvals without fingerprint: refuse reconnect.
            if rec.database and "://" in str(rec.database):
                raise ApprovalError(
                    "approval missing database_config_id; refuse reconnect "
                    "(re-queue required under v0.19+ target binding)"
                )
            if rec.db_path:
                expected = database_config_id(rec.db_path)
            if not expected:
                return

        candidate: str | None = None
        if rec.database:
            if url_has_redacted_password(rec.database):
                candidate = resolve_trusted_database_url(
                    rec.database,
                    config_id=expected,
                )
            elif database_config_id(rec.database) == expected:
                candidate = str(rec.database)
        if candidate is None and rec.db_path:
            if database_config_id(rec.db_path) == expected:
                candidate = str(rec.db_path)
        if candidate is None:
            current = self.database
            if database_config_id(current) == expected:
                candidate = str(current)
            elif (
                self.backend == BACKEND_DUCKDB
                and database_config_id(str(self.db_path)) == expected
            ):
                candidate = str(self.db_path)

        if candidate is None or database_config_id(candidate) != expected:
            raise ApprovalError(
                f"approval target mismatch: queued for {expected}, "
                "current DATABASE_URL/credentials do not bind to that fingerprint "
                "(fail closed; will not write to a different database)"
            )

        backend, target = resolve_target(database=candidate)
        if self._conn is not None and self._owns_conn:
            self.close()
        self.backend = backend
        self.database = target
        self.database_config_id = expected
        if backend == BACKEND_DUCKDB:
            self.db_path = Path(target)

    def _conn_if_available(self) -> Any | None:
        if self._conn is not None:
            return self._conn
        if self.backend == BACKEND_DUCKDB and self.db_path.exists():
            return self.conn
        return None

    def _conn_for_execute(self) -> Any | None:
        """Prefer a live connection for blast-radius; AST guards still run if connect fails."""
        if self._conn is not None:
            return self._conn
        try:
            return self.conn
        except Exception:
            return None

    def _evaluate(
        self, sql: str, *, use_conn: bool, human_approved: bool = False
    ) -> Decision:
        if use_conn:
            conn = self._conn_for_execute()
        else:
            conn = self._conn_if_available()
        return evaluate(
            sql,
            self.catalog,
            policy=self.policy,
            conn=conn,
            dialect=self.backend,
            human_approved=human_approved,
        )

    def _audit(
        self,
        decision: Decision,
        *,
        executed: bool | None = None,
        execution_outcome: str | None = None,
        error_class: str | None = None,
    ) -> None:
        append_audit(
            decision,
            agent=self.agent,
            environment=self.policy.environment,
            path=self.audit_path,
            database=self.database,
            executed=executed,
            execution_outcome=execution_outcome,
            error_class=error_class,
        )

    def check(self, sql: str) -> Decision:
        decision = self._evaluate(sql, use_conn=False)
        self._audit(decision)
        return decision

    def execute(self, sql: str) -> tuple[Decision, Any]:
        """Gate then (only if ALLOW) run SQL via the single adapter write path.

        REQUIRE_APPROVAL is enqueued and not executed. BLOCK is not queued
        and not executed. check() stays evaluate-only (no enqueue).
        """
        decision = self._evaluate(sql, use_conn=True)
        if decision.action == ACTION_APPROVAL:
            rec = enqueue_approval(
                sql=sql,
                decision=decision,
                database=self.database,
                db_path=str(self.db_path) if self.backend == BACKEND_DUCKDB else None,
                policy_path=str(self.policy_path) if self.policy_path else None,
                catalog_path=str(self.catalog_path) if self.catalog_path else None,
                path=self.approvals_path,
                backend=self.backend,
                agent=self.agent,
            )
            decision.approval_id = rec.id
            rec.decision = decision.to_dict()
            self._audit(
                decision,
                executed=False,
                execution_outcome="queued",
            )
            return decision, None
        if decision.action != ACTION_ALLOW:
            self._audit(
                decision,
                executed=False,
                execution_outcome="blocked",
            )
            return decision, None
        try:
            result = self._execute_user_sql(sql)
        except Exception as exc:
            self._audit(
                decision,
                executed=False,
                execution_outcome="failed",
                error_class=type(exc).__name__,
            )
            raise
        self._audit(
            decision,
            executed=True,
            execution_outcome="executed",
        )
        return decision, result

    def approve(
        self,
        approval_id: str,
        *,
        allow_unknown_retry: bool = False,
    ) -> tuple[Decision, Any]:
        """Atomically claim → executing, re-run guards, execute if ALLOW.

        Outcomes after attempt:
          succeeded — DB write/query completed; status ``succeeded``
          failed — known not executed / rolled back before commit uncertainty
          unknown — timeout/disconnect/mark failure; NEVER auto-retried

        Clears environment 'approval' rules and PII SELECT approval for this
        queued statement. Destructive / PII-write / freshness / blast BLOCK
        still apply. Only the claimer executes; a second approve on
        succeeded/unknown does not write (idempotent / explicit retry only).
        """
        existing = get_approval(approval_id, path=self.approvals_path)
        if existing is None:
            raise ApprovalError(f"approval not found: {approval_id}")
        if is_terminal_success(existing.status):
            decision = Decision(
                action=ACTION_ALLOW,
                risk="low",
                rule_id="ok",
                reason=(
                    f"approval {existing.id} already approved "
                    "(idempotent; not re-executed)"
                ),
                sql=existing.sql,
                approval_id=existing.id,
                operation=(existing.decision or {}).get("operation"),
                table=(existing.decision or {}).get("table"),
            )
            self._audit(
                decision,
                executed=False,
                execution_outcome="already_approved",
            )
            return decision, None
        if existing.status == STATUS_UNKNOWN and not allow_unknown_retry:
            raise ApprovalError(
                f"approval outcome unknown: {existing.id} — verify the target DB, "
                "then `resolve --as succeeded|failed|rejected` or "
                "`approve --allow-unknown-retry` (never auto-retried)"
            )
        if existing.status == STATUS_EXECUTING and not allow_unknown_retry:
            raise ApprovalError(
                f"approval still executing: {existing.id} — wait for TTL→unknown, "
                "use `approve --force-unknown-check`, then resolve or "
                "`--allow-unknown-retry` (never silently re-claimed)"
            )

        # Fail-closed target check before claim so a mismatch never leaves
        # the row stuck in ``executing``.
        self._bind_approval_target(existing)

        # Atomic claim under flock + SQLite — closes the approve race window.
        try:
            rec = claim_for_execute(
                approval_id,
                path=self.approvals_path,
                allow_unknown_retry=allow_unknown_retry,
            )
        except ApprovalError:
            # Re-read: may have become succeeded between get and claim.
            again = get_approval(approval_id, path=self.approvals_path)
            if again is not None and is_terminal_success(again.status):
                decision = Decision(
                    action=ACTION_ALLOW,
                    risk="low",
                    rule_id="ok",
                    reason=(
                        f"approval {again.id} already approved "
                        "(idempotent; not re-executed)"
                    ),
                    sql=again.sql,
                    approval_id=again.id,
                    operation=(again.decision or {}).get("operation"),
                    table=(again.decision or {}).get("table"),
                )
                self._audit(
                    decision,
                    executed=False,
                    execution_outcome="already_approved",
                )
                return decision, None
            raise

        # Reaffirm binding after claim (env must still match fingerprint).
        try:
            self._bind_approval_target(rec)
        except ApprovalError:
            release_claim(rec.id, path=self.approvals_path, to_status="pending")
            raise

        saved_policy = self.policy
        try:
            self.policy = saved_policy.with_env_approvals_cleared()
            decision = self._evaluate(rec.sql, use_conn=True, human_approved=True)
        finally:
            self.policy = saved_policy
        decision.approval_id = rec.id
        if decision.action != ACTION_ALLOW:
            release_claim(rec.id, path=self.approvals_path, to_status="pending")
            self._audit(
                decision,
                executed=False,
                execution_outcome="approve_blocked",
            )
            return decision, None
        try:
            result = self._execute_user_sql(rec.sql)
        except Exception as exc:
            outcome = classify_execute_error(exc)
            if outcome == STATUS_UNKNOWN:
                mark_unknown(
                    rec.id,
                    path=self.approvals_path,
                    error_class=type(exc).__name__,
                    outcome_note="execute raised indeterminate error",
                )
                exec_outcome = "unknown"
            else:
                mark_failed(
                    rec.id,
                    path=self.approvals_path,
                    error_class=type(exc).__name__,
                    outcome_note="execute raised known failure",
                )
                exec_outcome = "failed"
            self._audit(
                decision,
                executed=False,
                execution_outcome=exec_outcome,
                error_class=type(exc).__name__,
            )
            raise
        try:
            mark_succeeded(rec.id, path=self.approvals_path)
        except Exception as mark_exc:
            # Write may have reached the DB; do not leave executing for silent reclaim.
            try:
                mark_unknown(
                    rec.id,
                    path=self.approvals_path,
                    error_class=type(mark_exc).__name__,
                    outcome_note="post-exec mark_succeeded failed → unknown",
                )
            except ApprovalError:
                pass
            self._audit(
                decision,
                executed=True,
                execution_outcome="unknown",
                error_class=type(mark_exc).__name__,
            )
            raise
        self._audit(
            decision,
            executed=True,
            execution_outcome="executed",
        )
        return decision, result

    def reject(self, approval_id: str) -> None:
        """Mark pending id rejected. Does not write."""
        mark_rejected(approval_id, path=self.approvals_path)

    def _execute_user_sql(self, sql: str):
        if self.backend == BACKEND_POSTGRES:
            from write_gate.adapters.postgres import execute_user_sql as exec_sql
        elif self.backend == BACKEND_MYSQL:
            from write_gate.adapters.mysql import execute_user_sql as exec_sql
        elif self.backend == BACKEND_SQLITE:
            from write_gate.adapters.sqlite import execute_user_sql as exec_sql
        else:
            from write_gate.adapters.duckdb import execute_user_sql as exec_sql
        return exec_sql(self.conn, sql)

    def close(self) -> None:
        if self._owns_conn and self._conn is not None:
            close = getattr(self._conn, "close", None)
            if callable(close):
                close()
            self._conn = None

    def __enter__(self) -> "WriteGate":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
