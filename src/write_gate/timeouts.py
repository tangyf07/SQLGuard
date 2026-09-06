"""Statement timeout for check / execute / approve paths (v0.23 / v1.0.1).

When ``statement_timeout_sec`` > 0, user SQL (and optional session SET) must
finish within that wall clock. On expiry we raise ``StatementTimeoutError``.

Approve-path mapping (0.21 three-state):
  - Timeout after the driver may have accepted the statement → ``unknown``
  - Clear pre-send / client-side cancel with no DB apply → ``failed``

``StatementTimeoutError`` defaults to indeterminate (``unknown``) because a
worker thread may still be mid-flight when we abandon waiting.

v1.0.1: the *caller* returns promptly at the deadline. We do **not** block on
pool/thread shutdown waiting for the slow worker (the 1.0.0 ``with
ThreadPoolExecutor`` hang).
"""

from __future__ import annotations

import threading
from typing import Any, Callable, TypeVar

T = TypeVar("T")


class StatementTimeoutError(TimeoutError):
    """Raised when gated SQL exceeds the configured statement timeout.

    ``indeterminate`` True → treat like connection timeout (approve → unknown).
    ``indeterminate`` False → sure not applied (approve → failed).
    """

    def __init__(
        self,
        message: str,
        *,
        timeout_sec: float,
        indeterminate: bool = True,
    ) -> None:
        super().__init__(message)
        self.timeout_sec = float(timeout_sec)
        self.indeterminate = bool(indeterminate)


def apply_session_timeout(conn: Any, timeout_sec: float, backend: str) -> None:
    """Best-effort native session timeout (Postgres / MySQL). No-op if unsupported."""
    if timeout_sec is None or timeout_sec <= 0 or conn is None:
        return
    ms = max(1, int(timeout_sec * 1000))
    sql: str | None = None
    b = (backend or "").lower()
    if b in {"postgres", "postgresql"}:
        sql = f"SET statement_timeout = {ms}"
    elif b == "mysql":
        # MySQL 5.7+: max_execution_time is milliseconds (SELECT only on some versions).
        sql = f"SET SESSION max_execution_time = {ms}"
    if not sql:
        return
    try:
        execute = getattr(conn, "execute", None)
        if callable(execute):
            execute(sql)
    except Exception:
        # Native SET is best-effort; wall-clock wrapper still applies.
        pass


def run_with_timeout(
    fn: Callable[[], T],
    *,
    timeout_sec: float,
    label: str = "statement",
) -> T:
    """Run ``fn`` with a wall-clock timeout; return promptly when the deadline hits.

    Uses a **daemon** worker thread so DuckDB/SQLite/drivers without native
    cancel still surface a timeout to the gate. ``Thread.join(timeout=…)``
    returns at the deadline; we never block waiting for the slow worker to
    finish (unlike ``with ThreadPoolExecutor``, whose ``__exit__`` waited).

    Cancel / connection semantics (document for operators):
    - This wrapper does **not** forcibly abort an in-flight DB call. The
      daemon worker may keep running until the driver returns; it may still
      hold a connection or finish applying SQL after we raise.
    - Native session timeouts (Postgres ``statement_timeout``, MySQL
      ``max_execution_time`` via ``apply_session_timeout``) remain best-effort
      cooperation from the server side.
    - Because the outcome may still apply after we abandon the wait,
      ``StatementTimeoutError.indeterminate`` defaults to True → execute /
      approve map to ``unknown`` per 0.21. **No blind retry.**
    """
    if timeout_sec is None or timeout_sec <= 0:
        return fn()

    box: list[T] = []
    err: list[BaseException] = []

    def _runner() -> None:
        try:
            box.append(fn())
        except BaseException as exc:  # noqa: BLE001 — re-raise on caller thread
            err.append(exc)

    thread = threading.Thread(
        target=_runner,
        name=f"sql-write-gate-{label}",
        daemon=True,
    )
    thread.start()
    thread.join(timeout=timeout_sec)
    if thread.is_alive():
        raise StatementTimeoutError(
            f"{label} exceeded statement timeout "
            f"({timeout_sec:g}s); outcome may be indeterminate",
            timeout_sec=timeout_sec,
            indeterminate=True,
        )
    if err:
        raise err[0]
    return box[0]
