"""Statement timeout for check / execute / approve paths (v0.23).

When ``statement_timeout_sec`` > 0, user SQL (and optional session SET) must
finish within that wall clock. On expiry we raise ``StatementTimeoutError``.

Approve-path mapping (0.21 three-state):
  - Timeout after the driver may have accepted the statement → ``unknown``
  - Clear pre-send / client-side cancel with no DB apply → ``failed``

``StatementTimeoutError`` defaults to indeterminate (``unknown``) because a
worker thread may still be mid-flight when we abandon waiting.
"""

from __future__ import annotations

import concurrent.futures
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
    """Run ``fn`` with a wall-clock timeout.

    Uses a worker thread so DuckDB/SQLite/drivers without native cancel still
    surface a timeout to the gate. Abandoning the wait is indeterminate.
    """
    if timeout_sec is None or timeout_sec <= 0:
        return fn()
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        fut = pool.submit(fn)
        try:
            return fut.result(timeout=timeout_sec)
        except concurrent.futures.TimeoutError as exc:
            raise StatementTimeoutError(
                f"{label} exceeded statement timeout "
                f"({timeout_sec:g}s); outcome may be indeterminate",
                timeout_sec=timeout_sec,
                indeterminate=True,
            ) from exc
