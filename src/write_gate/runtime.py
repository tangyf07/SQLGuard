"""Runtime knobs for v0.23 ops (timeouts, result caps, audit rotation, request ids).

Env vars (preferred for ops) override policy.yaml fields when both are set.
Defaults are conservative so existing 0.17–0.22 suites stay green.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from typing import Any

# --- env names ---------------------------------------------------------------

ENV_STATEMENT_TIMEOUT = "SQL_WRITE_GATE_STATEMENT_TIMEOUT_SEC"
ENV_RESULT_ROW_LIMIT = "SQL_WRITE_GATE_RESULT_ROW_LIMIT"
ENV_RESULT_BYTE_LIMIT = "SQL_WRITE_GATE_RESULT_BYTE_LIMIT"
ENV_AUDIT_MAX_BYTES = "SQL_WRITE_GATE_AUDIT_MAX_BYTES"
ENV_AUDIT_ROTATE_DAILY = "SQL_WRITE_GATE_AUDIT_ROTATE_DAILY"
ENV_REQUEST_ID = "SQL_WRITE_GATE_REQUEST_ID"

# Defaults: generous / off so unit tests and short local runs do not flake.
DEFAULT_STATEMENT_TIMEOUT_SEC = 0.0  # 0 = disabled
DEFAULT_RESULT_ROW_LIMIT = 1000
DEFAULT_RESULT_BYTE_LIMIT = 0  # 0 = no byte cap
DEFAULT_AUDIT_MAX_BYTES = 10 * 1024 * 1024  # 10 MiB
DEFAULT_AUDIT_ROTATE_DAILY = False


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name, "")
    if not str(raw).strip():
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "")
    if not str(raw).strip():
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "")
    if not str(raw).strip():
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class RuntimeSettings:
    """Resolved ops settings for one gate / CLI invocation."""

    statement_timeout_sec: float = DEFAULT_STATEMENT_TIMEOUT_SEC
    result_row_limit: int = DEFAULT_RESULT_ROW_LIMIT
    result_byte_limit: int = DEFAULT_RESULT_BYTE_LIMIT
    audit_max_bytes: int = DEFAULT_AUDIT_MAX_BYTES
    audit_rotate_daily: bool = DEFAULT_AUDIT_ROTATE_DAILY

    @property
    def timeout_enabled(self) -> bool:
        return self.statement_timeout_sec is not None and self.statement_timeout_sec > 0


def load_runtime_settings(policy: Any | None = None) -> RuntimeSettings:
    """Merge env + optional policy fields into RuntimeSettings.

    Policy may carry::

        statement_timeout_sec: 30
        limits:
          result_rows: 500
          result_bytes: 1048576
          audit_max_bytes: 10485760
          audit_rotate_daily: true
    """
    pol_timeout = None
    pol_rows = None
    pol_bytes = None
    pol_audit_max = None
    pol_audit_daily = None
    if policy is not None:
        pol_timeout = getattr(policy, "statement_timeout_sec", None)
        pol_rows = getattr(policy, "result_row_limit", None)
        pol_bytes = getattr(policy, "result_byte_limit", None)
        pol_audit_max = getattr(policy, "audit_max_bytes", None)
        pol_audit_daily = getattr(policy, "audit_rotate_daily", None)

    # Env wins when set; else policy; else defaults.
    if os.environ.get(ENV_STATEMENT_TIMEOUT, "").strip():
        timeout = _env_float(ENV_STATEMENT_TIMEOUT, DEFAULT_STATEMENT_TIMEOUT_SEC)
    elif pol_timeout is not None:
        timeout = float(pol_timeout)
    else:
        timeout = DEFAULT_STATEMENT_TIMEOUT_SEC

    if os.environ.get(ENV_RESULT_ROW_LIMIT, "").strip():
        rows = _env_int(ENV_RESULT_ROW_LIMIT, DEFAULT_RESULT_ROW_LIMIT)
    elif pol_rows is not None:
        rows = int(pol_rows)
    else:
        rows = DEFAULT_RESULT_ROW_LIMIT

    if os.environ.get(ENV_RESULT_BYTE_LIMIT, "").strip():
        blimit = _env_int(ENV_RESULT_BYTE_LIMIT, DEFAULT_RESULT_BYTE_LIMIT)
    elif pol_bytes is not None:
        blimit = int(pol_bytes)
    else:
        blimit = DEFAULT_RESULT_BYTE_LIMIT

    if os.environ.get(ENV_AUDIT_MAX_BYTES, "").strip():
        amax = _env_int(ENV_AUDIT_MAX_BYTES, DEFAULT_AUDIT_MAX_BYTES)
    elif pol_audit_max is not None:
        amax = int(pol_audit_max)
    else:
        amax = DEFAULT_AUDIT_MAX_BYTES

    if os.environ.get(ENV_AUDIT_ROTATE_DAILY, "").strip():
        daily = _env_bool(ENV_AUDIT_ROTATE_DAILY, DEFAULT_AUDIT_ROTATE_DAILY)
    elif pol_audit_daily is not None:
        daily = bool(pol_audit_daily)
    else:
        daily = DEFAULT_AUDIT_ROTATE_DAILY

    return RuntimeSettings(
        statement_timeout_sec=max(0.0, timeout),
        result_row_limit=max(0, rows),
        result_byte_limit=max(0, blimit),
        audit_max_bytes=max(0, amax),
        audit_rotate_daily=daily,
    )


def new_request_id(explicit: str | None = None) -> str:
    """Return correlatable request id (env / arg / fresh uuid4)."""
    if explicit and str(explicit).strip():
        return str(explicit).strip()
    env = os.environ.get(ENV_REQUEST_ID, "")
    if str(env).strip():
        return str(env).strip()
    return str(uuid.uuid4())
