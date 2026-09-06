"""Approval privilege separation (v0.22).

DB credentials, policy, and approval authority live on the **trusted executor**.
Agent-facing entrypoints (``check``, ``hook``, MCP ``query_sql``/``write_sql``)
may enqueue REQUIRE_APPROVAL but must not ``approve`` / ``resolve`` / ``reject``
without an explicit trust token.

Design (key file + presenter token):
  - Trusted executor creates a local secret file
    (default ``.logs/approval.key``, or ``SQL_WRITE_GATE_APPROVAL_KEY_FILE``).
  - Operator/CI presents the same value via env ``SQL_WRITE_GATE_APPROVAL_TOKEN``.
  - Missing key file, missing token, or mismatch → refuse (fail closed).
  - Agents never receive the key file or token; they cannot rewrite ``policy.yaml``
    through gate commands (no policy-write API on agent paths).

Not a distributed auth system — single-host / 非生产唯一边界.
"""

from __future__ import annotations

import hmac
import os
from pathlib import Path

from write_gate.paths import default_log_dir

ENV_TOKEN = "SQL_WRITE_GATE_APPROVAL_TOKEN"
ENV_KEY_FILE = "SQL_WRITE_GATE_APPROVAL_KEY_FILE"
DEFAULT_KEY_NAME = "approval.key"


class TrustError(Exception):
    """Missing or invalid approval trust credentials."""


def approval_key_file_path() -> Path:
    """Path to the trusted-executor approval secret file."""
    raw = os.environ.get(ENV_KEY_FILE, "").strip()
    if raw:
        return Path(raw)
    return default_log_dir() / DEFAULT_KEY_NAME


def configured_secret() -> str | None:
    """Return the configured secret from the key file, or None if absent/empty."""
    path = approval_key_file_path()
    try:
        if not path.is_file():
            return None
        text = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return text or None


def presented_token() -> str | None:
    """Token presented by the caller via ``SQL_WRITE_GATE_APPROVAL_TOKEN``.

    Returns None when the env var is unset. An explicitly empty string is treated
    as a presented (but wrong) token so we fail closed with "invalid" rather than
    "missing" when someone clears the value.
    """
    if ENV_TOKEN not in os.environ:
        return None
    return os.environ.get(ENV_TOKEN, "")


def require_approval_trust() -> None:
    """Refuse unless presenter token matches the trusted-executor key file.

    Raises:
        TrustError: no key file, no token, or mismatch.
    """
    secret = configured_secret()
    key_path = approval_key_file_path()
    if secret is None:
        raise TrustError(
            "approval privilege refused: no approval key file on the trusted "
            f"executor (create {key_path} with a secret, then set "
            f"{ENV_TOKEN} to match). Agent check/hook/MCP cannot approve."
        )
    token = presented_token()
    if token is None:
        raise TrustError(
            "approval privilege refused: missing "
            f"{ENV_TOKEN} (must match the trusted executor key file). "
            "Agent-facing entrypoints cannot approve/resolve/reject."
        )
    if not hmac.compare_digest(token, secret):
        raise TrustError(
            "approval privilege refused: invalid approval token "
            f"(does not match {key_path})"
        )
