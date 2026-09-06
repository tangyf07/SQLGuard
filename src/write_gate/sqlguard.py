"""Optional SQLGuard product alias over write_gate.

DataPilot and docs may ``import sqlguard`` / ``from write_gate import sqlguard``.
Package name and CLI remain ``write_gate`` / ``sql-write-gate``.
"""

from __future__ import annotations

from write_gate import Decision, Evidence, WriteGate, __version__
from write_gate.api import decision_response, handle_datapilot_request, serve
from write_gate.engine import evaluate
from write_gate.policy import evaluate as policy_evaluate

PRODUCT = "SQLGuard"
VERSION = __version__

__all__ = [
    "PRODUCT",
    "VERSION",
    "WriteGate",
    "Decision",
    "Evidence",
    "evaluate",
    "policy_evaluate",
    "decision_response",
    "handle_datapilot_request",
    "serve",
]
