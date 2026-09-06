"""sql-write-gate: policy firewall for AI agents writing to databases."""

from write_gate.decision import Decision, Evidence
from write_gate.wrapper import WriteGate

__all__ = ["WriteGate", "Evidence", "Decision"]
__version__ = "0.21.0"
