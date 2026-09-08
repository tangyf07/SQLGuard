#!/usr/bin/env python3
"""SQLGuard seal: exactly four core cases (ALLOW/BLOCK + rule_id + evidence)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from write_gate.cases import (  # noqa: E402
    EXPIRED_WRITE_SQL,
    LEGAL_WRITE_SQL,
    PII_WRITE_SQL,
    SCHEMA_MISMATCH_SQL,
)
from write_gate.paths import DB_PATH, DEMO_POLICY_PATH  # noqa: E402
from write_gate.wrapper import WriteGate  # noqa: E402

# Stable seal order — do not reorder.
CASES = [
    ("legal_write", LEGAL_WRITE_SQL, True, "ok"),
    ("pii_write", PII_WRITE_SQL, False, "pii_column"),
    ("schema_mismatch", SCHEMA_MISMATCH_SQL, False, "schema_hallucination"),
    ("expired_partition", EXPIRED_WRITE_SQL, False, "expired_partition"),
]


def main() -> int:
    if len(CASES) != 4:
        print("SEAL_FAIL: expected exactly 4 cases", file=sys.stderr)
        return 1

    rc = 0
    audit_path = ROOT / ".logs" / "seal_audit.jsonl"
    if audit_path.exists():
        audit_path.unlink()

    with WriteGate(
        db_path=DB_PATH,
        policy_path=DEMO_POLICY_PATH,
        audit_path=audit_path,
        agent="seal",
        actor="sqlguard-seal",
        model_id="seal-offline",
        prompt_summary="make seal four core cases",
    ) as gate:
        for name, sql, expect_allow, expect_rule in CASES:
            evidence, _result = gate.execute(sql)
            verdict = "ALLOW" if evidence.allowed else "BLOCK"
            payload = {
                "case": name,
                "verdict": verdict,
                "rule_id": evidence.rule_id,
                "evidence": evidence.to_dict(),
            }
            print(json.dumps(payload, ensure_ascii=False))
            print(f"{verdict}  rule_id={evidence.rule_id}  case={name}")
            if evidence.allowed != expect_allow or evidence.rule_id != expect_rule:
                print(
                    f"SEAL_MISMATCH: case={name} expected verdict="
                    f"{'ALLOW' if expect_allow else 'BLOCK'} rule_id={expect_rule} "
                    f"got verdict={verdict} rule_id={evidence.rule_id}",
                    file=sys.stderr,
                )
                rc = 1

    if rc == 0:
        print("seal: 4/4 cases matched")
    else:
        print("seal: FAILED", file=sys.stderr)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())