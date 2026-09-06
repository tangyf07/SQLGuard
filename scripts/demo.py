#!/usr/bin/env python3
"""SQLGuard demo: classic three cases + AST / hallucination / risk / audit."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from write_gate.cases import EXPIRED_WRITE_SQL, LEGAL_WRITE_SQL, PII_WRITE_SQL  # noqa: E402
from write_gate.paths import DB_PATH, DEMO_POLICY_PATH  # noqa: E402
from write_gate.wrapper import WriteGate  # noqa: E402

CASES = [
    ("用例 1 · 合法写入（新鲜分区 + 非 PII 列）", LEGAL_WRITE_SQL, True, "ok"),
    ("用例 2 · 过期分区写入", EXPIRED_WRITE_SQL, False, "expired_partition"),
    ("用例 3 · PII 列写入", PII_WRITE_SQL, False, "pii_column"),
    (
        "用例 4 · AST · DELETE WHERE 1=1（全表写）",
        "DELETE FROM orders WHERE 1=1",
        False,
        "delete_without_where",
    ),
    (
        "用例 5 · AST · CROSS JOIN（笛卡尔积）",
        "SELECT o.order_id FROM orders o CROSS JOIN orders p",
        False,
        "cartesian_join",
    ),
    (
        "用例 6 · Schema hallucination · 未知表",
        "SELECT * FROM game_stream_sessions",
        False,
        "schema_hallucination",
    ),
]


def _banner(title: str) -> None:
    line = "=" * 72
    print(line)
    print(title)
    print(line)


def main() -> int:
    rc = 0
    audit_path = ROOT / ".logs" / "demo_audit.jsonl"
    if audit_path.exists():
        audit_path.unlink()
    with WriteGate(
        db_path=DB_PATH,
        policy_path=DEMO_POLICY_PATH,
        audit_path=audit_path,
        agent="demo",
        actor="sqlguard-demo",
        model_id="demo-offline",
        prompt_summary="make demo SQLGuard cases",
    ) as gate:
        for title, sql, expect_allow, expect_rule in CASES:
            _banner(title)
            print(f"SQL:\n  {sql}")
            evidence, result = gate.execute(sql)
            verdict = "ALLOWED" if evidence.allowed else "BLOCKED"
            print(f"VERDICT: {verdict}")
            print(f"rule_id: {evidence.rule_id}")
            print(f"risk_score: {evidence.risk_score}")
            print(f"risk_factors: {evidence.risk_factors}")
            print(f"message: {evidence.message}")
            print("evidence:")
            print(json.dumps(evidence.to_dict(), ensure_ascii=False, indent=2))
            if evidence.allowed and result is not None:
                n = gate.conn.execute(
                    "SELECT COUNT(*) FROM orders WHERE order_id = 900001"
                ).fetchone()[0]
                print(f"executed: warehouse row order_id=900001 present={int(n)}")
            else:
                print("executed: no (gate blocked write; DuckDB write API not called)")
            if evidence.allowed != expect_allow or evidence.rule_id != expect_rule:
                print(
                    f"UNEXPECTED: expected allowed={expect_allow} rule_id={expect_rule}"
                )
                rc = 1
            print()

        _banner("Audit · last lines (actor / risk_score / latency_ms)")
        if audit_path.is_file():
            lines = audit_path.read_text(encoding="utf-8").strip().splitlines()
            for line in lines[-4:]:
                rec = json.loads(line)
                print(
                    json.dumps(
                        {
                            "actor": rec.get("actor"),
                            "decision": rec.get("decision"),
                            "rule_id": rec.get("rule_id"),
                            "risk_score": rec.get("risk_score"),
                            "latency_ms": rec.get("latency_ms"),
                            "success": rec.get("success"),
                            "sql": (rec.get("sql") or "")[:60],
                        },
                        ensure_ascii=False,
                    )
                )
    if rc == 0:
        print("demo: SQLGuard cases matched expected verdicts")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
