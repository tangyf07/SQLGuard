"""Permanent R1–R6 regression contract (introduced in v0.19, kept for v0.20+).

Implementation lives in ``tests/test_v019.py``. Each R-item must assert BOTH:
dangerous cases BLOCK/REJECT **and** normal safe cases still ALLOW /
REQUIRE_APPROVAL (not over-block). v0.17 / v0.18 suites must stay green.
"""

from __future__ import annotations

import test_v019 as suite

_REQUIRED = [
    # R1 dangerous + safe
    "test_r1_claim_is_atomic_second_approve_does_not_execute",
    "test_r1_second_claim_blocked_under_flock",
    "test_r1_safe_single_approve_executes_once",
    # R2
    "test_r2_never_treat_stars_as_password",
    "test_r2_connect_refuses_redacted_without_binding",
    "test_r2_plain_url_connect_not_overblocked",
    # R3
    "test_r3_approve_json_includes_rows",
    # R4
    "test_r4_audit_on_execute_exception",
    "test_r4_successful_execute_audited_as_executed",
    # R5
    "test_r5_not_gte_cutoff_blocks",
    "test_r5_fresh_range_and_allows",
    "test_r5_safe_fresh_equality_allows",
    # R6
    "test_r6_nested_delete_under_insert_rejected",
    "test_r6_plain_insert_still_allows",
]


def test_r1_r6_permanent_suite_present():
    missing = [n for n in _REQUIRED if not callable(getattr(suite, n, None))]
    assert not missing, f"R1–R6 suite missing: {missing}"
