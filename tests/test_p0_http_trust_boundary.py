"""P0 HTTP trust boundary: body cannot override locked serve config; bind auth."""

from __future__ import annotations

from pathlib import Path

import pytest

from write_gate.api import (
    ServeBindError,
    authorize_http_request,
    handle_datapilot_request,
    is_all_interfaces_host,
    is_loopback_host,
    lock_serve_defaults,
    validate_serve_bind,
)

ROOT = Path(__file__).resolve().parents[1]


def _defaults(tmp_path: Path | None = None) -> dict:
    return {
        "db_path": str(ROOT / "seed" / "warehouse.duckdb"),
        "policy": str(ROOT / "examples" / "policy.demo.yaml"),
        "agent": "datapilot",
    }


def test_loopback_hosts_identified():
    assert is_loopback_host("127.0.0.1")
    assert is_loopback_host("localhost")
    assert is_loopback_host("::1")
    assert not is_loopback_host("0.0.0.0")
    assert not is_loopback_host("192.168.1.10")
    assert is_all_interfaces_host("0.0.0.0")
    assert is_all_interfaces_host("::")


def test_reject_all_interfaces_without_auth():
    with pytest.raises(ServeBindError, match="0.0.0.0"):
        validate_serve_bind("0.0.0.0", None)
    with pytest.raises(ServeBindError, match="authentication"):
        validate_serve_bind("::", None)


def test_reject_non_loopback_without_auth():
    with pytest.raises(ServeBindError, match="non-loopback"):
        validate_serve_bind("192.168.1.5", None)


def test_allow_loopback_without_auth():
    validate_serve_bind("127.0.0.1", None)
    validate_serve_bind("localhost", None)


def test_allow_non_loopback_with_auth():
    validate_serve_bind("0.0.0.0", "secret")
    validate_serve_bind("10.0.0.2", "secret")


def test_body_cannot_override_policy_catalog_db():
    defaults = lock_serve_defaults(_defaults())
    for route in ("/v1/check", "/v1/execute", "/v1/datapilot", "/v1/block"):
        for field, value in (
            ("policy", "/tmp/evil-policy.yaml"),
            ("catalog", "/tmp/evil-catalog.json"),
            ("database", "/tmp/evil.duckdb"),
            ("db_path", "/tmp/evil.duckdb"),
            ("environment", "demo"),
        ):
            status, payload = handle_datapilot_request(
                "POST",
                route,
                {"sql": "DELETE FROM orders", field: value},
                defaults=defaults,
            )
            assert status == 400, (route, field, payload)
            assert payload["error"] == "trust_boundary_violation"
            assert field in payload["rejected_fields"]
            assert payload["action"] == "BLOCK"


def test_body_override_ignored_fields_do_not_change_locked_gate(tmp_path):
    """Even if somehow only allowed keys present, locked paths win for evaluate."""
    defaults = lock_serve_defaults(_defaults())
    status, payload = handle_datapilot_request(
        "POST",
        "/v1/check",
        {"sql": "DELETE FROM orders", "actor": "pilot", "model_id": "m"},
        defaults=defaults,
    )
    assert status == 200
    assert payload["action"] == "BLOCK"
    assert payload["executed"] is False


def test_execute_alias_also_rejects_db_override():
    defaults = lock_serve_defaults(_defaults())
    status, payload = handle_datapilot_request(
        "POST",
        "/v1/execute",
        {
            "sql": "SELECT 1",
            "database": "postgresql://evil/db",
            "policy": "/etc/passwd",
        },
        defaults=defaults,
    )
    assert status == 400
    assert set(payload["rejected_fields"]) >= {"database", "policy"}


def test_auth_required_when_token_configured():
    defaults = lock_serve_defaults(_defaults())
    status, payload = handle_datapilot_request(
        "POST",
        "/v1/check",
        {"sql": "DELETE FROM orders"},
        defaults=defaults,
        auth_token="s3cret",
    )
    assert status == 401
    assert payload["error"] == "unauthorized"

    status, payload = handle_datapilot_request(
        "POST",
        "/v1/check",
        {"sql": "DELETE FROM orders"},
        defaults=defaults,
        auth_token="s3cret",
        presented_token="wrong",
    )
    assert status == 401

    status, payload = handle_datapilot_request(
        "POST",
        "/v1/check",
        {"sql": "DELETE FROM orders"},
        defaults=defaults,
        auth_token="s3cret",
        presented_token="s3cret",
    )
    assert status == 200
    assert payload["action"] == "BLOCK"


def test_authorize_http_request_headers():
    class H(dict):
        def get(self, k, default=None):
            for key, val in self.items():
                if key.lower() == k.lower():
                    return val
            return default

    assert authorize_http_request(auth_token=None) is True
    assert authorize_http_request(auth_token="t", headers=H()) is False
    assert authorize_http_request(
        auth_token="t", headers=H({"Authorization": "Bearer t"})
    )
    assert authorize_http_request(
        auth_token="t", headers=H({"X-SQLGuard-Token": "t"})
    )


def test_lock_serve_defaults_captures_environment():
    locked = lock_serve_defaults(_defaults())
    assert locked.get("environment")
    assert "policy" in locked
