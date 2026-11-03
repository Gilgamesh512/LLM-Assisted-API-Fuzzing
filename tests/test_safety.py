from __future__ import annotations

from core.safety import filter_safe_payloads, is_safe_payload


def test_is_safe_payload_blocks_delete_method():
    payload = {"method": "DELETE", "endpoint": "/api/users/123"}
    safe, reason = is_safe_payload(payload)
    assert not safe
    assert "DELETE" in reason


def test_is_safe_payload_blocks_destructive_endpoint():
    payload = {"method": "POST", "endpoint": "/api/v1/reset_database"}
    safe, reason = is_safe_payload(payload)
    assert not safe
    assert "reset" in reason.lower() or "phá hoại" in reason


def test_is_safe_payload_allows_benign_get_post():
    payload = {"method": "GET", "endpoint": "/api/users/profile"}
    safe, _ = is_safe_payload(payload)
    assert safe


def test_filter_safe_payloads():
    payloads = [
        {"method": "GET", "endpoint": "/api/posts"},
        {"method": "DELETE", "endpoint": "/api/posts/1"},
        {"method": "POST", "endpoint": "/api/admin/nuke"},
    ]
    safe, blocked = filter_safe_payloads(payloads, safe_mode=True)
    assert len(safe) == 1
    assert len(blocked) == 2
    assert safe[0]["endpoint"] == "/api/posts"
