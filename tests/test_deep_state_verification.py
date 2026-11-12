"""
tests/test_deep_state_verification.py — Tests for Deep State Loopback Verification & False Positive Suppression.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from core.tampering import (
    execute_mass_assignment_scan,
    find_matching_getter,
    generate_baseline_body,
)


def test_find_matching_getter() -> None:
    endpoints = [
        {"method": "POST", "path": "/api/v1/users"},
        {"method": "GET", "path": "/api/v1/users/{id}"},
        {"method": "PUT", "path": "/api/v1/users/profile"},
        {"method": "GET", "path": "/api/v1/users/profile"},
        {"method": "DELETE", "path": "/api/v1/orders"},
    ]

    # 1. Cùng path chính xác
    put_ep = {"method": "PUT", "path": "/api/v1/users/profile"}
    getter = find_matching_getter(put_ep, endpoints)
    assert getter is not None
    assert getter["method"] == "GET"
    assert getter["path"] == "/api/v1/users/profile"

    # 2. Path con /{id}
    post_ep = {"method": "POST", "path": "/api/v1/users"}
    getter2 = find_matching_getter(post_ep, endpoints)
    assert getter2 is not None
    assert getter2["method"] == "GET"
    assert getter2["path"] == "/api/v1/users/{id}"

    # 3. Không tìm thấy
    other_ep = {"method": "POST", "path": "/api/v1/unknown"}
    assert find_matching_getter(other_ep, endpoints) is None


def test_deep_state_loopback_verified_persistence() -> None:
    """Kiểm tra trường hợp CSDL thực sự bị biến đổi: PUT thành công và subsequent GET xác nhận role: admin."""
    mock_session = MagicMock()

    # Giả lập database ngầm
    db_state = {"username": "alice", "role": "user", "bio": "Initial bio"}

    def mock_request(method, url, json=None, headers=None, timeout=None):
        resp = MagicMock()
        if method == "PUT":
            # API cập nhật dữ liệu vào DB ngầm
            if json:
                db_state.update(json)
            resp.status_code = 200
            resp.json.return_value = {"status": "success", "message": "profile updated"}
        elif method == "GET":
            # API trả về dữ liệu thực tế trong DB
            resp.status_code = 200
            resp.json.return_value = dict(db_state)
        else:
            resp.status_code = 404
        return resp

    mock_session.request.side_effect = mock_request

    endpoints = [
        {
            "method": "PUT",
            "path": "/api/v1/profile",
            "parameters": [{"name": "bio", "location": "body", "type": "string"}],
        },
        {
            "method": "GET",
            "path": "/api/v1/profile",
            "parameters": [],
        },
    ]

    findings = execute_mass_assignment_scan(
        endpoints=endpoints,
        base_url="http://mock-bank.local",
        session=mock_session,
        deep_verify=True,
    )

    # Phải có finding CONFIRMED với bằng chứng [DEEP STATE LOOPBACK VERIFIED]
    assert len(findings) >= 1
    f = findings[0]
    assert f["confirmed"] is True
    assert f["confidence"] == 100
    assert "DEEP STATE LOOPBACK VERIFIED" in f["evidence"]
    assert f["severity"] == "critical"


def test_deep_state_suppresses_echo_only_false_positive() -> None:
    """Kiểm tra trường hợp tránh báo động giả: Server nhại lại role: admin nhưng GET kiểm tra thấy CSDL KHÔNG đổi."""
    mock_session = MagicMock()

    def mock_request(method, url, json=None, headers=None, timeout=None):
        resp = MagicMock()
        if method == "PUT":
            # Server chỉ echo lại json client gửi, nhưng KHÔNG lưu vào DB
            echo_resp = dict(json or {})
            echo_resp["id"] = 123
            resp.status_code = 200
            resp.json.return_value = echo_resp
        elif method == "GET":
            # GET kiểm tra trạng thái thực tế: role vẫn là 'user', không bị đổi thành 'admin'
            resp.status_code = 200
            resp.json.return_value = {"id": 123, "username": "alice", "role": "user"}
        else:
            resp.status_code = 404
        return resp

    mock_session.request.side_effect = mock_request

    endpoints = [
        {
            "method": "PUT",
            "path": "/api/v1/profile",
            "parameters": [{"name": "bio", "location": "body", "type": "string"}],
        },
        {
            "method": "GET",
            "path": "/api/v1/profile",
            "parameters": [],
        },
    ]

    findings = execute_mass_assignment_scan(
        endpoints=endpoints,
        base_url="http://mock-bank.local",
        session=mock_session,
        deep_verify=True,
    )

    # Lỗ hổng Mass Assignment confirmed không được kích hoạt báo động giả!
    # Thay vào đó chỉ ghi nhận dạng echo-only info để dev biết
    confirmed_findings = [f for f in findings if f["confirmed"] is True]
    assert len(confirmed_findings) == 0

    echo_findings = [f for f in findings if "ECHO ONLY" in f["evidence"]]
    assert len(echo_findings) >= 1
    assert echo_findings[0]["severity"] == "info"
    assert echo_findings[0]["confirmed"] is False


def test_live_seed_body_used_in_baseline() -> None:
    """Kiểm tra body seed từ lưu lượng HAR được dùng làm baseline, đảm bảo các trường DTO bắt buộc có mặt."""
    seed_body = {
        "citizen_id": "079201004567",
        "phone": "0901234567",
        "email": "real_user@fintech.vn",
        "account_type": "standard",
    }
    body = generate_baseline_body(parameters=[], seed_body=seed_body)
    assert body["citizen_id"] == "079201004567"
    assert body["email"] == "real_user@fintech.vn"
