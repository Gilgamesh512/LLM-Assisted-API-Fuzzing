"""
tests/test_tampering.py — Unit & Integration tests for Parameter Tampering (Mass Assignment) & Verb Tampering.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

from core.tampering import (
    check_mass_assignment_reflection,
    execute_mass_assignment_scan,
    execute_verb_tampering_scan,
    generate_baseline_body,
    resolve_endpoint_url,
)
from fuzzer import main


def test_generate_baseline_body() -> None:
    parameters = [
        {"name": "user.email", "type": "string", "location": "body"},
        {"name": "user.age", "type": "integer", "location": "body"},
        {"name": "is_active", "type": "boolean", "location": "body"},
        {"name": "tags", "type": "array", "location": "body"},
        {"name": "limit", "type": "integer", "location": "query"},  # should be ignored
    ]
    body = generate_baseline_body(parameters)
    assert body["email"] == "test@example.com"
    assert body["age"] == 1
    assert body["is_active"] is False
    assert body["tags"] == ["test"]
    assert "limit" not in body


def test_resolve_endpoint_url() -> None:
    url = resolve_endpoint_url("http://api.local/v1", "/users/{user_id}/orders/{order_id}")
    assert url == "http://api.local/v1/users/1/orders/1"


def test_check_mass_assignment_reflection() -> None:
    # 1. Trực tiếp trong root dict
    probe = {"is_admin": True}
    data = {"id": 123, "username": "alice", "is_admin": True}
    reflected, msg = check_mass_assignment_reflection(probe, data)
    assert reflected is True
    assert "is_admin" in msg

    # 2. Lồng trong object con
    probe_nested = {"role": "admin"}
    data_nested = {"status": "success", "user": {"id": 1, "role": "admin"}}
    reflected, msg = check_mass_assignment_reflection(probe_nested, data_nested)
    assert reflected is True
    assert "role" in msg

    # 3. Lồng trong array of objects
    probe_array = {"plan": "enterprise"}
    data_array = [{"plan": "basic"}, {"plan": "enterprise"}]
    reflected, msg = check_mass_assignment_reflection(probe_array, data_array)
    assert reflected is True

    # 4. Không phản hồi (không dính)
    data_safe = {"status": "success", "user": {"id": 1, "role": "user"}}
    reflected, msg = check_mass_assignment_reflection(probe_nested, data_safe)
    assert reflected is False


def test_execute_mass_assignment_scan_confirmed() -> None:
    mock_session = MagicMock()

    def mock_request(method, url, json=None, headers=None, timeout=None):
        resp = MagicMock()
        # Giả lập server dính Mass Assignment: nếu gửi role: admin hoặc is_admin: True, server nhận và phản hồi lại
        if json and (json.get("role") == "admin" or json.get("is_admin") is True):
            resp.status_code = 200
            resp.json.return_value = {"id": 5, "username": "fuzz", "role": "admin", "is_admin": True}
        else:
            resp.status_code = 400
            resp.json.return_value = {"error": "bad request"}
        return resp

    mock_session.request.side_effect = mock_request

    endpoints = [
        {
            "method": "POST",
            "path": "/api/users/register",
            "parameters": [
                {"name": "username", "type": "string", "location": "body"},
                {"name": "password", "type": "string", "location": "body"},
            ],
            "authentication": False,
        }
    ]

    findings = execute_mass_assignment_scan(
        endpoints=endpoints,
        base_url="http://mock-api.local",
        session=mock_session,
        target_name="TestApp",
    )

    assert len(findings) >= 1
    f = findings[0]
    assert f["vuln_type"] == "Mass Assignment"
    assert f["confirmed"] is True
    assert f["severity"] == "critical"
    assert f["endpoint"] == "/api/users/register"


def test_execute_mass_assignment_scan_secure() -> None:
    mock_session = MagicMock()

    def mock_request(method, url, json=None, headers=None, timeout=None):
        resp = MagicMock()
        # Server an toàn: loại bỏ các trường lạ, chỉ trả về user bình thường
        resp.status_code = 200
        resp.json.return_value = {"id": 5, "username": "fuzz", "role": "guest"}
        return resp

    mock_session.request.side_effect = mock_request

    endpoints = [
        {
            "method": "PUT",
            "path": "/api/profile",
            "parameters": [{"name": "bio", "type": "string", "location": "body"}],
        }
    ]

    findings = execute_mass_assignment_scan(
        endpoints=endpoints,
        base_url="http://mock-api.local",
        session=mock_session,
    )

    # Không có finding nào confirmed vì server không phản hồi thuộc tính nhạy cảm
    assert len(findings) == 0


def test_execute_verb_tampering_trace_detected() -> None:
    mock_session = MagicMock()

    def mock_request(method, url, headers=None, json=None, timeout=None):
        resp = MagicMock()
        if method == "TRACE":
            resp.status_code = 200
            resp.text = "TRACE /api/v1/resource HTTP/1.1\nHost: mock-api.local\nCookie: session=secret123"
        else:
            resp.status_code = 405
            resp.text = "Method Not Allowed"
        return resp

    mock_session.request.side_effect = mock_request

    endpoints = [{"method": "GET", "path": "/api/v1/resource", "authentication": False}]

    findings = execute_verb_tampering_scan(
        endpoints=endpoints,
        base_url="http://mock-api.local",
        session=mock_session,
    )

    assert any(f["vuln_type"] == "Insecure HTTP Methods (XST)" for f in findings)


def test_execute_verb_tampering_auth_bypass_head() -> None:
    mock_session = MagicMock()

    def mock_request(method, url, headers=None, json=None, timeout=None):
        resp = MagicMock()
        # Endpoint yêu cầu auth: nếu gửi HEAD không header auth, server bị lỗi cấu hình trả về 200 OK
        if method == "HEAD":
            resp.status_code = 200
        elif method == "TRACE":
            resp.status_code = 405
            resp.text = ""
        else:
            resp.status_code = 401
            resp.text = "Unauthorized"
        return resp

    mock_session.request.side_effect = mock_request

    endpoints = [{"method": "GET", "path": "/api/admin/dashboard", "authentication": True}]

    findings = execute_verb_tampering_scan(
        endpoints=endpoints,
        base_url="http://mock-api.local",
        session=mock_session,
    )

    head_findings = [f for f in findings if f["vuln_type"] == "HTTP Verb Tampering (Auth Bypass)"]
    assert len(head_findings) == 1
    assert head_findings[0]["method"] == "HEAD"
    assert head_findings[0]["confirmed"] is True


def test_execute_verb_tampering_method_override_tunneling() -> None:
    mock_session = MagicMock()

    def mock_request(method, url, headers=None, json=None, timeout=None):
        resp = MagicMock()
        if headers and headers.get("X-HTTP-Method-Override") == "DELETE":
            resp.status_code = 204  # Backend xử lý delete qua header override!
        else:
            resp.status_code = 200
            resp.text = "OK"
        return resp

    mock_session.request.side_effect = mock_request

    endpoints = [{"method": "POST", "path": "/api/users/5", "authentication": False}]

    findings = execute_verb_tampering_scan(
        endpoints=endpoints,
        base_url="http://mock-api.local",
        session=mock_session,
    )

    tunnel_findings = [f for f in findings if "Tunneling" in f["vuln_type"]]
    assert len(tunnel_findings) == 1
    assert tunnel_findings[0]["http_status"] == 204


class FakeProvider:
    name = "gemini"
    model = "test-model"

    def generate(self, prompt, *, system_prompt=None, context=None):
        return {
            "reply": json.dumps([
                {
                    "method": "POST",
                    "path": "/users/v1/register",
                    "target_parameter": "username",
                    "location": "body",
                    "vulnerability_type": "Other",
                    "payload_value": "admin",
                    "rationale": "Mass assignment check",
                    "expected_indicator": "HTTP 200",
                }
            ])
        }

    def repair(self, prompt, *, system_prompt=None, context=None):
        return self.generate(prompt)


def test_cli_fuzzer_logic_scan_dry_run(tmp_path) -> None:
    from unittest.mock import patch
    out_dir = tmp_path / "logic_scan_results"
    with patch("fuzzer.get_provider", return_value=FakeProvider()):
        rc = main([
            "scan",
            "dataset/vampi_openapi.json",
            "--provider", "gemini",
            "--dry-run",
            "--logic-scan",
            "--out-dir", str(out_dir),
        ])
    assert rc == 0
    assert (out_dir / "findings_summary.sarif").is_file()
    assert (out_dir / "report.html").is_file()
