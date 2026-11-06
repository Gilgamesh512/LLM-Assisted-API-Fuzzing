from __future__ import annotations

import io
import json
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

from core.baseline import compare_baseline, load_findings
from core.oracle import Signal, classify_one, is_server_leak, is_sql_error
from core.stateful_chain import ChainStep, StatefulContext, discover_crud_chains, execute_stateful_bola_scan
from fuzzer import RateLimiter, _send_fuzz_request, run_full_scan
from web_ui import app, scan_state


# ---------------------------------------------------------------------------
# 1. False Positive Reduction Tests
# ---------------------------------------------------------------------------

def test_false_positive_reduction_json_syntax_error():
    """Lỗi JSON syntax thông thường từ client 400 không được coi là lỗi SQL Injection."""
    finding = {
        "http_status": 400,
        "evidence": "HTTP 400; Response: {\"error\": \"Invalid JSON syntax error: unexpected token\"}",
        "confirmed": False,
    }
    c = classify_one(finding)
    assert c.signal is Signal.MISS
    assert not is_sql_error(finding["evidence"])


def test_false_positive_reduction_benign_exception_word():
    """Từ 'exception' trong phản hồi 200 hoặc 404 không được xem là rò rỉ stack trace."""
    finding_200 = {
        "http_status": 200,
        "evidence": "HTTP 200; Response: {\"status\": \"ok\", \"exception_handled\": true}",
        "confirmed": False,
    }
    c_200 = classify_one(finding_200)
    assert c_200.signal is Signal.MISS
    assert not is_server_leak(finding_200["evidence"], 200)


def test_genuine_sql_error_detected():
    """Lỗi cú pháp SQL thực thụ phải được phát hiện chính xác."""
    evidence = "HTTP 500; Response: ERROR: syntax error at or near 'WHERE' (PostgreSQL query failed)"
    assert is_sql_error(evidence)
    finding = {"http_status": 500, "evidence": evidence, "confirmed": False}
    c = classify_one(finding)
    assert c.signal is Signal.ANOMALY
    assert "lỗi SQL" in c.reason


# ---------------------------------------------------------------------------
# 2. Stateful Workflow Chaining & BOLA Tests
# ---------------------------------------------------------------------------

def test_discover_crud_chains():
    """Tự động phát hiện các cặp CRUD endpoints có liên kết trạng thái."""
    endpoints = [
        {"method": "post", "path": "/users/v1/register", "request_body": [{"name": "username"}]},
        {"method": "get", "path": "/users/v1/{username}"},
        {"method": "post", "path": "/api/orders"},
        {"method": "get", "path": "/api/orders/{id}"},
        {"method": "get", "path": "/health"},
    ]
    chains = discover_crud_chains(endpoints)
    assert len(chains) == 2

    # Chain 1: /users/v1/register -> /users/v1/{username}
    user_chain = next(c for c in chains if "username" in c["target_var"])
    assert user_chain["create_path"] == "/users/v1/register"
    assert user_chain["access_path"] == "/users/v1/{username}"

    # Chain 2: /api/orders -> /api/orders/{id}
    order_chain = next(c for c in chains if "id" in c["target_var"])
    assert order_chain["create_path"] == "/api/orders"
    assert order_chain["access_path"] == "/api/orders/{id}"


def test_execute_stateful_bola_scan_detects_unauthorized_access():
    """Mô phỏng User B truy cập được tài nguyên tạo bởi User A -> phát hiện BOLA/IDOR."""
    endpoints = [
        {"method": "post", "path": "/notes/v1", "parameters": [{"name": "title", "in": "body"}]},
        {"method": "get", "path": "/notes/v1/{id}"},
    ]

    mock_session = MagicMock()

    # Step 1: POST trả 201 với note id = "note-999"
    resp_create = MagicMock()
    resp_create.status_code = 201
    resp_create.json.return_value = {"id": "note-999", "title": "Secret Note"}

    # Step 2: GET /notes/v1/note-999 với User B token trả về 200 (BOLA)
    resp_access = MagicMock()
    resp_access.status_code = 200
    resp_access.json.return_value = {"id": "note-999", "title": "Secret Note"}

    mock_session.request.side_effect = [resp_create, resp_access]

    findings = execute_stateful_bola_scan(
        endpoints,
        base_url="http://mock-api.local",
        session=mock_session,
        primary_token="user-a-token",
        secondary_token="user-b-token",
    )

    assert len(findings) == 1
    f = findings[0]
    assert f["vuln_type"] == "BOLA"
    assert f["confirmed"] is True
    assert f["bola_detected"] is True
    assert f["severity"] == "critical"
    assert "STATEFUL BOLA CONFIRMED" in f["evidence"]


# ---------------------------------------------------------------------------
# 3. WAF Auto-Throttle & Network Retry Tests
# ---------------------------------------------------------------------------

def test_rate_limiter_throttle_up():
    """RateLimiter tự động tăng delay khi kích hoạt throttle_up."""
    limiter = RateLimiter(delay_ms=50.0)
    assert limiter.delay_sec == 0.05
    limiter.throttle_up(extra_delay_ms=200.0)
    assert round(limiter.delay_sec, 2) == 0.25


def test_send_fuzz_request_retries_on_waf_429():
    """_send_fuzz_request tự động thử lại và throttle delay khi gặp HTTP 429."""
    mock_session = MagicMock()

    resp_429 = MagicMock()
    resp_429.status_code = 429
    resp_429.text = "Too Many Requests - Rate limit exceeded"
    resp_429.headers = {"Retry-After": "0.01"}

    resp_200 = MagicMock()
    resp_200.status_code = 200
    resp_200.text = "OK"
    resp_200.headers = {}

    mock_session.request.side_effect = [resp_429, resp_200]
    limiter = RateLimiter(delay_ms=10.0)

    item = {
        "method": "GET",
        "endpoint": "/test",
        "target_param": "q",
        "param_location": "query",
        "payload_value": "test",
        "attack_type": "SQLi",
    }

    result = _send_fuzz_request(
        mock_session,
        base_url="http://test.local",
        item=item,
        rate_limiter=limiter,
        max_retries=2,
    )

    assert result["http_status"] == 200
    assert mock_session.request.call_count == 2
    # Delay tăng lên do throttle_up
    assert limiter.delay_sec > 0.01


# ---------------------------------------------------------------------------
# 4. Spec Chunking / Batching Tests
# ---------------------------------------------------------------------------

def test_spec_chunking_dry_run(tmp_path: Path):
    """Xử lý chia nhỏ đặc tả lớn thành nhiều batch khi chunk_size > 0."""
    # Tạo 25 endpoints giả lập
    endpoints = [
        {"path": f"/api/endpoint_{i}", "method": "get", "parameters": [{"name": "id", "in": "query"}]}
        for i in range(25)
    ]
    spec_file = tmp_path / "large_spec.json"
    spec_data = {
        "openapi": "3.0.0",
        "info": {"title": "Large API", "version": "1.0"},
        "paths": {
            f"/api/endpoint_{i}": {
                "get": {
                    "operationId": f"op_{i}",
                    "parameters": [{"name": "id", "in": "query", "schema": {"type": "string"}}],
                    "responses": {"200": {"description": "ok"}},
                }
            }
            for i in range(25)
        },
    }
    spec_file.write_text(json.dumps(spec_data), encoding="utf-8")

    mock_provider = MagicMock()
    mock_provider.name = "mock"
    mock_provider.model = "mock-model"
    # Mỗi lần gọi trả về 2 attack payloads
    mock_reply = json.dumps([
        {
            "method": "GET",
            "path": "/api/endpoint_0",
            "target_parameter": "id",
            "location": "query",
            "vulnerability_type": "SQLi",
            "payload_value": "' OR 1=1--",
            "rationale": "Test injection",
            "expected_indicator": "HTTP 500",
        }
    ])
    mock_provider.generate.return_value = {"reply": mock_reply, "usage": {"prompt_tokens": 100, "completion_tokens": 50}}

    with patch("fuzzer.get_provider", return_value=mock_provider):
        code = run_full_scan(
            str(spec_file),
            dry_run=True,
            out_dir=tmp_path / "results",
            chunk_size=10,  # 25 endpoints chia thành 3 chunks: 10, 10, 5
        )
        assert code == 0
        assert mock_provider.generate.call_count == 3


# ---------------------------------------------------------------------------
# 5. Adaptive Feedback Loop Tests
# ---------------------------------------------------------------------------

def test_adaptive_feedback_loop_multi_generation(tmp_path: Path):
    """Vòng lặp Adaptive Feedback Loop sinh thế hệ tiếp theo khi phát hiện anomaly."""
    spec_file = tmp_path / "spec.json"
    spec_data = {
        "openapi": "3.0.0",
        "info": {"title": "Test", "version": "1.0"},
        "paths": {
            "/api/login": {
                "post": {
                    "parameters": [{"name": "username", "in": "query", "schema": {"type": "string"}}],
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }
    spec_file.write_text(json.dumps(spec_data), encoding="utf-8")

    # Mock provider
    mock_provider = MagicMock()
    mock_provider.name = "mock"
    mock_provider.model = "mock-model"

    gen0_reply = json.dumps([
        {
            "method": "POST",
            "path": "/api/login",
            "target_parameter": "username",
            "location": "query",
            "vulnerability_type": "SQLi",
            "payload_value": "' OR '1'='1",
            "rationale": "Initial test",
            "expected_indicator": "HTTP 500",
        }
    ])
    gen1_reply = json.dumps([
        {
            "method": "POST",
            "path": "/api/login",
            "target_parameter": "username",
            "location": "query",
            "vulnerability_type": "SQLi",
            "payload_value": "' UNION SELECT NULL--",
            "rationale": "Refined test based on anomaly",
            "expected_indicator": "HTTP 200",
        }
    ])
    mock_provider.generate.side_effect = [
        {"reply": gen0_reply, "usage": {}},
        {"reply": gen1_reply, "usage": {}},
    ]

    # Mock HTTP session
    # Gen 0: trả 500 (anomaly) -> kích hoạt feedback prompt
    # Gen 1: trả 200 (matcher trúng / exploit)
    resp_gen0 = MagicMock()
    resp_gen0.status_code = 500
    resp_gen0.text = "Internal Server Error"
    resp_gen0.headers = {}

    resp_gen1 = MagicMock()
    resp_gen1.status_code = 200
    resp_gen1.text = "Welcome admin!"
    resp_gen1.headers = {}

    with patch("fuzzer.get_provider", return_value=mock_provider), \
         patch("requests.Session.request", side_effect=[resp_gen0, resp_gen1]):
        code = run_full_scan(
            str(spec_file),
            target_url="http://test.local",
            generations=2,
            out_dir=tmp_path / "results_adaptive",
            concurrency=1,
        )
        assert mock_provider.generate.call_count == 2
        # Manifest ghi nhận hoàn tất
        manifest_path = tmp_path / "results_adaptive" / "manifest.json"
        assert manifest_path.is_file()


# ---------------------------------------------------------------------------
# 6. Web UI Stop & Upload Tests
# ---------------------------------------------------------------------------

def test_web_ui_stop_endpoint():
    """Kiểm tra API dừng khẩn cấp (/api/scan/stop)."""
    client = app.test_client()
    resp = client.post("/api/scan/stop")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert scan_state["status"] == "stopped"


def test_web_ui_upload_spec(tmp_path: Path):
    """Kiểm tra API tải lên đặc tả API (/api/upload-spec)."""
    client = app.test_client()

    fake_spec_content = b'{"openapi": "3.0.0", "info": {"title": "Uploaded API"}}'
    data = {
        "file": (io.BytesIO(fake_spec_content), "uploaded_spec.json"),
    }
    resp = client.post("/api/upload-spec", data=data, content_type="multipart/form-data")
    assert resp.status_code == 200
    res_json = resp.get_json()
    assert res_json["ok"] is True
    assert "uploaded_spec.json" in res_json["filename"]
    assert Path(res_json["filepath"]).is_file()


# ---------------------------------------------------------------------------
# 7. Baseline Comparison Integration Test
# ---------------------------------------------------------------------------

def test_baseline_drift_comparison(tmp_path: Path):
    """Kiểm tra so sánh baseline drift phát hiện lỗ hổng mới và đã sửa."""
    previous = [
        {"target_app": "App1", "method": "GET", "endpoint": "/old_vuln", "vuln_type": "SQLi", "severity": "high"},
        {"target_app": "App1", "method": "POST", "endpoint": "/stay_vuln", "vuln_type": "BOLA", "severity": "critical"},
    ]
    current = [
        {"target_app": "App1", "method": "POST", "endpoint": "/stay_vuln", "vuln_type": "BOLA", "severity": "critical"},
        {"target_app": "App1", "method": "GET", "endpoint": "/new_vuln", "vuln_type": "SSRF", "severity": "high"},
    ]
    diff = compare_baseline(previous, current)
    assert len(diff.new) == 1
    assert diff.new[0]["endpoint"] == "/new_vuln"
    assert len(diff.resolved) == 1
    assert diff.resolved[0]["endpoint"] == "/old_vuln"
    assert len(diff.unchanged) == 1
    assert diff.unchanged[0]["endpoint"] == "/stay_vuln"
