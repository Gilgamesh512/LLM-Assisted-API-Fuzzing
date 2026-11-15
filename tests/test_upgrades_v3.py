"""
tests/test_upgrades_v3.py — Kiểm thử tự động toàn diện các tính năng nâng cấp V3:
- SARIF Fingerprinting & Deduplication
- JUnit XML Export cho CI/CD
- Postman Environment Variable Resolution
- CSRF Token Extraction & OAuth2 Refresh Token Grant
- Extended PII (CCCD, VN Phone, Credit Card) & Log Redaction
- Circuit Breaker Target Protection & Auto-Cleanup Rollback
- Centralized SQLite Audit History
- Webhook Notifier Dispatcher
- Cloud-Native Health Probes (/healthz, /readyz)
- Token-File & Checksums Generation
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

from core.analyzer import _convert_postman_to_openapi, load_postman_env
from core.auth_manager import TokenManager, extract_csrf_token
from core.db_history import get_recent_runs, init_db, save_scan_run
from core.junit_export import export_junit_xml
from core.notifier import send_webhook_notification
from core.safety import CircuitBreaker, execute_auto_cleanup
from core.sanitizer import DataMasker, mask_secrets_in_text
from core.sarif import convert_findings_to_sarif


def test_sarif_fingerprints_deterministic() -> None:
    findings = [
        {
            "target_app": "PaymentSvc",
            "method": "POST",
            "endpoint": "/api/v1/charge",
            "vuln_type": "SQLi",
            "severity": "critical",
            "target_parameter": "amount",
            "confirmed": True,
            "evidence": "syntax error near SELECT",
        }
    ]
    sarif = convert_findings_to_sarif(findings)
    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    fp = results[0].get("partialFingerprints", {})
    assert "primaryLocationLineHash" in fp
    assert len(fp["primaryLocationLineHash"]) == 64  # SHA256 length

    # Tính xác định: cùng finding sẽ cho ra cùng fingerprint
    sarif2 = convert_findings_to_sarif(findings)
    fp2 = sarif2["runs"][0]["results"][0]["partialFingerprints"]
    assert fp["primaryLocationLineHash"] == fp2["primaryLocationLineHash"]


def test_junit_xml_export_with_findings(tmp_path: Path) -> None:
    findings = [
        {
            "target_app": "CoreBanking",
            "method": "GET",
            "endpoint": "/accounts/{id}",
            "vuln_type": "BOLA",
            "severity": "critical",
            "confirmed": True,
            "evidence": "User A accessed User B account",
            "reproduction_curl": "curl -i http://target/accounts/99",
        }
    ]
    out_file = tmp_path / "junit.xml"
    xml_str = export_junit_xml(findings, target_name="CoreBanking", out_file=out_file)

    assert "<testsuites" in xml_str
    assert '<failure message="[CRITICAL] BOLA detected' in xml_str
    assert "User A accessed User B account" in xml_str
    assert out_file.is_file()


def test_junit_xml_export_clean_run() -> None:
    xml_str = export_junit_xml([], target_name="CleanApp")
    assert '<testcase classname="api.security.CleanApp" name="Clean-Run-No-Vulnerabilities"' in xml_str
    assert "failures=\"0\"" in xml_str


def test_postman_env_resolution(tmp_path: Path) -> None:
    env_file = tmp_path / "postman_env.json"
    env_file.write_text(
        json.dumps({
            "values": [
                {"key": "baseUrl", "value": "https://api.corp.vn"},
                {"key": "userId", "value": "12345"},
            ]
        }),
        encoding="utf-8",
    )
    env_dict = load_postman_env(env_file)
    assert env_dict.get("baseUrl") == "https://api.corp.vn"

    postman_data = {
        "info": {"title": "Test Collection"},
        "item": [
            {
                "request": {
                    "method": "GET",
                    "url": "{{baseUrl}}/users/{{userId}}/profile",
                }
            }
        ],
    }
    converted = _convert_postman_to_openapi(postman_data, env_vars=env_dict)
    assert "/users/12345/profile" in converted["paths"]


def test_csrf_token_extraction() -> None:
    # 1. Trích xuất từ Cookies
    resp = requests.Response()
    resp.cookies.set("csrf_token", "secret-csrf-token-123")
    assert extract_csrf_token(resp) == "secret-csrf-token-123"

    # 2. Trích xuất từ Headers
    resp2 = requests.Response()
    resp2.headers["X-CSRF-Token"] = "header-csrf-456"
    assert extract_csrf_token(resp2) == "header-csrf-456"

    # 3. Không có CSRF
    resp3 = requests.Response()
    assert extract_csrf_token(resp3) is None


def test_token_manager_refresh_token_grant() -> None:
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter()
    session.mount("https://", adapter)

    def mock_post(url, json=None, **kwargs):
        resp = requests.Response()
        resp.status_code = 200
        assert json.get("grant_type") == "refresh_token"
        assert json.get("refresh_token") == "old-refresh-token"
        resp._content = b'{"access_token": "new-jwt-access-token", "refresh_token": "new-refresh-token"}'
        return resp

    mgr = TokenManager(
        auth_type="refresh_token",
        refresh_url="https://auth.corp/oauth/token",
        refresh_token="old-refresh-token",
    )

    with patch.object(requests, "post", side_effect=mock_post):
        token = mgr.get_token()
        assert token == "new-jwt-access-token"
        assert mgr.refresh_token == "new-refresh-token"


def test_sanitizer_extended_pii() -> None:
    masker = DataMasker()
    # CCCD Việt Nam 12 số
    text_cccd = "Khách hàng có số CCCD là 079123456789 đăng ký tài khoản."
    masked_cccd = masker.mask_string(text_cccd)
    assert "079123456789" not in masked_cccd
    assert "09900000" in masked_cccd

    # Khôi phục unmask
    unmasked = masker.unmask_string(masked_cccd)
    assert unmasked == text_cccd

    # SĐT Việt Nam
    text_phone = "Liên hệ qua SĐT 0987654321 ngay."
    masked_phone = masker.mask_string(text_phone)
    assert "0987654321" not in masked_phone
    assert masker.unmask_string(masked_phone) == text_phone

    # Thẻ tín dụng Visa
    text_card = "Thanh toán bằng thẻ 4111111111111111 tại cổng."
    masked_card = masker.mask_string(text_card)
    assert "4111111111111111" not in masked_card
    assert masker.unmask_string(masked_card) == text_card


def test_mask_secrets_in_text_log() -> None:
    log_text = "Sending request with Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz and card 4111111111111111"
    redacted = mask_secrets_in_text(log_text)
    assert "eyJhbGci" not in redacted
    assert "[REDACTED_SECRET]" in redacted
    assert "[REDACTED_CARD]" in redacted


def test_circuit_breaker_tripping() -> None:
    breaker = CircuitBreaker(failure_threshold=3)
    assert not breaker.record_response(200)
    assert not breaker.record_response(503)
    assert not breaker.record_response(503)
    # Chưa đủ 3 lần
    assert not breaker.is_tripped

    # Lần thứ 3 mã 503 liên tiếp
    tripped = breaker.record_response(503)
    assert tripped is True
    assert breaker.is_tripped
    assert "503" in breaker.tripped_reason

    # Nếu có 200 trước đó thì reset
    breaker2 = CircuitBreaker(failure_threshold=3)
    breaker2.record_response(503)
    breaker2.record_response(200)  # reset
    breaker2.record_response(503)
    assert not breaker2.is_tripped


def test_auto_cleanup_execution(tmp_path: Path) -> None:
    manifest_file = tmp_path / "cleanup_manifest.json"
    manifest_file.write_text(
        json.dumps({
            "mutations": [
                {
                    "method": "POST",
                    "url": "http://api.target/users",
                    "identifier": "999",
                }
            ]
        }),
        encoding="utf-8",
    )

    mock_session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 204
    mock_session.delete.return_value = mock_resp

    res = execute_auto_cleanup(manifest_file, session=mock_session)
    assert res["status"] == "completed"
    assert res["cleaned_count"] == 1
    mock_session.delete.assert_called_once_with(
        "http://api.target/users/999",
        headers={},
        verify=True,
        timeout=10.0,
    )


def test_db_history_crud(tmp_path: Path) -> None:
    db_file = tmp_path / "test_history.db"
    conn = init_db(db_file)
    conn.close()

    run_data = {
        "run_id": "run-test-001",
        "target_name": "TestSvc",
        "target_url": "http://localhost:8000",
        "provider": "gemini",
        "model": "gemini-2.5-flash",
        "gate_status": "PASS",
        "compliance_score": 95.0,
        "critical_count": 0,
        "high_count": 1,
    }
    findings = [
        {
            "vuln_type": "SQLi",
            "severity": "high",
            "method": "GET",
            "endpoint": "/search",
            "target_parameter": "q",
            "confirmed": True,
            "evidence": "SQL error",
        }
    ]
    save_scan_run(run_data, findings, db_path=db_file)

    runs = get_recent_runs(limit=5, db_path=db_file)
    assert len(runs) == 1
    assert runs[0]["run_id"] == "run-test-001"
    assert runs[0]["compliance_score"] == 95.0


def test_send_webhook_notification() -> None:
    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        summary = {
            "run_id": "test-123",
            "target_app": "OrderService",
            "total_findings": 2,
            "gate_status": "FAIL",
            "compliance_score": 80,
        }
        res = send_webhook_notification("https://hooks.slack.com/services/xxx", summary)
        assert res is True
        assert mock_urlopen.called


def test_web_ui_healthz_and_readyz() -> None:
    from web_ui import app
    client = app.test_client()

    resp_h = client.get("/healthz")
    assert resp_h.status_code == 200
    data_h = resp_h.get_json()
    assert data_h["status"] == "healthy"
    assert "uptime_seconds" in data_h

    resp_r = client.get("/readyz")
    assert resp_r.status_code == 200
    data_r = resp_r.get_json()
    assert "ready" in data_r
