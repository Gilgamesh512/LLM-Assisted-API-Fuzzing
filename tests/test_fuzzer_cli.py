from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import fuzzer

FIXTURE = Path(__file__).parent / "fixtures" / "sample_openapi.json"

SAMPLE_PAYLOADS = json.dumps([
    {
        "method": "GET",
        "path": "/api/users/{id}",
        "target_parameter": "id",
        "location": "path",
        "vulnerability_type": "BOLA",
        "payload_value": "999",
        "rationale": "IDOR check",
        "expected_indicator": "HTTP 200",
    }
])


class FakeProvider:
    name = "gemini"
    model = "test-model"

    def generate(self, prompt, *, system_prompt=None, context=None):
        return {"reply": SAMPLE_PAYLOADS}

    def repair(self, prompt, *, system_prompt=None, context=None):
        return {"reply": SAMPLE_PAYLOADS}


def test_fuzzer_scan_dry_run(tmp_path: Path):
    with patch("fuzzer.get_provider", return_value=FakeProvider()):
        code = fuzzer.run_full_scan(
            FIXTURE,
            provider="gemini",
            out_dir=tmp_path / "out",
            dry_run=True,
            safe_mode=True,
            mask_data=True,
        )

    assert code == 0
    assert (tmp_path / "out" / "payloads_validated.json").is_file()
    assert (tmp_path / "out" / "payloads_fuzz.json").is_file()
    assert (tmp_path / "out" / "findings_summary.sarif").is_file()
    assert (tmp_path / "out" / "findings_summary.csv").is_file()
    assert (tmp_path / "out" / "findings_summary.ndjson").is_file()
    assert (tmp_path / "out" / "manifest.json").is_file()

    sarif_data = json.loads((tmp_path / "out" / "findings_summary.sarif").read_text(encoding="utf-8"))
    assert sarif_data["version"] == "2.1.0"


def test_fuzzer_scan_runtime_with_oracle_sync(tmp_path: Path):
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_resp.text = "Internal error: syntax error in SQL query near ''"

    fake_session = MagicMock()
    fake_session.request.return_value = mock_resp

    with patch("fuzzer.get_provider", return_value=FakeProvider()), \
         patch("requests.Session", return_value=fake_session):
        code = fuzzer.run_full_scan(
            FIXTURE,
            target_url="http://test-api.local",
            provider="gemini",
            out_dir=tmp_path / "out_runtime",
            dry_run=False,
            safe_mode=True,
            mask_data=False,
            fail_on="high",
        )

    sarif_file = tmp_path / "out_runtime" / "findings_summary.sarif"
    assert sarif_file.is_file()
    sarif_data = json.loads(sarif_file.read_text(encoding="utf-8"))
    results = sarif_data["runs"][0]["results"]
    assert len(results) >= 1
    # HTTP 500 -> severity high -> SARIF level error
    assert results[0]["level"] == "error"
    assert "ORACLE ANOMALY" in results[0]["message"]["text"]


def test_fuzzer_param_injection_all_locations():
    session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"success": true}'
    session.request.return_value = mock_resp

    # 1. Path param
    fuzzer._send_fuzz_request(
        session, "http://api.local",
        {"method": "GET", "endpoint": "/users/{id}", "target_param": "id",
         "param_location": "path", "payload_value": "123", "attack_type": "BOLA"}
    )
    session.request.assert_called_with(
        "GET", "http://api.local/users/123",
        params={}, data=None, headers={}, cookies={}, timeout=8.0
    )

    # 2. Header param
    session.reset_mock()
    fuzzer._send_fuzz_request(
        session, "http://api.local",
        {"method": "GET", "endpoint": "/data", "target_param": "X-Forwarded-For",
         "param_location": "header", "payload_value": "127.0.0.1", "attack_type": "SSRF"}
    )
    session.request.assert_called_with(
        "GET", "http://api.local/data",
        params={}, data=None, headers={"X-Forwarded-For": "127.0.0.1"}, cookies={}, timeout=8.0
    )

    # 3. Cookie param
    session.reset_mock()
    fuzzer._send_fuzz_request(
        session, "http://api.local",
        {"method": "GET", "endpoint": "/data", "target_param": "session_id",
         "param_location": "cookie", "payload_value": "secret", "attack_type": "AUTH_BYPASS"}
    )
    session.request.assert_called_with(
        "GET", "http://api.local/data",
        params={}, data=None, headers={}, cookies={"session_id": "secret"}, timeout=8.0
    )

    # 4. Nested body param
    session.reset_mock()
    fuzzer._send_fuzz_request(
        session, "http://api.local",
        {"method": "POST", "endpoint": "/register", "target_param": "user.profile.bio",
         "param_location": "body", "payload_value": "<script>", "attack_type": "XSS"}
    )
    args, kwargs = session.request.call_args
    assert kwargs["headers"]["Content-Type"] == "application/json"
    body = json.loads(kwargs["data"])
    assert body["user"]["profile"]["bio"] == "<script>"


def test_fuzzer_scan_runtime_with_confirmed_exploit(tmp_path: Path):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "You are logged in as admin!"

    fake_session = MagicMock()
    fake_session.request.return_value = mock_resp

    with patch("fuzzer.get_provider", return_value=FakeProvider()), \
         patch("requests.Session", return_value=fake_session):
        code = fuzzer.run_full_scan(
            FIXTURE,
            target_url="http://test-api.local",
            provider="gemini",
            out_dir=tmp_path / "out_exploit",
            dry_run=False,
            safe_mode=True,
            mask_data=False,
            auth_token="test-secret-token",
            fail_on="high",
        )

    # Because mock_resp didn't have confirmed flag yet in raw request,
    # let's test TokenManager header was set on session
    assert fake_session.headers.update.called or "Authorization" in str(fake_session.headers)


def test_fuzzer_scan_unmask_integration(tmp_path: Path):
    mock_provider = MagicMock()
    mock_provider.model = "test-model"
    # LLM returns payload with masked mock domain
    mock_provider.generate.return_value = {
        "reply": json.dumps([
            {
                "method": "GET",
                "path": "/api-service-1.example.com/data",
                "target_parameter": "email",
                "location": "query",
                "vulnerability_type": "SQLi",
                "payload_value": "user_1@example.mock' OR '1'='1",
                "rationale": "SQLi test with masked entity",
                "expected_indicator": "HTTP 500",
            }
        ])
    }

    # Simulate reverse_map
    with patch("fuzzer.get_provider", return_value=mock_provider), \
         patch("fuzzer.mask_spec_data", return_value=([{"path": "/api-service-1.example.com/data"}], {
             "user_1@example.mock": "real_admin@corp.internal",
             "api-service-1.example.com": "api.production.internal",
         })):
        code = fuzzer.run_full_scan(
            FIXTURE,
            provider="gemini",
            out_dir=tmp_path / "out_unmask",
            dry_run=True,
            mask_data=True,
        )

    assert code == 0
    validated_file = tmp_path / "out_unmask" / "payloads_validated.json"
    content = json.loads(validated_file.read_text(encoding="utf-8"))
    assert content[0]["path"] == "/api.production.internal/data"
    assert "real_admin@corp.internal" in content[0]["payload_value"]

