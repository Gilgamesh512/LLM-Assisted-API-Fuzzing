from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

from core.analyzer import (
    COMMON_SPEC_PATHS,
    load_spec,
    parse_raw_endpoints,
    probe_openapi_spec,
)
from fuzzer import RateLimiter, ScopeGuard, _parse_headers, main, run_full_scan


def test_scope_guard_in_scope_and_out_of_scope():
    guard = ScopeGuard("http://192.168.1.100:8000", extra_allowed=["api.corp.local"])

    # Cùng host & port -> in scope
    assert guard.is_in_scope("http://192.168.1.100:8000/api/v1/users")
    # Cùng host khác port hoặc path
    assert guard.is_in_scope("http://192.168.1.100/login")
    # Extra allowed host
    assert guard.is_in_scope("https://api.corp.local/v2/orders")
    # Host thứ 3 ngoài luồng -> out of scope
    assert not guard.is_in_scope("https://evil.external.com/steal")
    assert not guard.is_in_scope("https://api.stripe.com/v1/charges")


def test_rate_limiter_and_delay():
    limiter = RateLimiter(delay_ms=20.0, max_rps=50.0)
    assert limiter.delay_sec == 0.02
    assert limiter.min_interval == 0.02
    # Gọi wait không phát sinh lỗi
    limiter.wait()


def test_parse_headers():
    raw_headers = [
        "X-API-Key: secret_token_123",
        "X-Tenant-Id: corp_vn",
        "Authorization: Bearer test",
    ]
    parsed = _parse_headers(raw_headers)
    assert parsed["X-API-Key"] == "secret_token_123"
    assert parsed["X-Tenant-Id"] == "corp_vn"
    assert parsed["Authorization"] == "Bearer test"
    assert _parse_headers(None) == {}


def test_parse_raw_endpoints_from_txt(tmp_path: Path):
    txt_file = tmp_path / "raw_endpoints.txt"
    txt_file.write_text(
        """
        # Danh sách API doanh nghiệp không có Swagger
        GET /api/v1/customers
        GET /api/v1/customers/{customerId}
        POST /api/v1/transactions
        DELETE /api/v1/customers/{customerId}
        """,
        encoding="utf-8",
    )
    endpoints = parse_raw_endpoints(txt_file)
    assert len(endpoints) == 4
    paths = [e["path"] for e in endpoints]
    assert "/api/v1/customers" in paths
    assert "/api/v1/customers/{customerId}" in paths

    # Kiểm tra tự động phát hiện path param
    item_by_id = next(e for e in endpoints if e["path"] == "/api/v1/customers/{customerId}" and e["method"] == "GET")
    assert any(p["name"] == "customerId" and p["in"] == "path" for p in item_by_id["parameters"])


def test_parse_raw_endpoints_from_json():
    json_raw = [
        {"method": "GET", "path": "/api/v2/orders/{id}", "parameters": [{"name": "id", "in": "path"}]},
        {"method": "POST", "path": "/api/v2/checkout"},
    ]
    endpoints = parse_raw_endpoints(json.dumps(json_raw))
    assert len(endpoints) == 2
    assert endpoints[0]["path"] == "/api/v2/checkout"
    assert endpoints[1]["path"] == "/api/v2/orders/{id}"


def test_convert_postman_collection(tmp_path: Path):
    postman_data = {
        "info": {"name": "Corporate Order API", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
        "item": [
            {
                "name": "Get Account Profile",
                "request": {
                    "method": "GET",
                    "url": {
                        "raw": "https://api.enterprise.com/v1/accounts/{{accountId}}?filter=active",
                        "path": ["v1", "accounts", "{{accountId}}"],
                        "query": [{"key": "filter", "value": "active"}],
                    },
                },
            },
            {
                "name": "Create Order",
                "request": {
                    "method": "POST",
                    "url": "https://api.enterprise.com/v1/orders",
                    "body": {
                        "mode": "raw",
                        "raw": '{"amount": 1000, "currency": "VND"}',
                    },
                },
            },
        ],
    }
    p_file = tmp_path / "postman_collection.json"
    p_file.write_text(json.dumps(postman_data), encoding="utf-8")

    spec = load_spec(p_file)
    assert "paths" in spec
    assert "/v1/accounts/{accountId}" in spec["paths"]
    assert "get" in spec["paths"]["/v1/accounts/{accountId}"]
    assert "/v1/orders" in spec["paths"]
    assert "post" in spec["paths"]["/v1/orders"]


def test_probe_openapi_spec_mocked():
    sample_spec = {
        "openapi": "3.0.1",
        "info": {"title": "Internal Microservice", "version": "1.0"},
        "paths": {"/health": {"get": {"responses": {"200": {"description": "ok"}}}}},
    }

    def mock_get(url, **kwargs):
        resp = MagicMock()
        if url.endswith("/v3/api-docs"):
            resp.status_code = 200
            resp.content = json.dumps(sample_spec).encode("utf-8")
            resp.text = json.dumps(sample_spec)
        else:
            resp.status_code = 404
            resp.content = b""
            resp.text = ""
        return resp

    with patch("requests.get", side_effect=mock_get):
        spec, matched = probe_openapi_spec("http://10.0.0.15:8080")
        assert spec is not None
        assert matched == "http://10.0.0.15:8080/v3/api-docs"
        assert "/health" in spec["paths"]


def test_load_spec_remote_url_mocked():
    sample_spec = {
        "openapi": "3.0.0",
        "info": {"title": "Remote Gateway API", "version": "2.0"},
        "paths": {"/api/items": {"get": {}}},
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = json.dumps(sample_spec)

    with patch("requests.get", return_value=mock_resp):
        spec = load_spec("https://gateway.company.com/openapi.json", insecure=True, proxy="http://127.0.0.1:8080")
        assert spec["info"]["title"] == "Remote Gateway API"
        assert "/api/items" in spec["paths"]


def test_fuzzer_cli_enterprise_scan_dry_run(tmp_path: Path):
    txt_file = tmp_path / "custom_endpoints.txt"
    txt_file.write_text("GET /api/v1/users/{id}\nPOST /api/v1/users", encoding="utf-8")

    out_dir = tmp_path / "scan_out"

    mock_reply = json.dumps([
        {
            "method": "GET",
            "path": "/api/v1/users/{id}",
            "target_parameter": "id",
            "location": "path",
            "vulnerability_type": "BOLA",
            "payload_value": "00000000-0000-0000-0000-000000000000",
            "rationale": "Enterprise UUID IDOR testing",
            "expected_indicator": "HTTP 200",
        }
    ])

    mock_provider = MagicMock()
    mock_provider.name = "local"
    mock_provider.model = "default"
    mock_provider.generate.return_value = {"reply": mock_reply, "usage": {"tokens": 100}}

    with patch("fuzzer.get_provider", return_value=mock_provider):
        code = main([
            "scan",
            str(txt_file),
            "-u", "https://staging.corp.internal:8443",
            "--target-name", "EnterpriseUserSvc",
            "--provider", "local",
            "--out-dir", str(out_dir),
            "--insecure",
            "--dry-run",
        ])
    assert code == 0
    sarif_file = out_dir / "findings_summary.sarif"
    manifest_file = out_dir / "manifest.json"
    assert sarif_file.is_file()
    assert manifest_file.is_file()

    manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))
    assert manifest_data["target"]["name"] == "EnterpriseUserSvc"
