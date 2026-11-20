"""Test suite for features ported from Schemathesis:
- token_verifier (RFC 7519 JWT Auditor)
- callback_verifier (Local in-memory SSRF listener)
- hmac_sealer (Tamper-evident HMAC-SHA256 sealing)
- graphql_engine (GraphQL introspection & schema summary)
"""

import json
import time
import urllib.request
from unittest.mock import MagicMock, patch
import requests
import pytest

from core.token_verifier import TokenVerifier, b64url_encode
from core.callback_verifier import LocalCallbackListener, CallbackVerifier
from core.hmac_sealer import (
    compute_hmac_seal,
    verify_hmac_seal,
    seal_html_report,
    verify_sealed_html_report,
)
from core.graphql_engine import (
    parse_graphql_schema,
    build_nested_query_probe,
    audit_graphql_endpoint,
)


def _create_dummy_jwt(alg="HS256", exp_offset=3600, role="user"):
    header = {"alg": alg, "typ": "JWT"}
    payload = {"sub": "123456", "name": "John Doe", "role": role, "exp": int(time.time()) + exp_offset}
    h_str = b64url_encode(json.dumps(header).encode("utf-8"))
    p_str = b64url_encode(json.dumps(payload).encode("utf-8"))
    sig_str = "dummy_signature_bytes"
    return f"{h_str}.{p_str}.{sig_str}"


def test_token_verifier_probes():
    valid_jwt = _create_dummy_jwt()
    inspection = TokenVerifier.inspect_token(valid_jwt)
    assert inspection is not None
    assert inspection.algorithm == "HS256"
    assert inspection.payload["role"] == "user"
    assert not inspection.is_expired

    probes = TokenVerifier.generate_verification_probes(valid_jwt)
    assert "alg_none" in probes
    assert "stripped_signature" in probes
    assert "expired_claim" in probes

    # Verify alg_none probe has alg: none
    alg_none_token = probes["alg_none"]
    p_inspect = TokenVerifier.inspect_token(alg_none_token + "dummy_sig")
    assert p_inspect.header.get("alg") == "none"

    # Verify stripped signature ends with dot and empty signature
    assert probes["stripped_signature"].endswith(".")


def test_token_verifier_audit_detects_alg_none():
    valid_jwt = _create_dummy_jwt()

    def mock_requests_req(method, url, headers=None, **kwargs):
        resp = MagicMock()
        auth = (headers or {}).get("Authorization", "")
        if not auth:
            # Baseline không có auth trả về 401
            resp.status_code = 401
        else:
            inspection = TokenVerifier.inspect_token(auth)
            # Server dính lỗ hổng chấp nhận token alg: none
            if inspection and str(inspection.header.get("alg")).lower() == "none":
                resp.status_code = 200
            else:
                resp.status_code = 401
        return resp

    with patch("core.token_verifier.requests.request", side_effect=mock_requests_req):
        findings = TokenVerifier.audit_endpoint(
            base_url="http://localhost:5000",
            endpoint="/api/users/{username}",
            method="GET",
            valid_auth_header=valid_jwt,
            custom_headers={"X-Tenant": "test"},
            target_name="TestApp",
        )
        assert len(findings) >= 1
        f = findings[0]
        assert f["tool"] == "token_verifier"
        assert f["target_app"] == "TestApp"
        assert "JWT Algorithm None Bypass" in f["vulnerability"]
        assert "curl" in f["reproduction"]
        assert "X-Tenant" in f["reproduction"]["headers"]


def test_callback_listener_loopback():
    listener = LocalCallbackListener(host="127.0.0.1", port=0)
    base_url = listener.start()
    try:
        assert listener.port > 0
        token = "test-canary-ssrf-123"
        resp = requests.get(f"{base_url}/{token}", timeout=2.0)
        assert resp.status_code == 200
        assert resp.headers.get("X-SSRF-Canary") == "Captured"

        time.sleep(0.1)
        assert listener.has_hit(token)
        hit = listener.get_hit(token)
        assert hit is not None
        assert hit.path == f"/{token}"
    finally:
        listener.stop()


def test_callback_verifier_audit_detects_ssrf():
    listener = LocalCallbackListener(host="127.0.0.1", port=0)
    listener.start()

    def mock_requests_get(url, params=None, headers=None, **kwargs):
        # Giả lập target server gọi ngược về callback URL trong param qua urllib để tránh đụng mock
        if params and "url" in params:
            callback_url = params["url"]
            try:
                urllib.request.urlopen(callback_url, timeout=1.0)
            except Exception:
                pass
        resp = MagicMock()
        resp.status_code = 200
        return resp

    try:
        with patch("core.callback_verifier.requests.get", side_effect=mock_requests_get):
            findings = CallbackVerifier.audit_endpoint_ssrf(
                base_url="http://api.local",
                endpoint="/api/fetch/{doc_id}",
                method="GET",
                listener=listener,
                candidate_params=["url"],
                target_name="TestApp",
            )
            assert len(findings) == 1
            f = findings[0]
            assert f["tool"] == "callback_verifier"
            assert f["vulnerability"] == "Server-Side Request Forgery (SSRF)"
            assert f["confirmed"] is True
            assert "curl" in f["reproduction"]
    finally:
        listener.stop()


def test_hmac_sealer():
    content = "<html><body><h1>Security Audit Report</h1></body></html>"
    sig = compute_hmac_seal(content, secret_key="test-key")
    assert len(sig) == 64
    assert verify_hmac_seal(content, sig, secret_key="test-key")
    assert not verify_hmac_seal(content + "tampered", sig, secret_key="test-key")

    sealed_html = seal_html_report(content, secret_key="test-key")
    assert "Tamper-Evident Security Audit Seal" in sealed_html
    assert sig in sealed_html

    # Test tự động bóc tách và xác minh báo cáo đã niêm phong
    assert verify_sealed_html_report(sealed_html, secret_key="test-key") is True
    # Test phát hiện giả mạo trên file đã niêm phong
    tampered_sealed = sealed_html.replace("Security Audit Report", "Faked Report")
    assert verify_sealed_html_report(tampered_sealed, secret_key="test-key") is False


def test_graphql_engine_parsing():
    dummy_introspection = {
        "queryType": {"name": "Query"},
        "mutationType": {"name": "Mutation"},
        "types": [
            {
                "name": "Query",
                "fields": [
                    {
                        "name": "getUser",
                        "args": [{"name": "id", "type": {"name": "ID"}}],
                        "type": {"name": "User"},
                    }
                ],
            },
            {
                "name": "Mutation",
                "fields": [
                    {
                        "name": "updateRole",
                        "args": [
                            {"name": "id", "type": {"name": "ID"}},
                            {"name": "role", "type": {"name": "String"}},
                        ],
                        "type": {"name": "User"},
                    }
                ],
            },
        ],
    }
    summary = parse_graphql_schema(dummy_introspection)
    assert len(summary.queries) == 1
    assert summary.queries[0].name == "getUser"
    assert len(summary.mutations) == 1
    assert summary.mutations[0].name == "updateRole"

    context_str = summary.to_llm_context()
    assert "getUser" in context_str
    assert "updateRole" in context_str

    nested_probe = build_nested_query_probe("user", "profile", depth=3)
    assert "query DeepProbe" in nested_probe
    assert "profile { profile { profile" in nested_probe


def test_audit_graphql_endpoint_findings():
    dummy_schema = {
        "queryType": {"name": "Query"},
        "mutationType": {"name": "Mutation"},
        "types": [
            {
                "name": "Query",
                "fields": [
                    {"name": "systemInfo", "args": [], "type": {"name": "String"}}
                ],
            }
        ],
    }

    def mock_post(url, json=None, headers=None, **kwargs):
        resp = MagicMock()
        if json and "IntrospectionQuery" in json.get("query", ""):
            resp.status_code = 200
            resp.json.return_value = {"data": {"__schema": dummy_schema}}
        elif json and "DeepProbe" in json.get("query", ""):
            resp.status_code = 200
            resp.text = '{"data": {"systemInfo": "ok"}}'
        else:
            resp.status_code = 400
        return resp

    with patch("core.graphql_engine.requests.post", side_effect=mock_post):
        findings, summary = audit_graphql_endpoint(
            "http://localhost:5013/graphql",
            target_name="DVGA",
        )
        assert summary is not None
        assert len(findings) == 2
        f_types = [f["vulnerability"] for f in findings]
        assert "GraphQL Introspection Exposed" in f_types
        assert "GraphQL Query Depth Limit Missing" in f_types
        for f in findings:
            assert f["tool"] == "graphql_engine"
            assert "curl" in f["reproduction"]


def test_jwt_offline_cracking():
    from core.token_verifier import crack_hs256_secret, sign_forged_hs256_token
    token = sign_forged_hs256_token({"alg": "HS256"}, {"sub": "123", "role": "user"}, "secret")
    assert crack_hs256_secret(token) == "secret"

    # Offline audit findings
    offline_hits = TokenVerifier.audit_token_offline(token, target_name="TestApp")
    assert len(offline_hits) == 1
    assert offline_hits[0]["vulnerability"] == "JWT Weak HMAC Secret Key"
    assert offline_hits[0]["severity"] == "critical"
    assert offline_hits[0]["cwe"] == "CWE-522"


def test_cloud_metadata_ssrf_detection():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "ami-id: ami-0123456789abcdef0\ninstance-id: i-0123456789abcdef0"

    with patch("core.callback_verifier.requests.get", return_value=mock_resp):
        hits = CallbackVerifier.audit_endpoint_cloud_metadata(
            base_url="http://api.corp.local",
            endpoint="/api/v1/proxy",
            method="GET",
            candidate_params=["url"],
            target_name="CloudTarget",
        )
        assert len(hits) == 1
        assert "AWS IMDSv1" in hits[0]["vulnerability"]
        assert hits[0]["severity"] == "critical"
        assert hits[0]["cwe"] == "CWE-918"


def test_postman_poc_exporter(tmp_path):
    from core.poc_exporter import export_postman_poc_collection
    dummy_findings = [
        {
            "vuln_type": "JWT Algorithm None Bypass",
            "severity": "critical",
            "endpoint": "/api/admin",
            "method": "GET",
            "reproduction": {
                "url": "http://api.local/api/admin",
                "headers": {"Authorization": "Bearer forged_probe"},
                "curl": "curl -X GET 'http://api.local/api/admin'",
            },
        }
    ]
    out_file = tmp_path / "poc_collection.json"
    p = export_postman_poc_collection(dummy_findings, "DemoTarget", out_file)
    assert p.is_file()
    data = json.loads(p.read_text(encoding="utf-8"))
    assert "PoC Collection — DemoTarget" in data["info"]["name"]
    assert len(data["item"]) == 1
    req = data["item"][0]["request"]
    assert req["method"] == "GET"
    assert any(h["key"] == "Authorization" for h in req["header"])


def test_graphql_fuzz_prompt_and_execution():
    from core.graphql_engine import GraphQLSchemaSummary, GraphQLField, build_graphql_fuzz_prompt, execute_graphql_fuzz_probes
    summary = GraphQLSchemaSummary(
        queries=[GraphQLField(name="searchUser", args=[{"name": "query", "type": "String"}], return_type="User")]
    )
    prompt = build_graphql_fuzz_prompt(summary)
    assert "searchUser" in prompt
    assert "BOLA" in prompt

    # Execution mock
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "syntax error: unexpected token near SQL syntax"

    with patch("core.graphql_engine.requests.post", return_value=mock_resp):
        hits = execute_graphql_fuzz_probes(
            "http://api.local/graphql",
            payloads=[{"name": "sqli_probe", "query": 'query { searchUser(query: "\'") { id } }', "vuln_type": "GraphQL SQL Injection"}],
            target_name="GraphQLTarget",
        )
        assert len(hits) == 1
        assert hits[0]["vulnerability"] == "GraphQL SQL Injection"


def test_cli_verify_command(tmp_path):
    from fuzzer import main
    from core.hmac_sealer import seal_html_report
    report_file = tmp_path / "test_report.html"
    raw_html = "<html><body><h1>Audit Pass</h1></body></html>"
    sealed = seal_html_report(raw_html, secret_key="test-secret")
    report_file.write_text(sealed, encoding="utf-8")

    # Verify with matching key
    exit_code = main(["verify", str(report_file), "--key", "test-secret"])
    assert exit_code == 0

    # Verify with mismatched key
    exit_fail = main(["verify", str(report_file), "--key", "wrong-secret"])
    assert exit_fail == 1

