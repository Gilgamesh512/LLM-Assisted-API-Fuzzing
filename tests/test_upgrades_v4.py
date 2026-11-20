"""
tests/test_upgrades_v4.py — Test suite cho toàn bộ 5 module nâng cấp mới:
1. core/remediation.py (AI Remediation & Patch Generator)
2. core/hybrid_mutator.py (Smart Hybrid Fuzzing Mutation Engine)
3. core/websocket_fuzzer.py (Real-time API: WebSocket & SSE Auditor)
4. core/agent_fuzzer.py (Autonomous ReAct Pentest Agent)
5. core/pr_commenter.py (CI/CD Pull Request Formatter)
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from core.remediation import (
    generate_remediation,
    generate_all_remediations,
    export_remediations_markdown,
    export_remediations_file,
)
from core.hybrid_mutator import HybridMutator
from core.websocket_fuzzer import audit_websocket_handshake, audit_sse_endpoint
from core.agent_fuzzer import AutonomousPentestAgent, AgentContextMemory
from core.pr_commenter import format_github_pr_comment, export_pr_comment_file, post_github_pr_comment


# =====================================================================
# 1. Tests for core/remediation.py
# =====================================================================

def test_generate_remediation_categories():
    # Test BOLA / IDOR
    f_bola = {
        "endpoint": "/api/orders/{id}",
        "method": "GET",
        "target_param": "id",
        "vuln_type": "Broken Object Level Authorization (BOLA)",
        "severity": "critical",
    }
    rem_fastapi = generate_remediation(f_bola, framework="fastapi")
    assert "FastAPI" in rem_fastapi["title"]
    assert "owner_id == current_user.id" in rem_fastapi["remediation_code_patch"]

    rem_express = generate_remediation(f_bola, framework="express")
    assert "Express.js" in rem_express["title"]
    assert "ownerId: req.user.id" in rem_express["remediation_code_patch"]

    rem_spring = generate_remediation(f_bola, framework="spring_boot")
    assert "Spring" in rem_spring["title"]

    # Test Mass Assignment
    f_ma = {
        "endpoint": "/api/users/profile",
        "method": "PUT",
        "target_param": "is_admin",
        "vuln_type": "Mass Assignment Parameter Tampering",
        "severity": "high",
    }
    rem_ma = generate_remediation(f_ma, framework="fastapi")
    assert "extra='forbid'" in rem_ma["remediation_code_patch"]

    # Test SQLi
    f_sqli = {
        "endpoint": "/api/search",
        "method": "GET",
        "target_param": "q",
        "vuln_type": "SQL Injection (SQLi)",
        "severity": "critical",
    }
    rem_sqli = generate_remediation(f_sqli, framework="fastapi")
    assert "text(" in rem_sqli["remediation_code_patch"] or "stmt" in rem_sqli["remediation_code_patch"]

    # Test JWT Broken Auth
    f_jwt = {
        "endpoint": "/api/admin",
        "method": "GET",
        "target_param": "Authorization",
        "vuln_type": "Broken JWT Authentication (alg:none)",
        "severity": "critical",
    }
    rem_jwt = generate_remediation(f_jwt, framework="fastapi")
    assert "algorithms=[\"HS256\"]" in rem_jwt["remediation_code_patch"]


def test_generate_all_remediations_and_export(tmp_path: Path):
    findings = [
        {"endpoint": "/api/orders/1", "method": "GET", "target_param": "id", "vuln_type": "BOLA", "severity": "critical"},
        {"endpoint": "/api/users", "method": "POST", "target_param": "role", "vuln_type": "Mass Assignment", "severity": "high"},
        {"endpoint": "/api/ping", "method": "GET", "target_param": "none", "vuln_type": "Info Leak", "severity": "low"}, # Low should be filtered
    ]
    rems = generate_all_remediations(findings, framework="fastapi")
    assert len(rems) == 2

    out_json = tmp_path / "rems.json"
    out_md = tmp_path / "rems.md"
    export_remediations_file(rems, out_json, out_md, target_name="TestApp")

    assert out_json.is_file()
    assert out_md.is_file()
    md_content = out_md.read_text(encoding="utf-8")
    assert "BÁO CÁO KHUYẾN NGHỊ VÁ LỖI BẢO MẬT" in md_content
    assert "TestApp" in md_content


# =====================================================================
# 2. Tests for core/hybrid_mutator.py
# =====================================================================

def test_hybrid_mutator_scalar_and_dict():
    mutator = HybridMutator()

    # Numeric mutations
    int_muts = mutator.mutate_scalar(100)
    assert 0 in int_muts
    assert -1 in int_muts
    assert 2147483647 in int_muts

    # String mutations
    str_muts = mutator.mutate_scalar("search_query")
    assert "" in str_muts
    assert any("A" * 5000 in str(m) for m in str_muts)
    assert any("etc/passwd" in str(m) for m in str_muts)

    # Dict / DTO mutations
    base_dto = {"username": "john", "amount": 500}
    dict_muts = mutator.mutate_dict_payload(base_dto, count=6)
    assert len(dict_muts) == 6
    for m in dict_muts:
        assert isinstance(m, dict)


def test_hybrid_mutator_expand_fuzz_payloads():
    mutator = HybridMutator()
    base_items = [
        {
            "method": "POST",
            "endpoint": "/api/checkout",
            "target_param": "body",
            "param_location": "body",
            "payload_value": {"item_id": 12, "quantity": 2},
            "attack_type": "business_logic",
        },
        {
            "method": "GET",
            "endpoint": "/api/items",
            "target_param": "category",
            "param_location": "query",
            "payload_value": "electronics",
            "attack_type": "sqli",
        },
    ]

    expanded = mutator.expand_fuzz_payloads(base_items, mutations_per_seed=4)
    # 2 original seeds + multiple mutated payloads
    assert len(expanded) > len(base_items)
    # Check that mutations have the hybrid_mutation attack_type
    mut_types = [item["attack_type"] for item in expanded]
    assert any("hybrid_mutation" in mt for mt in mut_types)


# =====================================================================
# 3. Tests for core/websocket_fuzzer.py
# =====================================================================

def test_websocket_handshake_audit():
    with patch("socket.create_connection") as mock_conn:
        mock_sock = MagicMock()
        # Mocking 101 Switching Protocols response (vulnerable to CSWSH & unauth)
        mock_sock.recv.return_value = (
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
        )
        mock_conn.return_value = mock_sock

        findings = audit_websocket_handshake("ws://127.0.0.1:8080/ws/chat")
        assert len(findings) >= 1
        vuln_types = [f["vuln_type"] for f in findings]
        assert "Broken WebSocket Authentication" in vuln_types or "Cross-Site WebSocket Hijacking (CSWSH)" in vuln_types


def test_sse_endpoint_audit():
    with patch("requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "text/event-stream"}
        mock_resp.iter_lines.return_value = [b"data: {\"event\": \"user_connected\", \"user_id\": 109}"]
        mock_get.return_value = mock_resp

        findings = audit_sse_endpoint("http://127.0.0.1:8080/events")
        assert len(findings) == 1
        assert "Unauthenticated Server-Sent Events" in findings[0]["vuln_type"]


# =====================================================================
# 4. Tests for core/agent_fuzzer.py
# =====================================================================

def test_agent_context_memory():
    mem = AgentContextMemory()
    data = {
        "user": {"id": 42, "role": "admin", "token": "jwt_secret_token_123"},
        "order": {"order_id": 9999, "total": 150000},
    }
    mem.extract_from_json(data)
    assert mem.get("id") == 42 or mem.get("user.id") == 42
    assert mem.get("token") == "jwt_secret_token_123"
    assert mem.get("order_id") == 9999


def test_autonomous_pentest_agent_campaign():
    mock_session = MagicMock()

    # Giả lập response: Endpoint /api/users/profile trả về 200 OK ngay cả khi token fake
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"status": "success", "profile": {"email": "test@domain.com"}}'
    mock_resp.json.return_value = {"status": "success", "profile": {"email": "test@domain.com"}}
    mock_session.request.return_value = mock_resp

    agent = AutonomousPentestAgent("http://testserver:8000", session=mock_session)
    endpoints = [
        {"path": "/api/users/profile", "method": "GET"},
        {"path": "/api/orders/checkout", "method": "POST"},
    ]

    findings = agent.run_multi_step_logic_campaign(endpoints, primary_token="valid_token_abc")
    assert len(findings) >= 1
    types = [f["vuln_type"] for f in findings]
    assert "Multi-Step Workflow Auth Bypass (Fail-Open)" in types or "Negative Value Business Logic Flaw" in types


# =====================================================================
# 5. Tests for core/pr_commenter.py
# =====================================================================

def test_format_and_export_github_pr_comment(tmp_path: Path):
    run_summary = {
        "gate_status": "FAIL",
        "target_name": "PaymentGatewayMicroservice",
        "target_url": "https://pay.internal.corp",
        "run_id": "test_run_uuid_001",
        "provider": "gemini",
        "model": "gemini-3.7-flash",
        "compliance_score": 75.0,
        "critical_count": 1,
        "high_count": 2,
        "medium_count": 0,
        "low_count": 0,
        "total_findings": 3,
    }
    findings = [
        {
            "method": "POST",
            "endpoint": "/api/transfer",
            "target_param": "amount",
            "vuln_type": "BOLA / IDOR Financial Bypass",
            "severity": "critical",
            "evidence": "Giao dịch thành công với tài khoản người dùng khác.",
            "reproduction": {"method": "POST", "url": "https://pay.internal.corp/api/transfer", "body": {"amount": -100}},
        }
    ]

    comment = format_github_pr_comment(run_summary, findings)
    assert "PaymentGatewayMicroservice" in comment
    assert "SECURITY GATE BLOCKED" in comment
    assert "75.0%" in comment
    assert "curl" in comment
    assert "BOLA / IDOR Financial Bypass" in comment

    out_file = tmp_path / "pr_comment.md"
    export_pr_comment_file(comment, out_file)
    assert out_file.is_file()
    assert out_file.read_text(encoding="utf-8") == comment


def test_post_github_pr_comment_mock():
    with patch("requests.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_post.return_value = mock_resp

        success = post_github_pr_comment(
            comment_body="Test PR comment",
            repo="org/repo",
            pr_number=10,
            github_token="ghp_testtoken",
        )
        assert success is True
        mock_post.assert_called_once()


# =====================================================================
# 6. Tests for Resilient Provider Failover (Cloud API -> Local/Offline)
# =====================================================================

def test_resilient_provider_automatic_failover():
    from core.providers import GeminiProvider, OfflineProvider, ResilientProvider, get_resilient_provider

    # Giả lập GeminiProvider bị thiếu key hoặc hết token (ném RuntimeError)
    gemini = GeminiProvider()
    offline = OfflineProvider()

    resilient = ResilientProvider(primary=gemini, fallbacks=[offline], auto_fallback=True)
    assert resilient.name == "gemini"

    # Khi generate, Gemini lỗi sẽ tự động failover sang Offline
    res = resilient.generate("Test prompt")
    assert "reply" in res
    assert resilient.active_provider == offline
    assert resilient.name == "offline"
    meta = resilient.metadata()
    assert meta["failover_active"] == "True"


def test_get_resilient_provider_factory():
    from core.providers import get_resilient_provider, ResilientProvider

    prov = get_resilient_provider("gemini", fallback_name="offline")
    assert isinstance(prov, ResilientProvider)
