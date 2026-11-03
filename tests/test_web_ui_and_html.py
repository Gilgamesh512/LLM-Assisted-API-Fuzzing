from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.html_report import generate_html_report
from fuzzer import main as fuzzer_main
from web_ui import app, scan_state


def test_generate_html_report_renders_summary_and_rows():
    findings = [
        {
            "method": "POST",
            "endpoint": "/api/v1/auth/login",
            "vuln_type": "SQLi",
            "severity": "critical",
            "http_status": 500,
            "confirmed": True,
            "evidence": "[ORACLE CONFIRMED] SQL syntax error detected",
            "reproduction": {"method": "POST", "url": "http://test/login", "payload_value": "' OR '1'='1"},
        },
        {
            "method": "GET",
            "endpoint": "/api/v1/users/{id}",
            "vuln_type": "BOLA",
            "severity": "high",
            "http_status": 200,
            "confirmed": True,
            "evidence": "Accessed other user object without authorization",
            "reproduction": {"method": "GET", "url": "http://test/users/99"},
        },
        {
            "method": "GET",
            "endpoint": "/health",
            "vuln_type": "Other",
            "severity": "info",
            "http_status": 200,
            "confirmed": False,
            "evidence": "Candidate payload tested",
        },
    ]

    html_content = generate_html_report(
        findings,
        target_name="TestBankingAPI",
        target_url="http://192.168.1.50:8000",
        spec_source="remote_url",
        provider="gemini",
        model="gemini-3.7-flash",
        run_id="run-test-123",
        gate_status="FAIL",
        fail_on="high",
        output_files={"OASIS SARIF": "findings_summary.sarif", "CSV Report": "findings_summary.csv"},
    )

    assert "<!DOCTYPE html>" in html_content
    assert "TestBankingAPI" in html_content
    assert "Security Gate (HIGH): FAIL" in html_content
    assert "/api/v1/auth/login" in html_content
    assert "CRITICAL" in html_content
    assert "Đã xác nhận (Exploited)" in html_content
    assert "findings_summary.sarif" in html_content


def test_flask_web_ui_routes():
    client = app.test_client()

    # Route /
    resp_index = client.get("/")
    assert resp_index.status_code == 200
    assert b"LLM-Assisted API Fuzzing Console" in resp_index.data
    assert b"Lo\xe1\xba\xa1i Ngu\xe1\xbb\x93n \xc4\x90\xe1\xba\xb7c T\xe1\xba\xa3" in resp_index.data or b"Spec Mode" in resp_index.data

    # Route /api/env-status
    resp_env = client.get("/api/env-status")
    assert resp_env.status_code == 200
    data_env = resp_env.get_json()
    assert "gemini_ready" in data_env
    assert "deepseek_ready" in data_env
    assert "local_ready" in data_env

    # Route /api/scan/status
    resp_status = client.get("/api/scan/status")
    assert resp_status.status_code == 200
    data_status = resp_status.get_json()
    assert "status" in data_status
    assert "logs" in data_status


def test_flask_web_ui_report_404_when_missing(tmp_path: Path):
    client = app.test_client()
    scan_state["out_dir"] = str(tmp_path / "non_existent_results")
    resp_report = client.get("/report")
    assert resp_report.status_code == 404


def test_flask_web_ui_report_200_when_present(tmp_path: Path):
    client = app.test_client()
    report_file = tmp_path / "report.html"
    report_file.write_text("<h1>Mock Report</h1>", encoding="utf-8")

    scan_state["out_dir"] = str(tmp_path)
    resp_report = client.get("/report")
    assert resp_report.status_code == 200
    assert b"Mock Report" in resp_report.data


def test_cli_fuzzer_ui_help():
    with pytest.raises(SystemExit) as exc:
        fuzzer_main(["ui", "--help"])
    assert exc.value.code == 0
