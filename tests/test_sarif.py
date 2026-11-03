from __future__ import annotations

import json
from pathlib import Path

from core.sarif import convert_findings_to_sarif, export_sarif_file


def test_convert_findings_to_sarif():
    findings = [
        {
            "tool": "schemathesis",
            "target_app": "crapi",
            "endpoint": "/identity/api/auth/login",
            "method": "POST",
            "vuln_type": "SQLI",
            "severity": "high",
            "confirmed": True,
            "evidence": "syntax error near quote",
        },
        {
            "tool": "nuclei",
            "target_app": "vampi",
            "endpoint": "/users/v1/_debug",
            "method": "GET",
            "vuln_type": "Security Misconfiguration",
            "severity": "medium",
            "confirmed": False,
            "evidence": "missing HSTS",
        },
    ]

    sarif = convert_findings_to_sarif(findings)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "LLM-Assisted-API-Fuzzer"

    results = run["results"]
    assert len(results) == 2
    assert results[0]["level"] == "error"  # high severity maps to error
    assert results[1]["level"] == "warning"  # medium severity maps to warning


def test_export_sarif_file(tmp_path: Path):
    out = tmp_path / "results.sarif"
    findings = [
        {
            "endpoint": "/test",
            "method": "GET",
            "vuln_type": "BOLA",
            "severity": "critical",
            "confirmed": True,
        }
    ]
    export_sarif_file(findings, str(out))
    assert out.is_file()
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"
