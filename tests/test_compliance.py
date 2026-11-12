"""
tests/test_compliance.py — Unit tests cho core/compliance.py.
"""

from core.compliance import (
    OWASP_API_TAXONOMY,
    build_owasp_compliance_matrix,
    map_vulnerability_to_compliance,
)


def test_map_vulnerability_to_compliance_categories():
    # API1: BOLA
    res1 = map_vulnerability_to_compliance("BOLA")
    assert res1["owasp_id"] == "API1:2023"
    assert "CWE-639" in res1["cwe_ids"]

    # API2: Broken Auth
    res2 = map_vulnerability_to_compliance("JWT Authentication Bypass")
    assert res2["owasp_id"] == "API2:2023"

    # API3: Mass Assignment
    res3 = map_vulnerability_to_compliance("Mass Assignment Property Injection")
    assert res3["owasp_id"] == "API3:2023"

    # API4: Rate Limiting
    res4 = map_vulnerability_to_compliance("Rate Limit Exhaustion / DoS")
    assert res4["owasp_id"] == "API4:2023"

    # API7: SSRF
    res7 = map_vulnerability_to_compliance("SSRF via Metadata endpoint")
    assert res7["owasp_id"] == "API7:2023"

    # API10: Injection
    res10 = map_vulnerability_to_compliance("SQL Injection (SQLi)")
    assert res10["owasp_id"] == "API10:2023"
    assert "CWE-89" in res10["cwe_ids"]

    # Default fallback
    res_def = map_vulnerability_to_compliance("UnknownAnomaly123")
    assert res_def["owasp_id"] == "API8:2023"
    assert "CWE-693" in res_def["cwe_ids"]


def test_build_owasp_compliance_matrix_empty():
    matrix_data = build_owasp_compliance_matrix([])
    assert matrix_data["compliance_score"] == 100.0
    assert matrix_data["total_categories"] == 10
    assert matrix_data["passed_categories"] == 10
    assert matrix_data["violated_categories"] == 0
    assert matrix_data["warning_categories"] == 0


def test_build_owasp_compliance_matrix_with_findings():
    findings = [
        {
            "vuln_type": "BOLA",
            "severity": "critical",
            "confirmed": True,
        },
        {
            "vuln_type": "Mass Assignment",
            "severity": "high",
            "confirmed": False,
        },
        {
            "vuln_type": "TRACE Method Enabled",
            "severity": "low",
            "confirmed": False,
        },
    ]

    matrix_data = build_owasp_compliance_matrix(findings)
    assert matrix_data["total_categories"] == 10
    assert matrix_data["violated_categories"] == 2  # API1 (critical) & API3 (high)
    assert matrix_data["warning_categories"] == 1   # API8 (low)
    assert matrix_data["passed_categories"] == 7
    assert matrix_data["compliance_score"] == 70.0
