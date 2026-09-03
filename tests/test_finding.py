from core.finding import normalize_finding, normalize_findings, severity_rank


def test_normalize_finding_adds_research_fields():
    finding = normalize_finding(
        {
            "tool": "schemathesis",
            "target_app": "vampi",
            "endpoint": "/users/{id}",
            "method": "get",
            "vuln_type": "BOLA",
            "severity": "HIGH",
            "confirmed": True,
            "http_status": 200,
            "evidence": "User A accessed User B object",
        }
    )

    assert finding["id"].startswith("API-BOLA-001-")
    assert finding["vulnerability"] == "BOLA"
    assert finding["method"] == "GET"
    assert finding["confidence"] == 95
    assert finding["reproduction"]["status"] == 200
    assert "object-level authorization" in finding["recommendation"]


def test_normalize_finding_preserves_explicit_assessment():
    finding = normalize_finding(
        {
            "vulnerability": "Broken Function Level Authorization",
            "method": "post",
            "endpoint": "/admin/users",
            "confidence": 88,
            "reproduction": {"request": "User token"},
            "recommendation": "Use role checks.",
        },
        sequence=4,
    )

    assert finding["id"].startswith("API-BROKEN-FUNCTION-LEVEL-AUTHORIZATION-004-")
    assert finding["confidence"] == 88
    assert finding["reproduction"] == {"request": "User token"}
    assert finding["recommendation"] == "Use role checks."


def test_normalize_findings_and_severity_rank():
    findings = normalize_findings([{"vuln_type": "SQLi"}, {"vuln_type": "BOLA"}])

    assert findings[0]["id"].startswith("API-SQLI-001-")
    assert findings[1]["id"].startswith("API-BOLA-002-")
    assert severity_rank("critical") > severity_rank("high") > severity_rank("info")
