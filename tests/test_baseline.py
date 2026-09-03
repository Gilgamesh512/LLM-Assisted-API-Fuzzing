from core.baseline import compare_baseline, security_gate


def finding(vuln_type: str, severity: str = "info") -> dict[str, str]:
    return {
        "target_app": "vampi",
        "method": "GET",
        "endpoint": "/users/{id}",
        "vuln_type": vuln_type,
        "severity": severity,
    }


def test_compare_baseline_reports_new_and_resolved_findings():
    diff = compare_baseline(
        [finding("BOLA", "high"), finding("XSS", "low")],
        [finding("BOLA", "high"), finding("SQLi", "critical")],
    )

    assert [item["vuln_type"] for item in diff.new] == ["SQLi"]
    assert [item["vuln_type"] for item in diff.resolved] == ["XSS"]
    assert diff.new_by_severity == {"critical": 1}


def test_security_gate_fails_at_high_and_passes_for_low_only():
    assert security_gate([finding("XSS", "low")], "high")[0] is True
    passed, message = security_gate([finding("BOLA", "high")], "high")
    assert passed is False
    assert "FAIL" in message
    assert "high=1" in message
