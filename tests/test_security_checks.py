from core.security_checks import check_input_validation, check_security_misconfiguration


def test_input_validation_reports_sql_error_signal():
    result = check_input_validation("/users", "post", "' OR 1=1 --", 500, "SQL syntax error")
    assert result.vulnerable is True
    assert result.severity == "high"
    assert "sql syntax" in result.evidence


def test_security_misconfiguration_reports_missing_headers_and_debug_trace():
    results = check_security_misconfiguration("https://api.test/users", {}, "Traceback: secret")
    assert len(results) == 3
    assert any("HSTS" in result.evidence for result in results)
    assert any("stack trace" in result.evidence.lower() for result in results)
