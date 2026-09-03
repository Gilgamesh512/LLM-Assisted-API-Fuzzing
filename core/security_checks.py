"""Deterministic OWASP API checks for input handling and response hardening."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class SecurityCheck:
    name: str
    vulnerable: bool
    severity: str
    confidence: int
    evidence: str
    recommendation: str


def check_input_validation(
    endpoint: str,
    method: str,
    payload: str,
    response_status: int,
    response_body: str,
) -> SecurityCheck:
    """Flag likely injection/error disclosure signals without claiming exploitation."""
    body = response_body.lower()
    signals = ("sql syntax", "sqlstate", "traceback", "stack trace", "unhandled exception", "odbc")
    matched = [signal for signal in signals if signal in body]
    vulnerable = response_status >= 500 or bool(matched)
    evidence = f"HTTP {response_status}; matched signals: {matched or 'none'}"
    return SecurityCheck(
        name="Input Validation / Injection",
        vulnerable=vulnerable,
        severity="high" if vulnerable and response_status >= 500 else "medium" if vulnerable else "info",
        confidence=85 if matched else 70 if response_status >= 500 else 40,
        evidence=f"{method.upper()} {endpoint} with payload {payload!r}; {evidence}",
        recommendation="Validate input with allowlists and use parameterized queries; do not expose internal errors.",
    )


def check_security_misconfiguration(
    endpoint: str,
    headers: Mapping[str, Any],
    body: str = "",
) -> list[SecurityCheck]:
    """Check observable response headers and verbose error disclosure."""
    normalized = {str(key).lower(): str(value) for key, value in headers.items()}
    checks: list[SecurityCheck] = []
    if "strict-transport-security" not in normalized and endpoint.lower().startswith("https://"):
        checks.append(SecurityCheck(
            "Security Misconfiguration", True, "medium", 80,
            "HTTPS response omitted HSTS (Strict-Transport-Security).",
            "Enable HSTS on HTTPS responses after confirming all subdomains support HTTPS.",
        ))
    if "x-content-type-options" not in normalized:
        checks.append(SecurityCheck(
            "Security Misconfiguration", True, "low", 75,
            "Response omitted X-Content-Type-Options.",
            "Set X-Content-Type-Options: nosniff.",
        ))
    lower_body = body.lower()
    if "traceback" in lower_body or "stack trace" in lower_body:
        checks.append(SecurityCheck(
            "Security Misconfiguration", True, "medium", 90,
            "Response exposed a stack trace.",
            "Disable debug responses and return a generic error with a correlation ID.",
        ))
    return checks
