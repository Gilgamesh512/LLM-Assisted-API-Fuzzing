"""Shared finding normalization for security results and regression checks."""

from __future__ import annotations

import hashlib
import re
from typing import Any


SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

RECOMMENDATIONS = {
    "bola": "Enforce object-level authorization for every requested object.",
    "idor": "Enforce object-level authorization for every requested object.",
    "bfla": "Enforce function-level authorization and deny unauthorized roles by default.",
    "authentication": "Require valid, non-expired credentials and reject invalid tokens.",
    "jwt/auth": "Validate token signature, issuer, audience, expiry, and required claims.",
    "sqli": "Use parameterized queries and validate input against an allowlist.",
    "xss": "Validate input and contextually encode output before rendering.",
    "ssrf": "Allowlist outbound hosts and block private or link-local address ranges.",
    "security misconfiguration": "Disable verbose errors and enforce secure production defaults.",
}


def _slug(value: str) -> str:
    return re.sub(r"[^A-Z0-9]+", "-", value.upper()).strip("-") or "GENERAL"


def _confidence(finding: dict[str, Any]) -> int:
    if finding.get("confidence") is not None:
        try:
            return max(0, min(100, int(finding["confidence"])))
        except (TypeError, ValueError):
            pass
    if finding.get("confirmed") or finding.get("matched"):
        return 95
    if finding.get("evidence"):
        return 75
    return 40


def _recommendation(vulnerability: str) -> str:
    normalized = vulnerability.strip().lower()
    for key, recommendation in RECOMMENDATIONS.items():
        if key in normalized:
            return recommendation
    return "Review endpoint authorization, input validation, and production security controls."


def normalize_finding(finding: dict[str, Any], sequence: int = 1) -> dict[str, Any]:
    """Return stable research-facing fields while preserving existing fields."""
    vulnerability = str(finding.get("vulnerability") or finding.get("vuln_type") or "Unknown")
    endpoint = str(finding.get("endpoint") or finding.get("path") or "")
    method = str(finding.get("method") or "").upper()
    evidence = str(finding.get("evidence") or "")
    severity = str(finding.get("severity") or "info").lower()
    stable_key = "|".join((vulnerability, method, endpoint, str(finding.get("target_app") or "")))
    digest = hashlib.sha1(stable_key.encode("utf-8")).hexdigest()[:8].upper()
    reproduction = finding.get("reproduction") or {
        "method": method,
        "endpoint": endpoint,
        "status": finding.get("http_status"),
        "payload": finding.get("payload"),
    }
    return {
        **finding,
        "id": str(finding.get("id") or f"API-{_slug(vulnerability)}-{sequence:03d}-{digest}"),
        "vulnerability": vulnerability,
        "endpoint": endpoint,
        "method": method,
        "severity": severity,
        "confidence": _confidence(finding),
        "evidence": evidence,
        "reproduction": reproduction,
        "recommendation": str(finding.get("recommendation") or _recommendation(vulnerability)),
        "source_engine": str(finding.get("source_engine") or finding.get("tool") or finding.get("source") or "unknown"),
        "payload_source": str(
            finding.get("payload_source")
            or ("llm" if finding.get("llm_generated") else "unknown")
        ),
        "baseline_status": str(finding.get("baseline_status") or "unknown"),
        "confirmation_method": str(
            finding.get("confirmation_method")
            or ("runtime" if finding.get("confirmed") else "unconfirmed")
        ),
    }


def normalize_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [normalize_finding(finding, index) for index, finding in enumerate(findings, start=1)]


def severity_rank(severity: str) -> int:
    return SEVERITY_RANK.get(str(severity).lower(), 0)
