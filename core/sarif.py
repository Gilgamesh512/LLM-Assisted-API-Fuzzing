"""
core/sarif.py — Export kết quả kiểm thử ra chuẩn OASIS SARIF v2.1.0.

Cho phép tích hợp trực tiếp với các nền tảng Enterprise DevSecOps:
- GitHub Advanced Security (Code Scanning tab)
- GitLab Security Dashboard
- DefectDojo / SonarQube
"""

from __future__ import annotations

import json
from typing import Any

from core.finding import normalize_findings


def _severity_to_sarif_level(severity: str) -> str:
    s = str(severity).lower()
    if s in ("critical", "high"):
        return "error"
    if s == "medium":
        return "warning"
    return "note"


def convert_findings_to_sarif(
    findings: list[dict[str, Any]],
    *,
    tool_name: str = "LLM-Assisted-API-Fuzzer",
    tool_version: str = "1.0.0",
) -> dict[str, Any]:
    """Chuyển đổi danh sách findings (dict) sang chuẩn OASIS SARIF v2.1.0."""
    normalized = normalize_findings(findings)
    rules_dict: dict[str, dict[str, Any]] = {}
    results_list: list[dict[str, Any]] = []

    for item in normalized:
        vuln_type = str(item.get("vulnerability") or item.get("vuln_type") or "Security-Finding")
        rule_id = f"API-{vuln_type.upper().replace(' ', '-')}"
        severity = str(item.get("severity") or "info").lower()
        level = _severity_to_sarif_level(severity)

        if rule_id not in rules_dict:
            rules_dict[rule_id] = {
                "id": rule_id,
                "name": vuln_type,
                "shortDescription": {"text": f"Potential API Vulnerability: {vuln_type}"},
                "fullDescription": {"text": str(item.get("recommendation") or f"API security check for {vuln_type}")},
                "defaultConfiguration": {"level": level},
                "help": {
                    "text": str(item.get("recommendation") or "Review and sanitize input parameters and enforce authorization.")
                },
            }

        endpoint = str(item.get("endpoint") or item.get("path") or "/")
        method = str(item.get("method") or "").upper()
        evidence = str(item.get("evidence") or "")
        confirmed = bool(item.get("confirmed", False))
        message_text = f"[{method}] {endpoint} - {vuln_type} ({'CONFIRMED' if confirmed else 'POTENTIAL'}). {evidence}".strip()

        result_entry: dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message_text},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": endpoint.lstrip("/") or "root"},
                        "region": {"startLine": 1, "startColumn": 1},
                    }
                }
            ],
            "properties": {
                "method": method,
                "target_app": str(item.get("target_app") or ""),
                "confirmed": confirmed,
                "confidence": item.get("confidence", 50),
                "reproduction": item.get("reproduction"),
                "source_engine": item.get("source_engine", "unknown"),
            },
        }
        results_list.append(result_entry)

    sarif_doc: dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://github.com/enterprise/llm-api-fuzzer",
                        "rules": list(rules_dict.values()),
                    }
                },
                "results": results_list,
            }
        ],
    }
    return sarif_doc


def export_sarif_file(findings: list[dict[str, Any]], out_path: str) -> None:
    """Ghi findings ra file SARIF JSON."""
    from pathlib import Path

    doc = convert_findings_to_sarif(findings)
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")


__all__ = ["convert_findings_to_sarif", "export_sarif_file"]
