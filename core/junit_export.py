"""
core/junit_export.py — Xuất kết quả kiểm thử API Fuzzing ra chuẩn JUnit XML.

Cho phép tích hợp trực tiếp với các hệ thống CI/CD truyền thống:
- Jenkins Test Result Viewer
- Azure DevOps Test Plans & Runs
- Bitbucket Pipelines & GitLab CI test reports
"""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any


def export_junit_xml(
    findings: list[dict[str, Any]],
    *,
    target_name: str = "API-Target",
    suite_name: str = "LLM-Assisted-API-Fuzzing",
    duration_seconds: float = 0.0,
    out_file: str | Path | None = None,
) -> str:
    """Chuyển đổi danh sách findings sang tài liệu JUnit XML chuẩn."""
    total_tests = max(len(findings), 1)
    failures = sum(1 for f in findings if str(f.get("severity", "")).lower() in ("critical", "high", "medium"))
    errors = sum(1 for f in findings if str(f.get("severity", "")).lower() in ("low", "info") and f.get("confirmed"))

    xml_lines: list[str] = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<testsuites name="{html.escape(suite_name)}" tests="{total_tests}" failures="{failures}" errors="{errors}" time="{duration_seconds:.2f}">',
        f'  <testsuite name="{html.escape(target_name)}" tests="{total_tests}" failures="{failures}" errors="{errors}" time="{duration_seconds:.2f}">',
    ]

    if not findings:
        xml_lines.append(
            f'    <testcase classname="api.security.{html.escape(target_name)}" name="Clean-Run-No-Vulnerabilities" time="0.0"/>'
        )
    else:
        for f in findings:
            method = str(f.get("method") or "GET").upper()
            endpoint = str(f.get("endpoint") or f.get("path") or "/")
            vuln_type = str(f.get("vuln_type") or f.get("vulnerability") or "Security-Finding")
            severity = str(f.get("severity") or "high").upper()
            confirmed = bool(f.get("confirmed", False))
            evidence = str(f.get("evidence") or "")
            reproduction = str(f.get("reproduction_curl") or f.get("curl_command") or "")

            case_name = f"[{method}] {endpoint} - {vuln_type}"
            xml_lines.append(
                f'    <testcase classname="api.security.{html.escape(target_name)}" name="{html.escape(case_name)}" time="0.0">'
            )

            is_fail = severity in ("CRITICAL", "HIGH", "MEDIUM") or confirmed
            if is_fail:
                msg = f"[{severity}] {vuln_type} detected on {method} {endpoint}"
                details = f"Evidence: {evidence}\n\nConfirmed: {confirmed}\nReproduce:\n{reproduction}"
                xml_lines.append(
                    f'      <failure message="{html.escape(msg)}" type="{html.escape(severity)}">{html.escape(details)}</failure>'
                )

            xml_lines.append("    </testcase>")

    xml_lines.append("  </testsuite>")
    xml_lines.append("</testsuites>")

    xml_text = "\n".join(xml_lines) + "\n"

    if out_file:
        p = Path(out_file)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(xml_text, encoding="utf-8")

    return xml_text


__all__ = ["export_junit_xml"]
