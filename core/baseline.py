"""Baseline comparison and severity-based security gate."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.finding import severity_rank


@dataclass(frozen=True)
class BaselineDiff:
    new: list[dict[str, Any]]
    resolved: list[dict[str, Any]]
    unchanged: list[dict[str, Any]]

    @property
    def new_by_severity(self) -> dict[str, int]:
        return _count_by_severity(self.new)


def load_findings(path: Path | str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw in Path(path).read_text(encoding="utf-8-sig").splitlines():
        if raw.strip():
            rows.append(json.loads(raw))
    return rows


def _key(finding: dict[str, Any]) -> tuple[str, ...]:
    return (
        str(finding.get("target_app") or ""),
        str(finding.get("method") or "").upper(),
        str(finding.get("endpoint") or ""),
        str(finding.get("vulnerability") or finding.get("vuln_type") or ""),
    )


def compare_baseline(previous: list[dict[str, Any]], current: list[dict[str, Any]]) -> BaselineDiff:
    previous_by_key = {_key(finding): finding for finding in previous}
    current_by_key = {_key(finding): finding for finding in current}
    new = [finding for key, finding in current_by_key.items() if key not in previous_by_key]
    resolved = [finding for key, finding in previous_by_key.items() if key not in current_by_key]
    unchanged = [finding for key, finding in current_by_key.items() if key in previous_by_key]
    return BaselineDiff(new=new, resolved=resolved, unchanged=unchanged)


def _count_by_severity(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        severity = str(finding.get("severity") or "info").lower()
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def security_gate(findings: list[dict[str, Any]], fail_on: str = "high") -> tuple[bool, str]:
    threshold = severity_rank(fail_on)
    blocking = [finding for finding in findings if severity_rank(str(finding.get("severity", "info"))) >= threshold]
    if not blocking:
        return True, f"PASS: no findings at or above {fail_on}."
    counts = _count_by_severity(blocking)
    summary = ", ".join(f"{severity}={count}" for severity, count in sorted(counts.items(), key=lambda item: -severity_rank(item[0])))
    return False, f"FAIL: findings at or above {fail_on}: {summary}."
