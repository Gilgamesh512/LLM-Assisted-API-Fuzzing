"""Reproducible benchmark protocol and metrics for API fuzzing experiments."""

from __future__ import annotations

import csv
import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

from core.finding import normalize_findings


@dataclass(frozen=True)
class Treatment:
    """One comparable arm of the benchmark."""

    name: str
    generator: str
    validation: bool = False
    feedback: bool = False


@dataclass(frozen=True)
class ExperimentProtocol:
    """Inputs that must remain identical when comparing treatments."""

    benchmark: str
    targets: tuple[str, ...]
    endpoint_set: str
    timeout_seconds: int
    runs_per_treatment: int
    seed: int
    model: str = "none"
    provider: str = "none"
    prompt_version: str = "none"
    temperature: float = 0.0
    schema_hash: str = ""
    treatments: tuple[Treatment, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["targets"] = list(self.targets)
        result["treatments"] = [asdict(treatment) for treatment in self.treatments]
        return result


def schema_hash(schema: Any) -> str:
    """Return a stable hash for the exact input context sent to a generator."""
    encoded = json.dumps(schema, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _payload_key(payload: dict[str, Any]) -> str:
    relevant = {key: payload.get(key) for key in ("method", "path", "target_parameter", "location", "payload_value")}
    return json.dumps(relevant, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _finding_key(finding: dict[str, Any]) -> tuple[str, ...]:
    return (
        str(finding.get("target_app") or ""),
        str(finding.get("method") or "").upper(),
        str(finding.get("endpoint") or ""),
        str(finding.get("vulnerability") or finding.get("vuln_type") or ""),
    )


def evaluate_run(
    payloads: Iterable[dict[str, Any]],
    findings: Iterable[dict[str, Any]],
    *,
    runtime_seconds: float = 0.0,
    llm_cost_usd: float = 0.0,
    llm_tokens: int = 0,
    known_vulnerabilities: int | None = None,
) -> dict[str, Any]:
    """Calculate validity, novelty, effectiveness, cost and attribution metrics."""
    payload_list = list(payloads)
    finding_list = normalize_findings(list(findings))
    valid = [payload for payload in payload_list if bool(payload.get("valid", False))]
    executable = [payload for payload in valid if bool(payload.get("executable", False))]
    unique = {_payload_key(payload) for payload in executable}
    confirmed = [finding for finding in finding_list if bool(finding.get("confirmed", False))]
    rejected = [
        finding for finding in finding_list
        if str(finding.get("confirmation_status", "")).lower() == "rejected"
    ]
    confirmed_unique = {_finding_key(finding) for finding in confirmed}
    candidate_count = len(confirmed) + len(rejected)
    return {
        "payloads": len(payload_list),
        "valid_payloads": len(valid),
        "valid_payload_rate": len(valid) / len(payload_list) if payload_list else 0.0,
        "executable_payloads": len(executable),
        "executability_rate": len(executable) / len(payload_list) if payload_list else 0.0,
        "unique_payloads": len(unique),
        "unique_payload_rate": len(unique) / len(executable) if executable else 0.0,
        "findings": len(finding_list),
        "confirmed_findings": len(confirmed_unique),
        "false_positive_candidates": len(rejected),
        "false_positive_rate": len(rejected) / candidate_count if candidate_count else 0.0,
        "detection_rate": len(confirmed_unique) / known_vulnerabilities if known_vulnerabilities else None,
        "runtime_seconds": float(runtime_seconds),
        "llm_cost_usd": float(llm_cost_usd),
        "llm_tokens": int(llm_tokens),
        "attribution": {
            "source_engines": sorted({str(f.get("source_engine")) for f in finding_list}),
            "payload_sources": sorted({str(f.get("payload_source")) for f in finding_list}),
            "confirmed_by_payload_source": sorted({str(f.get("payload_source")) for f in confirmed}),
        },
    }


def write_metrics(rows: list[dict[str, Any]], output: Path | str) -> None:
    """Write machine-readable JSON and a flat CSV for paper tables."""
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    csv_path = output_path.with_suffix(".csv")
    fields = sorted({key for row in rows for key, value in row.items() if not isinstance(value, dict)})
    with csv_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows({key: row.get(key) for key in fields} for row in rows)


__all__ = ["Treatment", "ExperimentProtocol", "schema_hash", "evaluate_run", "write_metrics"]