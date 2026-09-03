"""Stable run-manifest contract shared by generation and fuzzing runners."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.telemetry import RunTelemetry

SCHEMA_VERSION = "1.0"
SCHEMA_PATH = Path(__file__).resolve().parent.parent / "config" / "manifest.schema.json"


class ManifestValidationError(ValueError):
    """Raised when a run artifact does not satisfy the versioned manifest contract."""


def new_run_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{timestamp}-{uuid.uuid4().hex[:8]}"


def build_manifest(
    *,
    run_id: str,
    target_name: str,
    protocol: str,
    provider: str,
    model: str,
    telemetry: RunTelemetry,
    payload_count: int,
    status: str,
    output_path: Path,
    context_path: Path,
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "run_id": run_id,
        "target": {"name": target_name, "protocol": protocol},
        "llm": {
            "provider": provider,
            "model": model,
            "usage_available": telemetry.usage.available,
            "prompt_tokens": telemetry.usage.prompt_tokens,
            "completion_tokens": telemetry.usage.completion_tokens,
            "total_tokens": telemetry.usage.total_tokens,
            "usage_source": telemetry.usage.source,
        },
        "generation": {
            "repair_count": telemetry.repair_count,
        },
        "repair": {
            "attempts": telemetry.repair_count,
            "initial_valid": telemetry.initial_valid,
            "final_valid": telemetry.final_valid,
            "successful": telemetry.initial_valid is False and telemetry.final_valid is True,
        },
        "runtime": {
            "total_ms": telemetry.total_ms,
            "analyzer_ms": telemetry.stages_ms.get("analyzer", 0.0),
            "generation_ms": telemetry.stages_ms.get("llm_generation", 0.0),
            "validation_ms": telemetry.stages_ms.get("validation", 0.0),
            "repair_ms": telemetry.stages_ms.get("repair", 0.0),
        },
        "fuzzing": {"engine": None, "runtime_ms": 0.0, "requests": 0},
        "result": {
            "status": status,
            "payload_count": payload_count,
            "finding_count": None,
        },
        "artifacts": {
            "context": str(context_path),
            "payloads": str(output_path),
            "findings": None,
        },
        "experiment": {
            "git_commit": None,
            "dataset_version": None,
            "config_version": None,
        },
    }


def write_manifest(manifest: dict[str, Any], path: Path | str) -> Path:
    validate_manifest(manifest)
    manifest_path = Path(path)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest_path


def validate_manifest(manifest: dict[str, Any]) -> None:
    """Validate a manifest against the checked-in JSON Schema before writing it."""
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ManifestValidationError(f"Unsupported schema_version: {manifest.get('schema_version')!r}")
    required = ("schema_version", "run_id", "target", "llm", "repair", "runtime", "result")
    missing = [field for field in required if field not in manifest]
    if missing:
        raise ManifestValidationError(f"Missing required fields: {', '.join(missing)}")
    try:
        import jsonschema
    except ImportError:
        _validate_manifest_without_jsonschema(manifest)
        return
    try:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        jsonschema.validate(manifest, schema)
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestValidationError(f"Cannot load manifest schema: {exc}") from exc
    except jsonschema.ValidationError as exc:
        raise ManifestValidationError(exc.message) from exc


def _validate_manifest_without_jsonschema(manifest: dict[str, Any]) -> None:
    """Keep pipeline validation usable before optional dependencies are installed."""
    required = {
        "target": {"name", "protocol"},
        "llm": {"provider", "model", "usage_available", "prompt_tokens", "completion_tokens", "total_tokens", "usage_source"},
        "generation": {"repair_count"},
        "repair": {"attempts", "initial_valid", "final_valid", "successful"},
        "runtime": {"total_ms", "analyzer_ms", "generation_ms", "validation_ms", "repair_ms"},
        "fuzzing": {"engine", "runtime_ms", "requests"},
        "result": {"status", "payload_count", "finding_count"},
        "artifacts": {"context", "payloads", "findings"},
        "experiment": {"git_commit", "dataset_version", "config_version"},
    }
    allowed_top = {"schema_version", "run_id", *required}
    unexpected = set(manifest) - allowed_top
    if unexpected:
        raise ManifestValidationError(f"Unexpected fields: {', '.join(sorted(unexpected))}")
    for section, fields in required.items():
        value = manifest.get(section)
        if not isinstance(value, dict) or set(value) != fields:
            raise ManifestValidationError(f"Invalid fields in {section}; expected: {', '.join(sorted(fields))}")
    llm = manifest["llm"]
    token_fields = ("prompt_tokens", "completion_tokens", "total_tokens")
    if not llm["usage_available"] and any(llm[field] is not None for field in token_fields):
        raise ManifestValidationError("Unavailable LLM usage must use null token fields")
    if llm["usage_available"] and any(not isinstance(llm[field], int) or llm[field] < 0 for field in token_fields):
        raise ManifestValidationError("Available LLM usage must use non-negative integer token fields")
    for section in ("generation", "repair", "runtime", "result"):
        if section == "runtime":
            values = manifest[section].values()
            if any(not isinstance(value, (int, float)) or value < 0 for value in values):
                raise ManifestValidationError("Runtime values must be non-negative numbers")
        elif section == "result" and (
            not isinstance(manifest[section]["payload_count"], int)
            or manifest[section]["payload_count"] < 0
        ):
            raise ManifestValidationError("payload_count must be a non-negative integer")


__all__ = ["SCHEMA_VERSION", "ManifestValidationError", "new_run_id", "build_manifest", "validate_manifest", "write_manifest"]
