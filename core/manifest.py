"""Stable run-manifest contract shared by generation and fuzzing runners."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.telemetry import RunTelemetry


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
        "llm": {"provider": provider, "model": model},
        "generation": {
            "prompt_tokens": telemetry.usage.prompt_tokens,
            "completion_tokens": telemetry.usage.completion_tokens,
            "total_tokens": telemetry.usage.total_tokens,
            "repair_count": telemetry.repair_count,
        },
        "repair": {
            "attempts": telemetry.repair_count,
            "initial_valid": telemetry.initial_valid,
            "final_valid": telemetry.final_valid,
            "successful": telemetry.initial_valid is False and telemetry.final_valid is True,
        },
        "runtime_ms": {
            "analyzer": telemetry.stages_ms.get("analyzer", 0.0),
            "llm_generation": telemetry.stages_ms.get("llm_generation", 0.0),
            "validation": telemetry.stages_ms.get("validation", 0.0),
            "repair": telemetry.stages_ms.get("repair", 0.0),
            "total": telemetry.total_ms,
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
    }


def write_manifest(manifest: dict[str, Any], path: Path | str) -> Path:
    manifest_path = Path(path)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest_path
