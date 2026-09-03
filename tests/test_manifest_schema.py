import copy
import json

import pytest

from core.manifest import ManifestValidationError, build_manifest, validate_manifest
from core.telemetry import RunTelemetry


def _manifest():
    telemetry = RunTelemetry()
    telemetry.record_validation(True)
    return build_manifest(
        run_id="run-1", target_name="vampi", protocol="rest", provider="deepcode",
        model="unknown", telemetry=telemetry, payload_count=2, status="completed",
        output_path="payloads.json", context_path="context.json",
    )


def test_manifest_has_unavailable_nullable_usage_and_validates():
    manifest = _manifest()

    validate_manifest(manifest)

    assert manifest["llm"]["usage_available"] is False
    assert manifest["llm"]["total_tokens"] is None


def test_manifest_rejects_silent_repair_field_rename():
    manifest = _manifest()
    invalid = copy.deepcopy(manifest)
    invalid["generation"]["repairs"] = invalid["generation"].pop("repair_count")

    with pytest.raises(ManifestValidationError):
        validate_manifest(invalid)


def test_checked_in_schema_matches_manifest_contract():
    schema = json.loads(open("config/manifest.schema.json", encoding="utf-8").read())
    assert schema["properties"]["llm"]["required"] == [
        "provider", "model", "usage_available", "prompt_tokens", "completion_tokens", "total_tokens", "usage_source"
    ]