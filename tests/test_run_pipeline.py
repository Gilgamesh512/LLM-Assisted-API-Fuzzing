"""tests/test_run_pipeline.py — Validation for the canonical provider-based pipeline."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import scripts.run_pipeline as pipeline  # noqa: E402

FIXTURE = Path(__file__).parent / "fixtures" / "sample_openapi.json"

VALID_PAYLOAD_JSON = json.dumps(
    [
        {
            "method": "GET",
            "path": "/api/users/{id}",
            "target_parameter": "id",
            "location": "path",
            "vulnerability_type": "BOLA",
            "payload_value": "2",
            "rationale": "test",
            "expected_indicator": "test",
        }
    ]
)


class FakeProvider:
    def __init__(self, name: str = "gemini", model: str = "test-model"):
        self.name = name
        self.model = model

    def generate(self, prompt: str, *, system_prompt=None, context=None):
        return {"reply": VALID_PAYLOAD_JSON}

    def repair(self, prompt: str, *, system_prompt=None, context=None):
        return {"reply": VALID_PAYLOAD_JSON}


def test_run_pipeline_happy_path(tmp_path: Path):
    output_path = tmp_path / "out.json"
    fake_provider = FakeProvider()
    with patch.object(pipeline, "get_provider", return_value=fake_provider) as mock_call:
        code = pipeline.run_pipeline(FIXTURE, output_path, cwd=tmp_path, provider="gemini")

    assert code == 0
    assert mock_call.call_count == 1
    written = json.loads(output_path.read_text(encoding="utf-8"))
    assert len(written) == 1
    assert written[0]["vulnerability_type"] == "BOLA"
    assert (tmp_path / "context.json").is_file()


def test_run_pipeline_retries_on_invalid_output_then_succeeds(tmp_path: Path):
    output_path = tmp_path / "out.json"
    manifest_path = tmp_path / "run_manifest.json"
    fake_provider = FakeProvider()
    responses = ["khong phai json hop le", VALID_PAYLOAD_JSON]

    def fake_generate(prompt: str, *, system_prompt=None, context=None):
        return {"reply": responses.pop(0)}

    fake_provider.generate = fake_generate
    fake_provider.repair = lambda prompt, *, system_prompt=None, context=None: {"reply": VALID_PAYLOAD_JSON}

    with patch.object(pipeline, "get_provider", return_value=fake_provider):
        code = pipeline.run_pipeline(FIXTURE, output_path, cwd=tmp_path, provider="gemini", manifest_path=manifest_path)

    assert code == 0
    assert output_path.is_file()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["generation"]["repair_count"] == 1
    assert manifest["repair"] == {
        "attempts": 1, "initial_valid": False, "final_valid": True, "successful": True
    }


def test_run_pipeline_gives_up_after_max_repair_attempts(tmp_path: Path):
    output_path = tmp_path / "out.json"
    fake_provider = FakeProvider()
    fake_provider.generate = lambda prompt, *, system_prompt=None, context=None: {"reply": "khong bao gio hop le"}
    fake_provider.repair = lambda prompt, *, system_prompt=None, context=None: {"reply": "khong bao gio hop le"}

    with patch.object(pipeline, "get_provider", return_value=fake_provider):
        with pytest.raises(pipeline.PipelineError, match="Hết"):
            pipeline.run_pipeline(FIXTURE, output_path, cwd=tmp_path, provider="gemini")

    assert not output_path.is_file()


def test_run_pipeline_propagates_provider_error(tmp_path: Path):
    output_path = tmp_path / "out.json"

    def boom(*args, **kwargs):
        raise pipeline.PipelineError("provider thoát mã lỗi 1")

    fake_provider = Mock()
    fake_provider.name = "gemini"
    fake_provider.model = "test-model"
    fake_provider.generate.side_effect = pipeline.PipelineError("provider thoát mã lỗi 1")

    with patch.object(pipeline, "get_provider", return_value=fake_provider):
        with pytest.raises(pipeline.PipelineError, match="thoát mã lỗi"):
            pipeline.run_pipeline(FIXTURE, output_path, cwd=tmp_path, provider="gemini")


def test_run_pipeline_records_generation_usage_in_manifest(tmp_path: Path):
    output_path = tmp_path / "out.json"
    manifest_path = tmp_path / "manifest.json"
    fake_provider = FakeProvider()
    fake_provider.model = "gemini-2.0-flash"
    fake_provider.generate = lambda prompt, *, system_prompt=None, context=None: {
        "reply": VALID_PAYLOAD_JSON,
        "usage": {"prompt_tokens": 42, "completion_tokens": 8, "total_tokens": 50},
        "model": "gemini-2.0-flash",
        "latency_seconds": 0.25,
    }
    fake_provider.repair = lambda prompt, *, system_prompt=None, context=None: {
        "reply": VALID_PAYLOAD_JSON,
        "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7},
        "model": "gemini-2.0-flash",
        "latency_seconds": 0.18,
    }

    with patch.object(pipeline, "get_provider", return_value=fake_provider):
        code = pipeline.run_pipeline(FIXTURE, output_path, cwd=tmp_path, provider="gemini", manifest_path=manifest_path)

    assert code == 0
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["llm"]["usage_available"] is True
    assert manifest["llm"]["prompt_tokens"] == 42
    assert manifest["llm"]["completion_tokens"] == 8
    assert manifest["llm"]["total_tokens"] == 50
    assert manifest["llm"]["model"] == "gemini-2.0-flash"


def test_run_pipeline_accumulates_repair_usage_with_generation_usage(tmp_path: Path):
    output_path = tmp_path / "out.json"
    manifest_path = tmp_path / "manifest.json"
    fake_provider = FakeProvider()
    fake_provider.model = "deepseek-chat"
    responses = iter([
        {"reply": "khong phai json hop le", "usage": {"prompt_tokens": 10, "completion_tokens": 4, "total_tokens": 14}, "model": "deepseek-chat", "latency_seconds": 0.3},
        {"reply": VALID_PAYLOAD_JSON, "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5}, "model": "deepseek-chat", "latency_seconds": 0.2},
    ])
    fake_provider.generate = lambda prompt, *, system_prompt=None, context=None: next(responses)
    fake_provider.repair = lambda prompt, *, system_prompt=None, context=None: {
        "reply": VALID_PAYLOAD_JSON,
        "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
        "model": "deepseek-chat",
        "latency_seconds": 0.2,
    }

    with patch.object(pipeline, "get_provider", return_value=fake_provider):
        code = pipeline.run_pipeline(FIXTURE, output_path, cwd=tmp_path, provider="deepseek", manifest_path=manifest_path)

    assert code == 0
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["llm"]["prompt_tokens"] == 13
    assert manifest["llm"]["completion_tokens"] == 6
    assert manifest["llm"]["total_tokens"] == 19
    assert manifest["llm"]["provider"] == "deepseek"
    assert manifest["llm"]["model"] == "deepseek-chat"


def test_run_pipeline_keeps_missing_usage_unavailable_no_fake_zero(tmp_path: Path):
    output_path = tmp_path / "out.json"
    manifest_path = tmp_path / "manifest.json"
    fake_provider = FakeProvider()
    fake_provider.model = "gemini-2.5-flash"
    fake_provider.generate = lambda prompt, *, system_prompt=None, context=None: {
        "reply": VALID_PAYLOAD_JSON,
        "model": "gemini-2.5-flash",
        "latency_seconds": 0.15,
    }
    fake_provider.repair = lambda prompt, *, system_prompt=None, context=None: {
        "reply": VALID_PAYLOAD_JSON,
        "model": "gemini-2.5-flash",
        "latency_seconds": 0.12,
    }

    with patch.object(pipeline, "get_provider", return_value=fake_provider):
        code = pipeline.run_pipeline(FIXTURE, output_path, cwd=tmp_path, provider="gemini", manifest_path=manifest_path)

    assert code == 0
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["llm"]["usage_available"] is False
    assert manifest["llm"]["prompt_tokens"] is None
    assert manifest["llm"]["completion_tokens"] is None
    assert manifest["llm"]["total_tokens"] is None
    assert manifest["llm"]["model"] == "gemini-2.5-flash"
