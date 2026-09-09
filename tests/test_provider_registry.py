from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.providers import DeepSeekProvider, GeminiProvider, get_provider
from core.validator import validate_llm_output


@pytest.mark.parametrize(
    ("provider_name", "expected_cls"),
    [("gemini", GeminiProvider), ("deepseek", DeepSeekProvider)],
)
def test_provider_registry_selects_expected_adapter(provider_name: str, expected_cls: type):
    provider = get_provider(provider_name)
    assert isinstance(provider, expected_cls)


def test_provider_metadata_exposes_runtime_model():
    provider = get_provider("gemini", model="gemini-2.0-flash")
    assert provider.metadata()["provider"] == "gemini"
    assert provider.metadata()["model"] == "gemini-2.0-flash"


def test_same_validator_applies_to_both_provider_outputs():
    payload = json.dumps([
        {
            "method": "GET",
            "path": "/api/users/{id}",
            "target_parameter": "id",
            "location": "path",
            "vulnerability_type": "BOLA",
            "payload_value": "2",
            "rationale": "path traversal of user id",
            "expected_indicator": "idor response"
        }
    ])
    assert validate_llm_output(payload).ok is True
    assert validate_llm_output(payload).payloads[0].vulnerability_type.value == "BOLA"


def test_missing_api_key_fails_with_provider_specific_message(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    provider = get_provider("gemini")
    with pytest.raises(RuntimeError, match="GEMINI_API_KEY"):
        provider.resolve_api_key()
