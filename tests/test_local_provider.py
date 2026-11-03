from __future__ import annotations

from unittest.mock import Mock, patch

import pytest
import requests

from core.local_client import LocalLLMError, call_local, resolve_api_key
from core.providers import LocalProvider, get_provider


def test_resolve_api_key_default_ollama():
    key = resolve_api_key()
    assert key == "ollama"


def test_get_provider_local_and_aliases():
    p_local = get_provider("local")
    assert isinstance(p_local, LocalProvider)

    p_ollama = get_provider("ollama")
    assert isinstance(p_ollama, LocalProvider)

    p_vllm = get_provider("vllm")
    assert isinstance(p_vllm, LocalProvider)


def test_call_local_success():
    fake_response = {
        "model": "qwen2.5-coder",
        "choices": [{"message": {"content": "[]"}}],
        "usage": {"total_tokens": 42},
    }
    mock_resp = Mock()
    mock_resp.ok = True
    mock_resp.json.return_value = fake_response

    with patch("requests.post", return_value=mock_resp) as mock_post:
        res = call_local("test prompt", model="qwen2.5-coder")

    assert res["reply"] == "[]"
    assert res["model"] == "qwen2.5-coder"
    assert res["usage"]["total_tokens"] == 42
    assert mock_post.called


def test_call_local_timeout_raises():
    with patch("requests.post", side_effect=requests.exceptions.Timeout("timed out")):
        with pytest.raises(LocalLLMError, match="timeout"):
            call_local("prompt", timeout=1.0)
