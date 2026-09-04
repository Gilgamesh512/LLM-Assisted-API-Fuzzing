"""tests/test_gemini_client.py — Test cho gemini_client.py (provider phụ dùng
để kiểm thử pipeline sớm, trước khi có key DeepSeek chính thức của Task B2).

Không gọi mạng thật: mock requests.post. Việc gọi API Gemini thật (smoke
test) chạy riêng qua:
    python core/gemini_client.py --smoke-test
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock, patch

import pytest
import requests

import core.gemini_client as gc


@pytest.fixture(autouse=True)
def _isolate_key_sources(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Đảm bảo mỗi test không bị ảnh hưởng bởi env var / .env thật trên máy."""
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setattr(gc, "DOTENV_PATH", tmp_path / ".env")


def test_resolve_api_key_missing_raises_clear_error():
    with pytest.raises(gc.GeminiAPIError, match="Không tìm thấy Gemini API key"):
        gc.resolve_api_key()


def test_resolve_api_key_prefers_explicit_over_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("GEMINI_API_KEY", "env-key")
    assert gc.resolve_api_key("explicit-key") == "explicit-key"


def test_resolve_api_key_falls_back_to_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("GEMINI_API_KEY", "env-key")
    assert gc.resolve_api_key() == "env-key"


def test_resolve_api_key_falls_back_to_dotenv_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    dotenv_path = tmp_path / ".env"
    dotenv_path.write_text('GEMINI_API_KEY="file-key"\n', encoding="utf-8")
    monkeypatch.setattr(gc, "DOTENV_PATH", dotenv_path)
    assert gc.resolve_api_key() == "file-key"


def test_call_gemini_success_parses_reply():
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "candidates": [{"content": {"parts": [{"text": "Xin chào!"}]}}],
        "usageMetadata": {"totalTokenCount": 42},
    }
    with patch.object(gc.requests, "post", return_value=mock_response) as mock_post:
        result = gc.call_gemini("test prompt", api_key="k")

    assert result["reply"] == "Xin chào!"
    assert result["model"] == gc.DEFAULT_MODEL
    assert result["usage"] == {"totalTokenCount": 42}
    assert result["latency_seconds"] >= 0
    body = mock_post.call_args.kwargs["json"]
    assert body["generationConfig"] == {
        "temperature": 0.2,
        "responseMimeType": "application/json",
    }
    called_url = mock_post.call_args.args[0]
    assert called_url == f"https://generativelanguage.googleapis.com/v1beta/models/{gc.DEFAULT_MODEL}:generateContent"
    assert mock_post.call_args.kwargs["params"] == {"key": "k"}


def test_call_gemini_http_error_raises():
    mock_response = Mock()
    mock_response.status_code = 403
    mock_response.text = "Forbidden"
    with patch.object(gc.requests, "post", return_value=mock_response):
        with pytest.raises(gc.GeminiAPIError, match="403"):
            gc.call_gemini("test prompt", api_key="bad-key")


def test_call_gemini_network_error_raises():
    with patch.object(gc.requests, "post", side_effect=requests.ConnectionError("boom")):
        with pytest.raises(gc.GeminiAPIError, match="Lỗi mạng"):
            gc.call_gemini("test prompt", api_key="k")


def test_call_gemini_malformed_response_raises():
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"unexpected": "shape"}
    with patch.object(gc.requests, "post", return_value=mock_response):
        with pytest.raises(gc.GeminiAPIError, match="thiếu trường mong đợi"):
            gc.call_gemini("test prompt", api_key="k")
