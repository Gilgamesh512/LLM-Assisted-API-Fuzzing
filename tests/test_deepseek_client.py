"""tests/test_deepseek_client.py — Test cho Task B2 (deepseek_client.py).

Không gọi mạng thật: mock requests.post để kiểm tra logic resolve key,
xử lý lỗi, và parse response — độc lập với việc có API key thật hay không.
Việc gọi API DeepSeek thật (smoke test) chạy riêng qua:
    python core/deepseek_client.py --smoke-test
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
import requests

import core.deepseek_client as ds


@pytest.fixture(autouse=True)
def _isolate_key_sources(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Đảm bảo mỗi test không bị ảnh hưởng bởi env var / settings.json thật trên máy."""
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.setattr(ds, "USER_SETTINGS_PATH", tmp_path / "settings.json")


def test_resolve_api_key_missing_raises_clear_error():
    with pytest.raises(ds.DeepSeekAPIError, match="Không tìm thấy DeepSeek API key"):
        ds.resolve_api_key()


def test_resolve_api_key_prefers_explicit_over_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "env-key")
    assert ds.resolve_api_key("explicit-key") == "explicit-key"


def test_resolve_api_key_falls_back_to_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "env-key")
    assert ds.resolve_api_key() == "env-key"


def test_resolve_api_key_falls_back_to_user_settings_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    settings_path = tmp_path / "settings.json"
    settings_path.write_text(json.dumps({"env": {"API_KEY": "file-key"}}), encoding="utf-8")
    monkeypatch.setattr(ds, "USER_SETTINGS_PATH", settings_path)
    assert ds.resolve_api_key() == "file-key"


def test_call_deepseek_success_parses_reply():
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "model": "deepseek-chat",
        "choices": [{"message": {"content": "Xin chào!"}}],
        "usage": {"total_tokens": 42},
    }
    with patch.object(ds.requests, "post", return_value=mock_response) as mock_post:
        result = ds.call_deepseek("test prompt", api_key="k")

    assert result["reply"] == "Xin chào!"
    assert result["model"] == "deepseek-chat"
    assert result["usage"] == {"total_tokens": 42}
    assert result["latency_seconds"] >= 0
    called_url = mock_post.call_args.args[0]
    assert called_url == "https://api.deepseek.com/chat/completions"


def test_call_deepseek_http_error_raises():
    mock_response = Mock()
    mock_response.status_code = 401
    mock_response.text = "Unauthorized"
    with patch.object(ds.requests, "post", return_value=mock_response):
        with pytest.raises(ds.DeepSeekAPIError, match="401"):
            ds.call_deepseek("test prompt", api_key="bad-key")


def test_call_deepseek_network_error_raises():
    with patch.object(ds.requests, "post", side_effect=requests.ConnectionError("boom")):
        with pytest.raises(ds.DeepSeekAPIError, match="Lỗi mạng"):
            ds.call_deepseek("test prompt", api_key="k")


def test_call_deepseek_malformed_response_raises():
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"unexpected": "shape"}
    with patch.object(ds.requests, "post", return_value=mock_response):
        with pytest.raises(ds.DeepSeekAPIError, match="thiếu trường mong đợi"):
            ds.call_deepseek("test prompt", api_key="k")
