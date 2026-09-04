"""tests/test_switch_ai.py — Test cho scripts/switch_ai.py (cơ chế đổi
provider DeepSeek <-> Gemini cho deepcode CLI).

Toàn bộ đường dẫn file (providers.json, project settings.json, user
settings.json, .env) đều được trỏ vào tmp_path — không đụng tới cấu hình
thật trên máy khi chạy test.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import scripts.switch_ai as sw  # noqa: E402

PROVIDERS_FIXTURE = {
    "deepseek": {
        "env": {"MODEL": "deepseek-v4-pro", "BASE_URL": "https://api.deepseek.com"},
        "thinkingEnabled": True,
        "reasoningEffort": "max",
        "key_env_var": "DEEPSEEK_API_KEY",
    },
    "gemini": {
        "env": {"MODEL": "gemini-3.7-flash", "BASE_URL": "https://generativelanguage.googleapis.com/v1beta/openai/"},
        "thinkingEnabled": False,
        "key_env_var": "GEMINI_API_KEY",
    },
}


@pytest.fixture(autouse=True)
def _isolate_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    providers_path = tmp_path / "providers.json"
    providers_path.write_text(json.dumps(PROVIDERS_FIXTURE), encoding="utf-8")

    monkeypatch.setattr(sw, "PROVIDERS_PATH", providers_path)
    monkeypatch.setattr(sw, "PROJECT_SETTINGS_PATH", tmp_path / "project_settings.json")
    monkeypatch.setattr(sw, "USER_SETTINGS_PATH", tmp_path / "user_settings.json")
    monkeypatch.setattr(sw, "DOTENV_PATH", tmp_path / ".env")


def _write_dotenv(tmp_path: Path, **pairs: str) -> None:
    lines = [f"{k}={v}" for k, v in pairs.items()]
    (tmp_path / ".env").write_text("\n".join(lines), encoding="utf-8")


def test_switch_without_key_raises_clear_error(tmp_path: Path):
    with pytest.raises(sw.SwitchAIError, match="Chưa có key"):
        sw.switch_to("gemini")


def test_switch_unknown_provider_raises(tmp_path: Path):
    _write_dotenv(tmp_path, GEMINI_API_KEY="g-key")
    with pytest.raises(sw.SwitchAIError, match="Không có provider"):
        sw.switch_to("chatgpt")


def test_switch_to_gemini_writes_project_and_user_settings(tmp_path: Path):
    _write_dotenv(tmp_path, GEMINI_API_KEY="g-key")
    sw.switch_to("gemini")

    project = json.loads(sw.PROJECT_SETTINGS_PATH.read_text(encoding="utf-8"))
    assert project["env"]["MODEL"] == "gemini-3.7-flash"
    assert project["env"]["BASE_URL"] == "https://generativelanguage.googleapis.com/v1beta/openai/"
    assert project["thinkingEnabled"] is False
    assert "reasoningEffort" not in project
    assert "API_KEY" not in project["env"]  # key KHÔNG được ghi vào file commit-được

    user = json.loads(sw.USER_SETTINGS_PATH.read_text(encoding="utf-8"))
    assert user["env"]["API_KEY"] == "g-key"


def test_switch_preserves_existing_project_settings_fields(tmp_path: Path):
    sw.PROJECT_SETTINGS_PATH.write_text(
        json.dumps({"enabledSkills": {"api-payload-generator": True}}), encoding="utf-8"
    )
    _write_dotenv(tmp_path, GEMINI_API_KEY="g-key")
    sw.switch_to("gemini")

    project = json.loads(sw.PROJECT_SETTINGS_PATH.read_text(encoding="utf-8"))
    assert project["enabledSkills"] == {"api-payload-generator": True}
    assert project["env"]["MODEL"] == "gemini-3.7-flash"


def test_switching_back_and_forth_updates_reasoning_effort(tmp_path: Path):
    _write_dotenv(tmp_path, GEMINI_API_KEY="g-key", DEEPSEEK_API_KEY="d-key")

    sw.switch_to("deepseek")
    project = json.loads(sw.PROJECT_SETTINGS_PATH.read_text(encoding="utf-8"))
    assert project["reasoningEffort"] == "max"

    sw.switch_to("gemini")
    project = json.loads(sw.PROJECT_SETTINGS_PATH.read_text(encoding="utf-8"))
    assert "reasoningEffort" not in project  # phải bị xoá, không sót lại từ deepseek


def test_status_reports_active_provider_and_key_presence(tmp_path: Path):
    _write_dotenv(tmp_path, GEMINI_API_KEY="g-key")
    sw.switch_to("gemini")
    result = sw.status()
    assert "gemini" in result
    assert "có key trong .env" in result


def test_status_before_any_switch(tmp_path: Path):
    result = sw.status()
    assert "chưa từng chạy switch_ai.py" in result
