"""
scripts/switch_ai.py — Cơ chế đổi "bộ não" AI cho `deepcode` CLI: chuyển
qua lại giữa DeepSeek (chính thức, trả phí) và Gemini (miễn phí, dùng thử
nghiệm trước khi mua key DeepSeek) chỉ bằng 1 lệnh.

Cách hoạt động (khớp đúng cơ chế ưu tiên config của deepcode-cli — xem
docs/configuration_en.md ở gốc deepcode-cli-main: "Project settings override
user settings"):

- MODEL / BASE_URL / thinkingEnabled / reasoningEffort (không nhạy cảm) được
    ghi vào PROJECT-level settings — `.deepcode/settings.json` ở workspace root
  (file này CÓ commit git, nhưng không bao giờ chứa key).
- API_KEY (nhạy cảm) được ghi vào USER-level settings —
  `~/.deepcode/settings.json` (KHÔNG commit git, riêng tư).
- Vì env được merge theo từng key (`{...userEnv, ...projectEnv, ...systemEnv}`)
  và project không set API_KEY, giá trị API_KEY ở user-level sẽ "lọt qua"
  bình thường trong khi MODEL/BASE_URL của project vẫn thắng.

Danh sách "bộ não" khả dụng lấy từ `.deepcode/providers.json` (cạnh file này
1 cấp lên) — thêm provider mới chỉ cần thêm 1 entry vào đó, không cần sửa
script.

API key của từng provider đọc từ workspace `.env` (gitignored), theo
tên biến khai báo ở `key_env_var` trong providers.json, ví dụ:

    DEEPSEEK_API_KEY=sk-...
    GEMINI_API_KEY=AIzaSy...

Sử dụng:
    python scripts/switch_ai.py gemini      # chuyển sang Gemini (free)
    python scripts/switch_ai.py deepseek    # chuyển sang DeepSeek (chính thức)
    python scripts/switch_ai.py status      # xem đang dùng provider nào
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
PROVIDERS_PATH = REPO_ROOT / ".deepcode" / "providers.json"
PROJECT_SETTINGS_PATH = REPO_ROOT / ".deepcode" / "settings.json"
DOTENV_PATH = REPO_ROOT / ".env"
USER_SETTINGS_PATH = Path.home() / ".deepcode" / "settings.json"


class SwitchAIError(RuntimeError):
    """Lỗi khi đổi provider (thiếu profile, thiếu key, file cấu hình hỏng)."""


def _load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SwitchAIError(f"File JSON không hợp lệ: {path} ({exc})") from exc


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def load_providers() -> dict[str, Any]:
    providers = _load_json(PROVIDERS_PATH)
    providers.pop("_comment", None)
    if not providers:
        raise SwitchAIError(f"Không đọc được provider nào từ {PROVIDERS_PATH}")
    return providers


def _read_key_from_dotenv(var_name: str) -> str | None:
    """Đọc 1 biến dạng KEY=VALUE từ file .env (bỏ qua dòng trống/comment)."""
    if not DOTENV_PATH.is_file():
        return None
    for line in DOTENV_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        if key.strip() == var_name:
            value = value.strip().strip('"').strip("'")
            return value or None
    return None


def switch_to(provider_name: str) -> str:
    """Chuyển deepcode sang `provider_name`. Trả về thông báo kết quả."""
    providers = load_providers()
    if provider_name not in providers:
        available = ", ".join(sorted(providers))
        raise SwitchAIError(f"Không có provider '{provider_name}'. Các provider khả dụng: {available}")

    profile = providers[provider_name]
    key_var = profile["key_env_var"]
    api_key = _read_key_from_dotenv(key_var)
    if not api_key:
        raise SwitchAIError(
            f"Chưa có key cho '{provider_name}'. Thêm dòng sau vào {DOTENV_PATH}:\n"
            f"  {key_var}=...\n"
            f"Lấy key tại: {profile.get('get_key_url', '(xem tài liệu provider)')}"
        )

    # 1) Ghi MODEL/BASE_URL/thinking vào project settings (commit được, không có key)
    project_settings = _load_json(PROJECT_SETTINGS_PATH)
    project_settings.setdefault("env", {})
    project_settings["env"].update(profile["env"])
    if "thinkingEnabled" in profile:
        project_settings["thinkingEnabled"] = profile["thinkingEnabled"]
    if "reasoningEffort" in profile:
        project_settings["reasoningEffort"] = profile["reasoningEffort"]
    else:
        project_settings.pop("reasoningEffort", None)
    _write_json(PROJECT_SETTINGS_PATH, project_settings)

    # 2) Ghi API_KEY vào user settings (riêng tư, không commit). Đồng thời "seed"
    #    TẤT CẢ key có trong .env vào các trường env.<PROVIDER>_API_KEY riêng —
    #    để lệnh /model NGAY TRONG deepcode (xem packages/core/src/settings.ts,
    #    applyModelConfigSelection) cũng tự tìm được key mỗi khi đổi qua lại,
    #    không chỉ khi đổi bằng script này.
    user_settings = _load_json(USER_SETTINGS_PATH)
    user_settings.setdefault("env", {})
    for other_profile in providers.values():
        other_key_var = other_profile["key_env_var"]
        other_key = _read_key_from_dotenv(other_key_var)
        if other_key:
            user_settings["env"][other_key_var] = other_key
    user_settings["env"]["API_KEY"] = api_key
    _write_json(USER_SETTINGS_PATH, user_settings)

    return (
        f"Đã chuyển deepcode sang '{provider_name}' "
        f"(model={profile['env']['MODEL']}, base_url={profile['env']['BASE_URL']}).\n"
        f"Chạy `deepcode` bình thường trong {REPO_ROOT.name}/ là dùng {provider_name} ngay.\n"
        f"(Đã đồng bộ key của các provider khác vào ~/.deepcode/settings.json — lệnh /model "
        f"ngay trong deepcode giờ cũng đổi qua lại được, không chỉ script này.)"
    )


def status() -> str:
    """So khớp project settings hiện tại với các provider đã khai báo."""
    providers = load_providers()
    project_settings = _load_json(PROJECT_SETTINGS_PATH)
    current_base_url = project_settings.get("env", {}).get("BASE_URL")
    current_model = project_settings.get("env", {}).get("MODEL")

    if current_base_url is None:
        return "Chưa có BASE_URL nào trong project settings — chưa từng chạy switch_ai.py."

    for name, profile in providers.items():
        if profile["env"]["BASE_URL"] == current_base_url:
            has_key = bool(_read_key_from_dotenv(profile["key_env_var"]))
            key_note = "có key trong .env" if has_key else "CHƯA có key trong .env"
            return f"Đang dùng: {name} (model={current_model}) — {key_note}"

    return f"BASE_URL hiện tại ({current_base_url}) không khớp provider nào đã khai báo — cấu hình tuỳ chỉnh."


def _ensure_utf8_console() -> None:
    """Ép stdout/stderr sang UTF-8 — console Windows mặc định (cp1252/cp437)
    sẽ ném UnicodeEncodeError khi in tiếng Việt có dấu nếu không làm việc này.
    """
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (AttributeError, ValueError, OSError):
                pass


def main(argv: list[str] | None = None) -> int:
    _ensure_utf8_console()
    parser = argparse.ArgumentParser(description="Đổi bộ não AI cho deepcode CLI (DeepSeek <-> Gemini).")
    parser.add_argument("provider", help="Tên provider (xem .deepcode/providers.json), hoặc 'status'")
    args = parser.parse_args(argv)

    try:
        if args.provider == "status":
            print(status())
        else:
            print(switch_to(args.provider))
    except SwitchAIError as exc:
        print(f"[switch_ai] Lỗi: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
