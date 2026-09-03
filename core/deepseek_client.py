"""
core/deepseek_client.py — Task B2 (phần "Đăng ký & test DeepSeek API").

Hàm gọi DeepSeek API cơ bản, độc lập với CLI `deepcode` — dùng để:
1. Xác nhận API key hoạt động (kết nối thành công).
2. Có log test mẫu (request/response thật) làm bằng chứng cho báo cáo B,
   tách biệt khỏi pipeline skill `api-payload-generator` chạy qua deepcode CLI.

DeepSeek dùng API tương thích OpenAI (chat completions), nên chỉ cần
`requests` thuần, không phụ thuộc SDK riêng.

API key được đọc theo thứ tự ưu tiên (không hardcode trong code/git):
1. Tham số `api_key` truyền trực tiếp.
2. Biến môi trường `DEEPSEEK_API_KEY`.
3. `env.API_KEY` trong `~/.deepcode/settings.json` (file cấu hình dùng chung
   với CLI `deepcode`, KHÔNG nằm trong repo git).

Sử dụng nhanh:
    python core/deepseek_client.py "Chào, bạn là ai?"
    python core/deepseek_client.py --smoke-test   # chạy 1-2 request mẫu, in log

Dùng trong code:
    from core.deepseek_client import call_deepseek
    reply = call_deepseek("Test message")
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import requests

DEFAULT_BASE_URL = "https://api.deepseek.com"
DEFAULT_MODEL = "deepseek-chat"
DEFAULT_TIMEOUT_SECONDS = 60

USER_SETTINGS_PATH = Path.home() / ".deepcode" / "settings.json"


class DeepSeekAPIError(RuntimeError):
    """Lỗi khi gọi DeepSeek API (thiếu key, lỗi mạng, hoặc lỗi từ server)."""


def _read_key_from_user_settings() -> str | None:
    """Đọc env.API_KEY từ ~/.deepcode/settings.json nếu file tồn tại và hợp lệ."""
    if not USER_SETTINGS_PATH.is_file():
        return None
    try:
        data = json.loads(USER_SETTINGS_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    key = data.get("env", {}).get("API_KEY")
    return key if isinstance(key, str) and key.strip() else None


def resolve_api_key(explicit_key: str | None = None) -> str:
    """Xác định API key theo thứ tự ưu tiên; ném lỗi rõ ràng nếu không tìm thấy."""
    if explicit_key and explicit_key.strip():
        return explicit_key.strip()

    env_key = os.environ.get("DEEPSEEK_API_KEY")
    if env_key and env_key.strip():
        return env_key.strip()

    settings_key = _read_key_from_user_settings()
    if settings_key:
        return settings_key

    raise DeepSeekAPIError(
        "Không tìm thấy DeepSeek API key. Cung cấp qua một trong ba cách:\n"
        "  1. Biến môi trường DEEPSEEK_API_KEY\n"
        "  2. Tham số api_key khi gọi call_deepseek()\n"
        f"  3. Trường env.API_KEY trong {USER_SETTINGS_PATH}\n"
        "Lấy key tại: https://platform.deepseek.com/api_keys"
    )


def call_deepseek(
    prompt: str,
    *,
    api_key: str | None = None,
    model: str = DEFAULT_MODEL,
    base_url: str = DEFAULT_BASE_URL,
    system_prompt: str | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Gọi DeepSeek Chat Completions API với một prompt đơn giản.

    Trả về dict gồm: reply (str), model, usage (token count nếu server trả),
    latency_seconds (thời gian round-trip, dùng để log test mẫu).

    Ném DeepSeekAPIError nếu thiếu key, lỗi mạng, timeout, hoặc server trả
    lỗi (4xx/5xx) — không nuốt lỗi âm thầm.
    """
    key = resolve_api_key(api_key)

    messages: list[dict[str, str]] = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})

    payload = {"model": model, "messages": messages, "stream": False}
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }
    url = f"{base_url.rstrip('/')}/chat/completions"

    started = time.monotonic()
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=timeout)
    except requests.RequestException as exc:
        raise DeepSeekAPIError(f"Lỗi mạng khi gọi DeepSeek API ({url}): {exc}") from exc
    latency = time.monotonic() - started

    if response.status_code != 200:
        raise DeepSeekAPIError(
            f"DeepSeek API trả lỗi HTTP {response.status_code}: {response.text[:500]}"
        )

    try:
        data = response.json()
    except json.JSONDecodeError as exc:
        raise DeepSeekAPIError(f"Không parse được JSON từ response: {exc}") from exc

    try:
        reply = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise DeepSeekAPIError(f"Response thiếu trường mong đợi (choices[0].message.content): {data}") from exc

    return {
        "reply": reply,
        "model": data.get("model", model),
        "usage": data.get("usage"),
        "latency_seconds": round(latency, 3),
    }


def _smoke_test() -> int:
    """Chạy 1-2 request mẫu và in log — dùng làm bằng chứng cho Task 2 (B)."""
    samples = [
        "Trả lời đúng một câu: bạn là mô hình nào?",
        (
            "Đây là 1 endpoint API: "
            '{"method": "GET", "path": "/api/users/{id}", "jwt": true}. '
            "Hãy nêu ngắn gọn 1 loại lỗ hổng cần kiểm thử cho endpoint này, không vượt quá 1 câu."
        ),
    ]
    print(f"[deepseek_client] Smoke test — model={DEFAULT_MODEL}, base_url={DEFAULT_BASE_URL}")
    try:
        resolve_api_key()  # fail sớm với thông báo rõ ràng nếu chưa có key
    except DeepSeekAPIError as exc:
        print(f"[deepseek_client] LỖI: {exc}", file=sys.stderr)
        return 1

    for i, prompt in enumerate(samples, start=1):
        print(f"\n--- Request mẫu {i}/{len(samples)} ---")
        print(f"Prompt: {prompt}")
        try:
            result = call_deepseek(prompt)
        except DeepSeekAPIError as exc:
            print(f"[deepseek_client] LỖI ở request {i}: {exc}", file=sys.stderr)
            return 1
        print(f"Reply: {result['reply']}")
        print(f"Model: {result['model']} | Latency: {result['latency_seconds']}s | Usage: {result['usage']}")

    print("\n[deepseek_client] Smoke test THÀNH CÔNG — API key hoạt động, kết nối DeepSeek OK.")
    return 0


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
    parser = argparse.ArgumentParser(description="Task B2 — Test kết nối DeepSeek API cơ bản.")
    parser.add_argument("prompt", nargs="?", help="Prompt để gửi (bỏ qua nếu dùng --smoke-test)")
    parser.add_argument(
        "--smoke-test", action="store_true", help="Chạy 1-2 request mẫu, in log đầy đủ (bằng chứng Task 2)"
    )
    parser.add_argument("--model", default=DEFAULT_MODEL, help=f"Model DeepSeek (mặc định: {DEFAULT_MODEL})")
    args = parser.parse_args(argv)

    if args.smoke_test:
        return _smoke_test()

    if not args.prompt:
        parser.print_help()
        return 1

    try:
        result = call_deepseek(args.prompt, model=args.model)
    except DeepSeekAPIError as exc:
        print(f"[deepseek_client] Lỗi: {exc}", file=sys.stderr)
        return 1

    print(result["reply"])
    print(f"[deepseek_client] model={result['model']} latency={result['latency_seconds']}s usage={result['usage']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
