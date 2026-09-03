"""
core/gemini_client.py — Client Google Gemini dùng để thử nghiệm pipeline B
TRƯỚC KHI có key DeepSeek chính thức.

Lưu ý: kế hoạch triển khai đề tài chỉ định rõ dùng DeepSeek cho hệ thống
chính thức (xem core/deepseek_client.py — Task B2). Module này KHÔNG thay
thế DeepSeek trong sản phẩm bàn giao, chỉ dùng để kiểm thử nhanh logic
gọi API / xử lý response trong lúc chưa có key DeepSeek, và làm phương án
dự phòng nếu DeepSeek bị giới hạn quota khi demo.

Cùng interface (đối xứng) với deepseek_client.call_deepseek() — cả 2 hàm
trả về dict {reply, model, usage, latency_seconds} — để core/validator.py
và skill sinh payload có thể dùng chung logic xử lý output bất kể provider
nào được gọi.

API key được đọc theo thứ tự ưu tiên (không hardcode trong code/git):
1. Tham số `api_key` truyền trực tiếp.
2. Biến môi trường `GEMINI_API_KEY`.
3. File `.env` ở thư mục gốc workspace (`.env`, dòng
   `GEMINI_API_KEY=...`) — đã có trong .gitignore (`*.env`), không commit.

Sử dụng nhanh:
    python core/gemini_client.py "Chào, bạn là ai?"
    python core/gemini_client.py --smoke-test   # chạy 1-2 request mẫu, in log

Dùng trong code:
    from core.gemini_client import call_gemini
    reply = call_gemini("Test message")
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path
from typing import Any

import requests

DEFAULT_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"
# gemini-flash-lite-latest: model mặc định đã xác nhận hoạt động ổn định
# (không bị 429 quota) trong dự án cá nhân khác của người dùng.
DEFAULT_MODEL = "gemini-flash-lite-latest"
DEFAULT_TIMEOUT_SECONDS = 60

DOTENV_PATH = Path(__file__).resolve().parent.parent / ".env"


class GeminiAPIError(RuntimeError):
    """Lỗi khi gọi Gemini API (thiếu key, lỗi mạng, hoặc lỗi từ server)."""


def _read_key_from_dotenv() -> str | None:
    """Đọc GEMINI_API_KEY từ file .env (KEY=VALUE, bỏ qua dòng trống/comment)."""
    if not DOTENV_PATH.is_file():
        return None
    try:
        lines = DOTENV_PATH.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        if key.strip() == "GEMINI_API_KEY":
            value = value.strip().strip('"').strip("'")
            return value or None
    return None


def resolve_api_key(explicit_key: str | None = None) -> str:
    """Xác định API key theo thứ tự ưu tiên; ném lỗi rõ ràng nếu không tìm thấy."""
    if explicit_key and explicit_key.strip():
        return explicit_key.strip()

    env_key = os.environ.get("GEMINI_API_KEY")
    if env_key and env_key.strip():
        return env_key.strip()

    dotenv_key = _read_key_from_dotenv()
    if dotenv_key:
        return dotenv_key

    raise GeminiAPIError(
        "Không tìm thấy Gemini API key. Cung cấp qua một trong ba cách:\n"
        "  1. Biến môi trường GEMINI_API_KEY\n"
        "  2. Tham số api_key khi gọi call_gemini()\n"
        f"  3. Dòng GEMINI_API_KEY=... trong {DOTENV_PATH}\n"
        "Lấy key tại: https://aistudio.google.com/apikey"
    )


def call_gemini(
    prompt: str,
    *,
    api_key: str | None = None,
    model: str = DEFAULT_MODEL,
    base_url: str = DEFAULT_BASE_URL,
    system_prompt: str | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Gọi Gemini generateContent API với một prompt đơn giản.

    Trả về dict cùng cấu trúc với deepseek_client.call_deepseek():
    reply (str), model, usage, latency_seconds — để B4 (validator.py) và
    skill sinh payload dùng chung logic xử lý bất kể provider.

    Ném GeminiAPIError nếu thiếu key, lỗi mạng, timeout, hoặc server trả
    lỗi (4xx/5xx) — không nuốt lỗi âm thầm.
    """
    key = resolve_api_key(api_key)

    body: dict[str, Any] = {"contents": [{"parts": [{"text": prompt}]}]}
    if system_prompt:
        body["systemInstruction"] = {"parts": [{"text": system_prompt}]}

    url = f"{base_url.rstrip('/')}/models/{model}:generateContent"

    started = time.monotonic()
    try:
        response = requests.post(
            url,
            params={"key": key},
            json=body,
            timeout=timeout,
        )
    except requests.RequestException as exc:
        raise GeminiAPIError(f"Lỗi mạng khi gọi Gemini API ({url}): {exc}") from exc
    latency = time.monotonic() - started

    if response.status_code != 200:
        raise GeminiAPIError(
            f"Gemini API trả lỗi HTTP {response.status_code}: {response.text[:500]}"
        )

    try:
        data = response.json()
    except ValueError as exc:
        raise GeminiAPIError(f"Không parse được JSON từ response: {exc}") from exc

    try:
        reply = data["candidates"][0]["content"]["parts"][0]["text"]
    except (KeyError, IndexError, TypeError) as exc:
        raise GeminiAPIError(
            f"Response thiếu trường mong đợi (candidates[0].content.parts[0].text): {data}"
        ) from exc

    return {
        "reply": reply,
        "model": model,
        "usage": data.get("usageMetadata"),
        "latency_seconds": round(latency, 3),
    }


def _smoke_test() -> int:
    """Chạy 1-2 request mẫu và in log — dùng để kiểm thử pipeline sớm với Gemini."""
    samples = [
        "Trả lời đúng một câu: bạn là mô hình nào?",
        (
            "Đây là 1 endpoint API: "
            '{"method": "GET", "path": "/api/users/{id}", "jwt": true}. '
            "Hãy nêu ngắn gọn 1 loại lỗ hổng cần kiểm thử cho endpoint này, không vượt quá 1 câu."
        ),
    ]
    print(f"[gemini_client] Smoke test — model={DEFAULT_MODEL}, base_url={DEFAULT_BASE_URL}")
    print("[gemini_client] LƯU Ý: dùng để test pipeline sớm, sản phẩm bàn giao chính thức của Task B là DeepSeek.")
    try:
        resolve_api_key()  # fail sớm với thông báo rõ ràng nếu chưa có key
    except GeminiAPIError as exc:
        print(f"[gemini_client] LỖI: {exc}", file=sys.stderr)
        return 1

    for i, prompt in enumerate(samples, start=1):
        print(f"\n--- Request mẫu {i}/{len(samples)} ---")
        print(f"Prompt: {prompt}")
        try:
            result = call_gemini(prompt)
        except GeminiAPIError as exc:
            print(f"[gemini_client] LỖI ở request {i}: {exc}", file=sys.stderr)
            return 1
        print(f"Reply: {result['reply']}")
        print(f"Model: {result['model']} | Latency: {result['latency_seconds']}s | Usage: {result['usage']}")

    print("\n[gemini_client] Smoke test THÀNH CÔNG — API key hoạt động, kết nối Gemini OK.")
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
    parser = argparse.ArgumentParser(description="Client Gemini dùng để test pipeline sớm trước khi có key DeepSeek.")
    parser.add_argument("prompt", nargs="?", help="Prompt để gửi (bỏ qua nếu dùng --smoke-test)")
    parser.add_argument(
        "--smoke-test", action="store_true", help="Chạy 1-2 request mẫu, in log đầy đủ"
    )
    parser.add_argument("--model", default=DEFAULT_MODEL, help=f"Model Gemini (mặc định: {DEFAULT_MODEL})")
    args = parser.parse_args(argv)

    if args.smoke_test:
        return _smoke_test()

    if not args.prompt:
        parser.print_help()
        return 1

    try:
        result = call_gemini(args.prompt, model=args.model)
    except GeminiAPIError as exc:
        print(f"[gemini_client] Lỗi: {exc}", file=sys.stderr)
        return 1

    print(result["reply"])
    print(f"[gemini_client] model={result['model']} latency={result['latency_seconds']}s usage={result['usage']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
