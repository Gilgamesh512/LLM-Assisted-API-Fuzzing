"""
core/local_client.py — Client gọi Local LLM (Ollama, vLLM, LocalAI) hoặc On-Premise OpenAI-compatible endpoints.

Phục vụ yêu cầu Doanh nghiệp: Bảo vệ quyền riêng tư dữ liệu (Zero Data Retention),
cho phép chạy hoàn toàn Offline/On-premise mà không cần gửi API specs ra Cloud.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any

import requests

DEFAULT_BASE_URL = os.environ.get("LOCAL_LLM_URL", "http://localhost:11434/v1")
DEFAULT_MODEL = os.environ.get("LOCAL_LLM_MODEL", "qwen2.5-coder")
DEFAULT_TIMEOUT_SECONDS = 90.0


class LocalLLMError(RuntimeError):
    """Lỗi khi gọi Local LLM qua OpenAI-compatible API."""


def resolve_api_key(explicit_key: str | None = None) -> str:
    """Xác định API key cho Local LLM (mặc định 'ollama' / 'EMPTY' nếu không cấu hình)."""
    if explicit_key and explicit_key.strip():
        return explicit_key.strip()
    env_key = os.environ.get("LOCAL_LLM_API_KEY")
    if env_key and env_key.strip():
        return env_key.strip()
    return "ollama"  # Ollama và vLLM chấp nhận bất kỳ dummy key nào


def call_local(
    prompt: str,
    *,
    api_key: str | None = None,
    model: str = DEFAULT_MODEL,
    base_url: str = DEFAULT_BASE_URL,
    system_prompt: str | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Gọi OpenAI-compatible Chat Completions API của local engine (Ollama, vLLM, etc.)."""
    key = resolve_api_key(api_key)
    normalized_base = base_url.rstrip("/")
    endpoint = f"{normalized_base}/chat/completions"

    messages: list[dict[str, str]] = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})

    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }
    payload: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "temperature": 0.0,
    }

    start = time.perf_counter()
    try:
        response = requests.post(endpoint, headers=headers, json=payload, timeout=timeout)
    except requests.exceptions.Timeout as exc:
        raise LocalLLMError(f"Local LLM timeout sau {timeout}s ({endpoint})") from exc
    except requests.exceptions.RequestException as exc:
        raise LocalLLMError(f"Lỗi mạng khi kết nối Local LLM ({endpoint}): {exc}") from exc

    latency = round(time.perf_counter() - start, 3)

    if not response.ok:
        raise LocalLLMError(
            f"Local LLM server trả mã lỗi {response.status_code} ({response.reason}): {response.text[:500]}"
        )

    try:
        data = response.json()
    except json.JSONDecodeError as exc:
        raise LocalLLMError(f"Local LLM không trả JSON hợp lệ: {response.text[:500]}") from exc

    choices = data.get("choices")
    if not choices or not isinstance(choices, list):
        raise LocalLLMError(f"Response thiếu trường 'choices': {data}")

    reply = choices[0].get("message", {}).get("content", "")
    return {
        "reply": reply,
        "model": data.get("model", model),
        "usage": data.get("usage"),
        "latency_seconds": latency,
    }
