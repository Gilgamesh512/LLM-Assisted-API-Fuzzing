from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.validator import build_repair_prompt as _build_repair_prompt


def build_payload_generation_prompt(context: str | Path | list[dict[str, Any]] | dict[str, Any]) -> str:
    """Build the shared prompt for all providers."""
    if isinstance(context, (str, Path)):
        path = Path(context)
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                data = path.read_text(encoding="utf-8")
        else:
            data = path.name
    elif isinstance(context, list):
        data = context
    elif isinstance(context, dict):
        data = context
    else:
        data = str(context)
    return (
        "Bạn là chuyên gia kiểm thử bảo mật API REST. "
        "Sinh payload tấn công context-aware, an toàn trong môi trường lab, chỉ để benchmark.\n\n"
        "Cấu trúc input (context):\n"
        f"{json.dumps(data, ensure_ascii=False, indent=2) if isinstance(data, (dict, list)) else str(data)}\n\n"
        "Yêu cầu:\n"
        "1. Chỉ trả về JSON array hợp lệ.\n"
        "2. Mỗi mục phải tuân đúng schema AttackPayload: method, path, target_parameter, location, vulnerability_type, payload_value, rationale, expected_indicator.\n"
        "3. Tập trung vào SQLi, BOLA, SSRF, JWT/Auth, FileUpload, XSS, Other.\n"
        "4. Không giải thích ngoài JSON.\n"
        "5. Không tạo payload không phù hợp với context API.\n"
    )


def build_repair_prompt(raw_text: str, error_message: str, attempt: int) -> str:
    return _build_repair_prompt(raw_text, error_message, attempt)


__all__ = ["build_payload_generation_prompt", "build_repair_prompt"]
