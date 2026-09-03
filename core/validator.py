"""
core/validator.py — Task B4: Chuẩn hoá & xác thực output của LLM (JSON Guardrails).

DeepSeek (qua skill api-payload-generator, xem .deepcode/skills/) phải trả về
một mảng JSON payload tấn công có cấu trúc. Module này:

1. Trích JSON từ text trả về của LLM (kể cả khi LLM bọc trong ```json ... ```).
2. Validate cấu trúc bằng Pydantic — đúng field, đúng kiểu, đúng enum.
3. Nếu sai định dạng, sinh ra một "repair prompt" mô tả rõ lỗi để gửi ngược
   lại cho LLM sinh lại (đúng quy trình tự sửa lỗi mô tả trong kế hoạch B4).
4. Sau khi hợp lệ, payload này là thứ duy nhất được bàn giao cho Thành viên C
   (fuzzing engine) — đảm bảo 100% payload trước khi chuyển đi đều đúng cấu trúc.

Sử dụng nhanh:
    from core.validator import validate_llm_output

    result = validate_llm_output(raw_text_from_llm)
    if result.ok:
        payloads = result.payloads          # list[AttackPayload]
    else:
        next_prompt = result.repair_prompt   # gửi lại cho LLM
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, TypeAdapter, ValidationError

MAX_REPAIR_ATTEMPTS = 3  # đồng bộ với điều kiện dừng "3 lần thử thất bại" của phần C


class VulnerabilityType(str, Enum):
    """Các nhóm lỗ hổng mà đề tài nhắm tới (khớp với api_inventory.csv của A)."""

    SQLI = "SQLi"
    BOLA = "BOLA"
    SSRF = "SSRF"
    JWT_AUTH = "JWT/Auth"
    FILE_UPLOAD = "FileUpload"
    XSS = "XSS"
    OTHER = "Other"


class ParamLocation(str, Enum):
    PATH = "path"
    QUERY = "query"
    HEADER = "header"
    COOKIE = "cookie"
    BODY = "body"
    FORM_DATA = "form-data"


class AttackPayload(BaseModel):
    """Một payload tấn công context-aware do LLM sinh cho một endpoint cụ thể."""

    model_config = {"extra": "forbid"}

    method: str = Field(..., description="HTTP method, ví dụ GET/POST/PUT/DELETE")
    path: str = Field(..., description="Endpoint path, ví dụ /api/users/{id}")
    target_parameter: str = Field(..., description="Tên tham số bị nhắm tới")
    location: ParamLocation = Field(..., description="Vị trí tham số: path/query/header/cookie/body/form-data")
    vulnerability_type: VulnerabilityType
    payload_value: str = Field(..., description="Giá trị payload cụ thể sẽ gửi đi")
    rationale: str = Field(..., min_length=1, description="Vì sao payload này phù hợp ngữ cảnh endpoint")
    expected_indicator: str = Field(
        ..., min_length=1, description="Dấu hiệu kỳ vọng cho biết payload có tác dụng (vd: HTTP 500, độ trễ bất thường, lỗi SQL trong response)"
    )


_payload_list_adapter: TypeAdapter[list[AttackPayload]] = TypeAdapter(list[AttackPayload])

_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)


def _extract_json_text(raw_text: str) -> str:
    """Bóc phần JSON ra khỏi output của LLM (loại bỏ markdown code fence, text thừa)."""
    fence_match = _JSON_FENCE_RE.search(raw_text)
    if fence_match:
        return fence_match.group(1).strip()

    text = raw_text.strip()
    # Nếu LLM chèn giải thích trước/sau JSON, cắt theo cặp ngoặc ngoài cùng đầu tiên.
    start_candidates = [i for i in (text.find("["), text.find("{")) if i != -1]
    if not start_candidates:
        return text
    start = min(start_candidates)
    end_bracket = "]" if text[start] == "[" else "}"
    end = text.rfind(end_bracket)
    if end == -1 or end < start:
        return text
    return text[start : end + 1]


@dataclass
class ValidationResult:
    ok: bool
    payloads: list[AttackPayload] | None = None
    error_message: str | None = None
    repair_prompt: str | None = None
    attempt: int = 1


def _format_pydantic_errors(exc: ValidationError) -> str:
    lines = []
    for err in exc.errors():
        loc = " -> ".join(str(part) for part in err["loc"])
        lines.append(f"  - [{loc}] {err['msg']} (input={err.get('input')!r})")
    return "\n".join(lines)


def build_repair_prompt(raw_text: str, error_message: str, attempt: int) -> str:
    """Sinh prompt yêu cầu LLM tự sửa output sai định dạng."""
    return (
        f"Output trước của bạn KHÔNG hợp lệ (lần thử {attempt}/{MAX_REPAIR_ATTEMPTS}).\n\n"
        "Output đã nhận:\n"
        f"{raw_text}\n\n"
        "Lỗi cấu trúc:\n"
        f"{error_message}\n\n"
        "Hãy sinh lại DUY NHẤT một JSON array hợp lệ, không kèm giải thích, "
        "không bọc trong markdown, tuân thủ đúng schema AttackPayload đã cung cấp "
        "(method, path, target_parameter, location, vulnerability_type, payload_value, "
        "rationale, expected_indicator)."
    )


def validate_llm_output(raw_text: str, attempt: int = 1) -> ValidationResult:
    """Validate output thô từ LLM, trả về ValidationResult.

    - Nếu hợp lệ: ok=True, payloads chứa list[AttackPayload].
    - Nếu không hợp lệ: ok=False, error_message mô tả lỗi, repair_prompt
      sẵn sàng để gửi ngược lại LLM (nếu attempt < MAX_REPAIR_ATTEMPTS).
    """
    json_text = _extract_json_text(raw_text)

    try:
        data: Any = json.loads(json_text)
    except json.JSONDecodeError as exc:
        error_message = f"JSON không parse được: {exc}"
        return ValidationResult(
            ok=False,
            error_message=error_message,
            repair_prompt=build_repair_prompt(raw_text, error_message, attempt),
            attempt=attempt,
        )

    if isinstance(data, dict) and "payloads" in data:
        data = data["payloads"]  # chấp nhận cả trường hợp LLM bọc trong {"payloads": [...]}

    try:
        payloads = _payload_list_adapter.validate_python(data)
    except ValidationError as exc:
        error_message = _format_pydantic_errors(exc)
        return ValidationResult(
            ok=False,
            error_message=error_message,
            repair_prompt=build_repair_prompt(raw_text, error_message, attempt),
            attempt=attempt,
        )

    return ValidationResult(ok=True, payloads=payloads, attempt=attempt)


def payloads_to_jsonable(payloads: list[AttackPayload]) -> list[dict[str, Any]]:
    """Chuyển list[AttackPayload] thành list[dict] JSON-serializable cho Thành viên C."""
    return [p.model_dump(mode="json") for p in payloads]


__all__ = [
    "AttackPayload",
    "VulnerabilityType",
    "ParamLocation",
    "ValidationResult",
    "MAX_REPAIR_ATTEMPTS",
    "validate_llm_output",
    "build_repair_prompt",
    "payloads_to_jsonable",
]
