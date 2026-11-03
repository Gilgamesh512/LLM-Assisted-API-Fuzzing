"""
core/validator.py — Chuẩn hoá & xác thực output của LLM (Pydantic Guardrails & Self-Repair).

1. Trích xuất JSON từ text phản hồi của LLM (loại bỏ markdown fence, text thừa).
2. Xác thực cấu trúc bằng Pydantic v2 (AttackPayload schema, enum, locations).
3. Tự động sinh "repair prompt" khi output sai định dạng để gửi lại cho LLM tự sửa.
4. Cung cấp bridge chuyển đổi tương thích sang các định dạng downstream fuzzer.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, TypeAdapter, ValidationError

MAX_REPAIR_ATTEMPTS = 3


class VulnerabilityType(str, Enum):
    """Các nhóm lỗ hổng mà hệ thống nhắm tới."""

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
        data = data["payloads"]

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
    """Chuyển list[AttackPayload] thành list[dict] JSON-serializable."""
    return [p.model_dump(mode="json") for p in payloads]


def convert_attack_payload_to_fuzz(
    payload: AttackPayload | dict[str, Any],
    target_app: str = "",
) -> dict[str, Any]:
    """Convert AttackPayload sang định dạng Fuzzing tương thích downstream engines."""
    d = payload if isinstance(payload, dict) else payload.model_dump(mode="json")
    raw_vuln = d.get("vulnerability_type", "")
    if hasattr(raw_vuln, "value"):
        raw_vuln = raw_vuln.value
    raw_vuln_str = str(raw_vuln).strip()

    vuln_map = {
        "SQLi": "SQL_INJECTION",
        "BOLA": "BOLA",
        "SSRF": "SSRF",
        "JWT/Auth": "AUTH_BYPASS",
        "FileUpload": "PATH_TRAVERSAL",
        "XSS": "XSS",
        "Other": "OTHER",
    }
    attack_type = vuln_map.get(raw_vuln_str, raw_vuln_str.upper())

    raw_indicator = str(d.get("expected_indicator") or "")
    expected_signal = [
        s.strip()
        for s in re.split(r"[,;|\n]+", raw_indicator)
        if s.strip()
    ] or ([raw_indicator] if raw_indicator else [])

    location_raw = str(d.get("location") or d.get("param_location") or "query")
    if hasattr(location_raw, "value"):
        location_raw = location_raw.value

    return {
        "endpoint": str(d.get("path") or d.get("endpoint") or ""),
        "method": str(d.get("method", "GET")).upper(),
        "target_param": str(d.get("target_parameter") or d.get("target_param") or ""),
        "param_location": str(location_raw),
        "attack_type": attack_type,
        "payload_value": d.get("payload_value"),
        "owasp_category": f"OWASP {raw_vuln_str}",
        "context": str(d.get("rationale") or d.get("context") or ""),
        "expected_signal": expected_signal,
        "target_app": target_app or str(d.get("target_app") or ""),
    }


def convert_fuzz_to_attack_payload(fuzz_data: dict[str, Any]) -> AttackPayload:
    """Convert định dạng Fuzzing ngược lại thành AttackPayload chuẩn."""
    attack_type = str(fuzz_data.get("attack_type", "")).upper()
    reverse_vuln_map = {
        "SQL_INJECTION": VulnerabilityType.SQLI,
        "SQLI": VulnerabilityType.SQLI,
        "BOLA": VulnerabilityType.BOLA,
        "SSRF": VulnerabilityType.SSRF,
        "AUTH_BYPASS": VulnerabilityType.JWT_AUTH,
        "JWT/AUTH": VulnerabilityType.JWT_AUTH,
        "PATH_TRAVERSAL": VulnerabilityType.FILE_UPLOAD,
        "COMMAND_INJECTION": VulnerabilityType.OTHER,
        "MASS_ASSIGNMENT": VulnerabilityType.OTHER,
        "XSS": VulnerabilityType.XSS,
    }
    vuln_type = reverse_vuln_map.get(attack_type, VulnerabilityType.OTHER)

    param_loc_str = str(fuzz_data.get("param_location") or "query").lower()
    valid_locations = {loc.value: loc for loc in ParamLocation}
    location = valid_locations.get(param_loc_str, ParamLocation.QUERY)

    expected_signal = fuzz_data.get("expected_signal")
    if isinstance(expected_signal, list):
        expected_indicator = ", ".join(str(s) for s in expected_signal) or "response anomaly"
    else:
        expected_indicator = str(expected_signal or "response anomaly")

    return AttackPayload(
        method=str(fuzz_data.get("method", "GET")).upper(),
        path=str(fuzz_data.get("endpoint") or fuzz_data.get("path") or "/"),
        target_parameter=str(fuzz_data.get("target_param") or fuzz_data.get("target_parameter") or "param"),
        location=location,
        vulnerability_type=vuln_type,
        payload_value=str(fuzz_data.get("payload_value", "")),
        rationale=str(fuzz_data.get("context") or fuzz_data.get("rationale") or "Contextual test payload"),
        expected_indicator=expected_indicator,
    )


__all__ = [
    "AttackPayload",
    "VulnerabilityType",
    "ParamLocation",
    "ValidationResult",
    "MAX_REPAIR_ATTEMPTS",
    "validate_llm_output",
    "build_repair_prompt",
    "payloads_to_jsonable",
    "convert_attack_payload_to_fuzz",
    "convert_fuzz_to_attack_payload",
]
