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
        "Bạn là chuyên gia kiểm thử bảo mật API (Enterprise API Penetration Testing & Fuzzing Specialist) "
        "cho các hệ thống ứng dụng và vi dịch vụ (Microservices) thực tế của Doanh nghiệp.\n"
        "Nhiệm vụ: Sinh payload tấn công context-aware, có tính thực chiến cao nhằm phát hiện các lỗ hổng bảo mật nghiêm trọng "
        "(OWASP API Security Top 10) trên các endpoints được cung cấp.\n\n"
        "Cấu trúc input (context endpoints):\n"
        f"{json.dumps(data, ensure_ascii=False, indent=2) if isinstance(data, (dict, list)) else str(data)}\n\n"
        "Hướng dẫn sinh payload thực tế doanh nghiệp:\n"
        "- BOLA/IDOR: Thử nghiệm UUID v4 (00000000-0000-0000-0000-000000000000), sequential ID, hoặc tenant/org identifier khác.\n"
        "- SQLi: Thử nghiệm error-based, boolean-based, union, hoặc time-based delay (pg_sleep, sleep) phù hợp với RDBMS.\n"
        "- SSRF: Thử nghiệm AWS/GCP metadata (http://169.254.169.254/latest/meta-data/), internal private IP (127.0.0.1, 10.0.0.1).\n"
        "- JWT/Auth: Thử nghiệm token giả mạo, algorithm 'none', bearer token rỗng, hoặc role privilege escalation (isAdmin: true).\n"
        "- FileUpload / XSS / Command Injection: Thử nghiệm các ký tự thoát chuỗi, path traversal (../../etc/passwd), hoặc script tag.\n\n"
        "Yêu cầu định dạng output bắt buộc:\n"
        "1. Trả về DUY NHẤT một JSON array hợp lệ (không giải thích, không bọc markdown ```json).\n"
        "2. Mỗi phần tử trong array là một AttackPayload object với đúng 8 trường (không thêm trường thừa):\n"
        "   - \"method\": HTTP method (ví dụ \"GET\", \"POST\", \"PUT\", \"DELETE\")\n"
        "   - \"path\": Endpoint path (ví dụ \"/api/users/{id}\")\n"
        "   - \"target_parameter\": Tên tham số bị nhắm tới (ví dụ \"id\", \"username\")\n"
        "   - \"location\": Vị trí tham số, CHỈ ĐƯỢC CHỌN 1 trong các giá trị sau (chính xác chữ thường):\n"
        "     [\"path\", \"query\", \"header\", \"cookie\", \"body\", \"form-data\"]\n"
        "   - \"vulnerability_type\": Phân loại lỗ hổng, CHỈ ĐƯỢC CHỌN 1 trong các giá trị sau (chính xác từng chữ hoa/thường):\n"
        "     [\"SQLi\", \"BOLA\", \"SSRF\", \"JWT/Auth\", \"FileUpload\", \"XSS\", \"Other\"]\n"
        "   - \"payload_value\": Giá trị chuỗi payload tấn công cụ thể\n"
        "   - \"rationale\": Lý do vì sao payload này phù hợp với ngữ cảnh endpoint\n"
        "   - \"expected_indicator\": Dấu hiệu kỳ vọng (vd: \"HTTP 500\", \"syntax error\", \"response delay > 4s\")\n"
        "3. Ví dụ mẫu:\n"
        "[\n"
        "  {\n"
        "    \"method\": \"GET\",\n"
        "    \"path\": \"/api/v1/accounts/{accountId}\",\n"
        "    \"target_parameter\": \"accountId\",\n"
        "    \"location\": \"path\",\n"
        "    \"vulnerability_type\": \"BOLA\",\n"
        "    \"payload_value\": \"00000000-0000-0000-0000-000000000000\",\n"
        "    \"rationale\": \"Thử truy cập tài khoản định danh UUID của tổ chức khác mà không có quyền\",\n"
        "    \"expected_indicator\": \"HTTP 200\"\n"
        "  }\n"
        "]\n"
    )


def build_repair_prompt(raw_text: str, error_message: str, attempt: int) -> str:
    return _build_repair_prompt(raw_text, error_message, attempt)


__all__ = ["build_payload_generation_prompt", "build_repair_prompt"]
