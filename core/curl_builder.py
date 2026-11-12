"""
core/curl_builder.py — Tiện ích tự động tạo lệnh cURL hoàn chỉnh (1-Click Reproduce) cho Lập trình viên.

Chuyển đổi mọi finding kiểm thử bảo mật thành 1 dòng lệnh cURL chuẩn xác,
giúp Developer/QA chỉ cần copy và paste trực tiếp vào Terminal để tái hiện lỗi ngay lập tức mà không cần tự ráp tham số.
"""

from __future__ import annotations

import json
import shlex
import urllib.parse
from typing import Any


def build_curl_command(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    data: Any = None,
    json_data: Any = None,
    cookies: dict[str, str] | None = None,
    insecure: bool = False,
) -> str:
    """Tạo chuỗi lệnh curl chuẩn xác, tương thích cả Bash/Zsh và Windows PowerShell.
    
    Ví dụ:
        curl -i -s -k -X POST "https://api.corp.local/api/v1/profile" \\
          -H "Authorization: Bearer eyJ..." \\
          -H "Content-Type: application/json" \\
          -d '{"role":"admin"}'
    """
    clean_method = method.upper().strip()
    target_url = url.strip()

    # Xử lý query params nếu có
    if params:
        encoded_params = urllib.parse.urlencode(params)
        sep = "&" if "?" in target_url else "?"
        target_url = f"{target_url}{sep}{encoded_params}"

    cmd_parts: list[str] = ["curl", "-i", "-s"]

    if insecure:
        cmd_parts.append("-k")

    cmd_parts.extend(["-X", clean_method])
    cmd_parts.append(f'"{target_url}"')

    # Headers
    req_headers = dict(headers or {})

    # Cookies
    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        req_headers["Cookie"] = cookie_str

    for h_name, h_val in req_headers.items():
        # Tránh các header tự động của curl
        if h_name.lower() in ("content-length", "host"):
            continue
        clean_val = str(h_val).replace('"', '\\"')
        cmd_parts.extend(["-H", f'"{h_name}: {clean_val}"'])

    # Body data
    body_payload = None
    if json_data is not None:
        if isinstance(json_data, (dict, list)):
            body_payload = json.dumps(json_data, ensure_ascii=False)
        else:
            body_payload = str(json_data)
        if "Content-Type" not in req_headers and "content-type" not in req_headers:
            cmd_parts.extend(["-H", '"Content-Type: application/json"'])
    elif data is not None:
        if isinstance(data, dict):
            body_payload = urllib.parse.urlencode(data)
            if "Content-Type" not in req_headers and "content-type" not in req_headers:
                cmd_parts.extend(["-H", '"Content-Type: application/x-www-form-urlencoded"'])
        else:
            body_payload = str(data)

    if body_payload is not None:
        # Chuẩn hóa escaping cho body trong curl
        escaped_body = body_payload.replace("'", "'\\''")
        cmd_parts.extend(["-d", f"'{escaped_body}'"])

    return " ".join(cmd_parts)
