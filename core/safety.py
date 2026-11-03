"""
core/safety.py — Safe Mode & Non-destructive Fuzzing Controls.

Bảo vệ môi trường Staging/UAT của Doanh nghiệp:
- Ngăn chặn các phương thức có tính phá hoại (DELETE, PURGE) trong chế độ an toàn.
- Chặn các endpoint nhạy cảm có nguy cơ xóa dữ liệu hoặc reset hệ thống (ví dụ: /reset, /purge, /drop_db).
"""

from __future__ import annotations

import re
from typing import Any

DESTRUCTIVE_METHODS = {"DELETE", "PURGE"}

DESTRUCTIVE_PATH_PATTERNS = [
    re.compile(r"(?:/|_|-)(?:reset|drop|truncate|purge|nuke|destroy|clear_db|createdb)", re.IGNORECASE),
    re.compile(r"/admin/(?:delete|wipe|shutdown)", re.IGNORECASE),
]


def is_safe_payload(payload: dict[str, Any]) -> tuple[bool, str]:
    """Kiểm tra xem một test case/payload có an toàn cho môi trường Staging hay không."""
    method = str(payload.get("method") or "GET").upper()
    endpoint = str(payload.get("path") or payload.get("endpoint") or "/")

    if method in DESTRUCTIVE_METHODS:
        return False, f"Phương thức '{method}' bị chặn bởi Safe Mode (nguy cơ thay đổi/xoá dữ liệu)."

    for pattern in DESTRUCTIVE_PATH_PATTERNS:
        if pattern.search(endpoint):
            return False, f"Endpoint '{endpoint}' khớp mẫu phá hoại nguy hiểm ({pattern.pattern})."

    return True, "Safe"


def filter_safe_payloads(
    payloads: list[dict[str, Any]],
    *,
    safe_mode: bool = True,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Lọc danh sách payload thành (safe_payloads, blocked_payloads).

    Nếu safe_mode=False, tất cả payload đều được coi là safe.
    """
    if not safe_mode:
        return list(payloads), []

    safe: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []

    for p in payloads:
        ok, reason = is_safe_payload(p)
        if ok:
            safe.append(p)
        else:
            item = dict(p)
            item["_blocked_reason"] = reason
            blocked.append(item)

    return safe, blocked


__all__ = ["DESTRUCTIVE_METHODS", "DESTRUCTIVE_PATH_PATTERNS", "is_safe_payload", "filter_safe_payloads"]
