"""
core/safety.py — Safe Mode, Non-destructive Controls & Enterprise Data Audit/Cleanup Tracker.

Bảo vệ môi trường Staging/UAT của Doanh nghiệp:
1. Safe Mode:
   - Ngăn chặn các phương thức có tính phá hoại (DELETE, PURGE) trong chế độ an toàn.
   - Chặn các endpoint nhạy cảm có nguy cơ xóa dữ liệu hoặc reset hệ thống (ví dụ: /reset, /purge, /drop_db).
2. Enterprise Audit & Traceability:
   - Tự động gắn Audit Headers (X-Fuzzer-Audit, X-Fuzzer-Run-Id) trên mọi request để SOC/WAF/Dev dễ lọc log.
3. Cleanup Manifest:
   - Ghi nhận danh sách tất cả các bản ghi/tài nguyên được tạo mới hoặc biến đổi trạng thái thành công trong phiên test,
     xuất file `cleanup_manifest.json` kèm câu lệnh gợi ý dọn dẹp (Rollback suggestions) cho DBA/Dev.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DESTRUCTIVE_METHODS = {"DELETE", "PURGE"}

DESTRUCTIVE_PATH_PATTERNS = [
    re.compile(r"(?:/|_|-)(?:reset|drop|truncate|purge|nuke|destroy|clear_db|createdb)", re.IGNORECASE),
    re.compile(r"/admin/(?:delete|wipe|shutdown)", re.IGNORECASE),
]

FUZZER_AUDIT_HEADER = "X-Fuzzer-Audit"
FUZZER_RUN_ID_HEADER = "X-Fuzzer-Run-Id"


def get_audit_headers(run_id: str) -> dict[str, str]:
    """Tạo header đánh dấu audit cho toàn bộ request của fuzzer."""
    return {
        FUZZER_AUDIT_HEADER: "true",
        FUZZER_RUN_ID_HEADER: run_id,
    }


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


@dataclass
class MutatedResource:
    run_id: str
    method: str
    url: str
    path: str
    status_code: int
    identifier: str | None = None
    payload: Any = None
    suggested_cleanup: str = ""


class CleanupTracker:
    """Theo dõi các tài nguyên/bản ghi đã tạo hoặc biến đổi trong CSDL target phục vụ dọn dẹp/rollback."""

    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        self.mutations: list[MutatedResource] = []

    def record_mutation(
        self,
        method: str,
        url: str,
        path: str,
        status_code: int,
        identifier: str | None = None,
        payload: Any = None,
    ) -> None:
        if status_code < 200 or status_code >= 300:
            return

        method_upper = method.upper()
        if method_upper not in ("POST", "PUT", "PATCH"):
            return

        # Tạo gợi ý dọn dẹp
        suggested = ""
        if method_upper == "POST":
            if identifier:
                suggested = f"DELETE {path.rstrip('/')}/{identifier}"
            else:
                suggested = f"Kiểm tra và xóa bản ghi mới tạo trên {path} với payload: {json.dumps(payload, ensure_ascii=False) if payload else '{}'}"
        elif method_upper in ("PUT", "PATCH"):
            suggested = f"Khôi phục trạng thái ban đầu cho tài nguyên tại {path}"

        item = MutatedResource(
            run_id=self.run_id,
            method=method_upper,
            url=url,
            path=path,
            status_code=status_code,
            identifier=identifier,
            payload=payload,
            suggested_cleanup=suggested,
        )
        self.mutations.append(item)

    def export_cleanup_manifest(self, out_path: Path | str) -> Path:
        """Xuất file JSON cleanup_manifest.json cho DBA / DevOps team."""
        p = Path(out_path)
        data = {
            "run_id": self.run_id,
            "total_mutations_recorded": len(self.mutations),
            "audit_header_used": f"{FUZZER_RUN_ID_HEADER}: {self.run_id}",
            "mutations": [
                {
                    "method": m.method,
                    "url": m.url,
                    "path": m.path,
                    "status_code": m.status_code,
                    "identifier": m.identifier,
                    "payload": m.payload,
                    "suggested_cleanup": m.suggested_cleanup,
                }
                for m in self.mutations
            ],
        }
        p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        return p


__all__ = [
    "DESTRUCTIVE_METHODS",
    "DESTRUCTIVE_PATH_PATTERNS",
    "FUZZER_AUDIT_HEADER",
    "FUZZER_RUN_ID_HEADER",
    "get_audit_headers",
    "is_safe_payload",
    "filter_safe_payloads",
    "CleanupTracker",
    "MutatedResource",
]
