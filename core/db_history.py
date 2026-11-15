"""
core/db_history.py — Enterprise Centralized Scan Run & Findings Audit Database.

Lưu trữ lịch sử tất cả các phiên quét vào cơ sở dữ liệu SQLite cục bộ (results/history.db):
- Bảng `scan_runs`: metadata các lần chạy (run_id, target, gate status, owasp score...).
- Bảng `scan_findings`: danh sách các phát hiện bảo mật đã xác thực.
- Cho phép tra cứu lịch sử, theo dõi xu hướng bảo mật qua thời gian.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Any


def init_db(db_path: Path | str = "results/history.db") -> sqlite3.Connection:
    """Khởi tạo cấu trúc bảng SQLite nếu chưa tồn tại."""
    p = Path(db_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p))
    with conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_runs (
                run_id TEXT PRIMARY KEY,
                target_name TEXT,
                target_url TEXT,
                provider TEXT,
                model TEXT,
                gate_status TEXT,
                fail_on TEXT,
                total_findings INTEGER,
                critical_count INTEGER,
                high_count INTEGER,
                medium_count INTEGER,
                low_count INTEGER,
                compliance_score REAL,
                created_at REAL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT,
                rule_id TEXT,
                vuln_type TEXT,
                severity TEXT,
                method TEXT,
                endpoint TEXT,
                parameter TEXT,
                confirmed INTEGER,
                evidence TEXT,
                curl_command TEXT,
                created_at REAL,
                FOREIGN KEY(run_id) REFERENCES scan_runs(run_id)
            )
            """
        )
    return conn


def save_scan_run(
    run_data: dict[str, Any],
    findings: list[dict[str, Any]],
    *,
    db_path: Path | str = "results/history.db",
) -> None:
    """Lưu trữ thông tin một phiên quét và toàn bộ findings vào SQLite."""
    conn = init_db(db_path)
    now = time.time()
    run_id = str(run_data.get("run_id") or f"run_{int(now)}")

    with conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO scan_runs (
                run_id, target_name, target_url, provider, model,
                gate_status, fail_on, total_findings, critical_count,
                high_count, medium_count, low_count, compliance_score, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                str(run_data.get("target_name") or ""),
                str(run_data.get("target_url") or ""),
                str(run_data.get("provider") or ""),
                str(run_data.get("model") or ""),
                str(run_data.get("gate_status") or "PASS"),
                str(run_data.get("fail_on") or "high"),
                int(run_data.get("total_findings", len(findings))),
                int(run_data.get("critical_count", 0)),
                int(run_data.get("high_count", 0)),
                int(run_data.get("medium_count", 0)),
                int(run_data.get("low_count", 0)),
                float(run_data.get("compliance_score", 100.0)),
                now,
            ),
        )

        for f in findings:
            vuln = str(f.get("vuln_type") or f.get("vulnerability") or "")
            curl_cmd = str(f.get("reproduction_curl") or f.get("curl_command") or "")
            conn.execute(
                """
                INSERT INTO scan_findings (
                    run_id, rule_id, vuln_type, severity, method, endpoint,
                    parameter, confirmed, evidence, curl_command, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    f"API-{vuln.upper().replace(' ', '-')}",
                    vuln,
                    str(f.get("severity") or "high").upper(),
                    str(f.get("method") or "GET").upper(),
                    str(f.get("endpoint") or f.get("path") or "/"),
                    str(f.get("target_parameter") or f.get("parameter") or ""),
                    1 if f.get("confirmed") else 0,
                    str(f.get("evidence") or "")[:500],
                    curl_cmd[:1000],
                    now,
                ),
            )
    conn.close()


def get_recent_runs(limit: int = 10, db_path: Path | str = "results/history.db") -> list[dict[str, Any]]:
    """Lấy danh sách các phiên quét gần nhất."""
    p = Path(db_path)
    if not p.is_file():
        return []
    conn = sqlite3.connect(str(p))
    conn.row_factory = sqlite3.Row
    with conn:
        cursor = conn.execute(
            "SELECT * FROM scan_runs ORDER BY created_at DESC LIMIT ?", (limit,)
        )
        rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


__all__ = ["init_db", "save_scan_run", "get_recent_runs"]
