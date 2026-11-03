"""
web_ui.py — Web Management Console cho hệ thống LLM-Assisted API Fuzzing.

Giao diện Web điều khiển trực quan, hiện đại, màu sắc thanh lịch (White / Soft Slate / Indigo / Violet),
không dùng phong cách màu đen ma trận SOC/SIEM gây nhức mắt.
Hỗ trợ:
- Lựa chọn linh hoạt mọi loại mục tiêu (IP, URL, Auto-Discovery, Remote Spec, File local, Raw endpoints).
- Lựa chọn quy trình Fuzzing, LLM Provider, Safe Mode, Data Masking, Insecure SSL, Proxy, Rate limiting.
- Theo dõi tiến trình và Live log console thời gian thực.
- Xuất đầy đủ các định dạng chuẩn (OASIS SARIF, CSV, NDJSON, Manifest) kèm Báo cáo HTML tổng kết đẹp mắt.
"""

from __future__ import annotations

import io
import json
import os
import sys
import threading
import time
import urllib.request
import webbrowser
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template_string, request, send_from_directory

REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT))

from fuzzer import run_full_scan  # noqa: E402

app = Flask(__name__)

# State quản lý phiên quét nền
scan_state: dict[str, Any] = {
    "status": "idle",  # "idle" | "running" | "completed" | "error"
    "logs": [],
    "progress": 0,
    "current_step": "Chờ lệnh",
    "findings_count": 0,
    "summary": {},
    "error_message": "",
    "out_dir": "results",
    "report_ready": False,
}
scan_lock = threading.Lock()


class LogCapture(io.StringIO):
    """Bắt stdout và stderr đồng thời lưu vào danh sách log cho Web UI."""

    def __init__(self, original_stream):
        super().__init__()
        self.original_stream = original_stream

    def write(self, s: str) -> int:
        if s:
            self.original_stream.write(s)
            self.original_stream.flush()
            # Làm sạch chuỗi log và lưu vào buffer
            clean_s = s.strip("\r")
            if clean_s:
                lines = clean_s.split("\n")
                for ln in lines:
                    if ln.strip():
                        scan_state["logs"].append(ln)
                        if "[1/6]" in ln:
                            scan_state["progress"] = 15
                            scan_state["current_step"] = "Phân tích đặc tả API"
                        elif "[2/6]" in ln:
                            scan_state["progress"] = 30
                            scan_state["current_step"] = "Data Masking (Bảo vệ PII)"
                        elif "[3/6]" in ln:
                            scan_state["progress"] = 50
                            scan_state["current_step"] = "Gọi LLM sinh Payload"
                        elif "[4/6]" in ln:
                            scan_state["progress"] = 65
                            scan_state["current_step"] = "Xác thực Pydantic Guardrails"
                        elif "[5/6]" in ln:
                            scan_state["progress"] = 80
                            scan_state["current_step"] = "Thực thi Fuzzing Runtime"
                        elif "[6/6]" in ln:
                            scan_state["progress"] = 95
                            scan_state["current_step"] = "Phân tích Enhanced Oracle & Báo cáo"
        return len(s)

    def flush(self) -> None:
        self.original_stream.flush()


def _background_scan_worker(params: dict[str, Any]) -> None:
    """Thread chạy tác vụ Fuzzing nền."""
    global scan_state
    old_stdout = sys.stdout
    old_stderr = sys.stderr
    capture = LogCapture(old_stdout)

    sys.stdout = capture
    sys.stderr = capture

    out_dir = Path(params.get("out_dir", "results"))
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        exit_code = run_full_scan(
            params.get("spec_path"),
            target_url=params.get("target_url"),
            target_name=params.get("target_name"),
            provider=params.get("provider", "gemini"),
            model=params.get("model") or None,
            out_dir=out_dir,
            safe_mode=params.get("safe_mode", True),
            mask_data=params.get("mask_data", True),
            dry_run=params.get("dry_run", False),
            fail_on=params.get("fail_on", "high"),
            auth_token=params.get("auth_token") or None,
            auth_header=params.get("auth_header", "Authorization"),
            auth_prefix=params.get("auth_prefix", "Bearer "),
            headers=params.get("headers"),
            insecure=params.get("insecure", False),
            proxy=params.get("proxy") or None,
            delay_ms=params.get("delay_ms", 0.0),
            max_rps=params.get("max_rps", 0.0),
            allowed_hosts=params.get("allowed_hosts"),
            auto_discover=params.get("auto_discover", False),
            raw_endpoints=params.get("raw_endpoints"),
            concurrency=params.get("concurrency", 5),
            timeout=params.get("timeout", 8.0),
        )

        # Đọc kết quả summary nếu có
        manifest_file = out_dir / "manifest.json"
        sarif_file = out_dir / "findings_summary.sarif"
        html_file = out_dir / "report.html"

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        findings_count = 0

        if sarif_file.is_file():
            try:
                sarif_data = json.loads(sarif_file.read_text(encoding="utf-8"))
                for run in sarif_data.get("runs", []):
                    for res in run.get("results", []):
                        findings_count += 1
                        lvl = str(res.get("level", "note")).lower()
                        if lvl == "error":
                            counts["high"] += 1
                        elif lvl == "warning":
                            counts["medium"] += 1
                        else:
                            counts["low"] += 1
            except Exception:
                pass

        with scan_lock:
            scan_state["status"] = "completed" if exit_code == 0 else "gate_failed"
            scan_state["progress"] = 100
            scan_state["current_step"] = "Hoàn tất kiểm thử"
            scan_state["findings_count"] = findings_count
            scan_state["summary"] = counts
            scan_state["report_ready"] = html_file.is_file()

    except Exception as exc:
        with scan_lock:
            scan_state["status"] = "error"
            scan_state["error_message"] = str(exc)
            scan_state["current_step"] = f"Lỗi: {exc}"
        print(f"[WEB-UI ERROR] Quy trình quét gặp lỗi: {exc}", file=old_stderr)
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr


# Giao diện HTML của Web UI (Light Theme: White / Soft Slate / Indigo)
INDEX_HTML = """<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LLM-Assisted API Fuzzer — Bảng Điều Khiển Quét Doanh Nghiệp</title>
    <style>
        :root {
            --primary: #4f46e5;
            --primary-hover: #4338ca;
            --primary-light: #eef2ff;
            --primary-border: #c7d2fe;
            --bg-page: #f8fafc;
            --bg-card: #ffffff;
            --border: #e2e8f0;
            --text-main: #1e293b;
            --text-muted: #64748b;
            --text-sub: #475569;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-page);
            color: var(--text-main);
            line-height: 1.5;
            padding: 24px;
        }
        .container { max-width: 1400px; margin: 0 auto; }

        /* Top Navbar */
        .navbar {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 16px 24px;
            margin-bottom: 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 1px 2px rgba(0,0,0,0.03);
        }
        .nav-brand {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .nav-brand svg { width: 28px; height: 28px; color: var(--primary); }
        .nav-title { font-size: 18px; font-weight: 700; color: var(--text-main); }
        .nav-badge {
            background: var(--primary-light);
            color: var(--primary);
            border: 1px solid var(--primary-border);
            padding: 2px 8px;
            border-radius: 9999px;
            font-size: 11px;
            font-weight: 600;
        }

        /* 2-Column Layout */
        .main-grid {
            display: grid;
            grid-template-columns: 480px 1fr;
            gap: 24px;
        }
        @media (max-width: 1024px) {
            .main-grid { grid-template-columns: 1fr; }
        }

        /* Card styles */
        .card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px 24px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.02);
            margin-bottom: 20px;
        }
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
            padding-bottom: 12px;
            border-bottom: 1px solid var(--border);
        }
        .card-title {
            font-size: 15px;
            font-weight: 700;
            color: var(--text-main);
            display: flex;
            align-items: center;
            gap: 8px;
        }

        /* Form elements */
        .form-group { margin-bottom: 14px; }
        .form-label {
            display: block;
            font-size: 12px;
            font-weight: 600;
            color: var(--text-sub);
            margin-bottom: 5px;
        }
        .form-input, .form-select, .form-textarea {
            width: 100%;
            padding: 8px 12px;
            border: 1px solid var(--border);
            border-radius: 8px;
            font-size: 13px;
            color: var(--text-main);
            background: #ffffff;
            transition: border-color 0.15s;
        }
        .form-input:focus, .form-select:focus, .form-textarea:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(79, 70, 229, 0.1);
        }
        .form-hint { font-size: 11px; color: var(--text-muted); margin-top: 3px; }
        .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }

        /* Switches / Checkboxes */
        .toggle-group {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #f1f5f9;
        }
        .toggle-label { font-size: 13px; font-weight: 500; color: var(--text-sub); }

        /* Buttons */
        .btn-primary {
            width: 100%;
            background: var(--primary);
            color: #ffffff;
            border: none;
            border-radius: 8px;
            padding: 12px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 8px;
            box-shadow: 0 2px 4px rgba(79, 70, 229, 0.2);
            transition: background 0.15s;
        }
        .btn-primary:hover { background: var(--primary-hover); }
        .btn-primary:disabled { background: #94a3b8; cursor: not-allowed; }

        /* Status & Live Console */
        .status-strip {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 12px 16px;
            background: #f1f5f9;
            border-radius: 8px;
            margin-bottom: 16px;
        }
        .status-pill {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 4px 10px;
            border-radius: 9999px;
            font-size: 12px;
            font-weight: 600;
        }
        .status-idle { background: #e2e8f0; color: #475569; }
        .status-running { background: #dbeafe; color: #1e40af; }
        .status-completed { background: #dcfce7; color: #166534; }
        .status-error { background: #fee2e2; color: #991b1b; }

        /* Progress Bar */
        .progress-bar-wrap {
            height: 6px;
            background: #e2e8f0;
            border-radius: 9999px;
            overflow: hidden;
            margin-bottom: 16px;
        }
        .progress-bar-fill {
            height: 100%;
            background: var(--primary);
            width: 0%;
            transition: width 0.3s ease;
        }

        /* Console Box (Light, Clean) */
        .console-box {
            background: #ffffff;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 14px 16px;
            height: 460px;
            overflow-y: auto;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 12px;
            line-height: 1.6;
            color: #334155;
            box-shadow: inset 0 1px 2px rgba(0,0,0,0.02);
        }
        .console-line { margin-bottom: 2px; }
        .console-line.step { color: var(--primary); font-weight: 600; }
        .console-line.ok { color: #15803d; }
        .console-line.err { color: #b91c1c; font-weight: 600; }

        /* Summary Badges */
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 12px;
            margin-bottom: 16px;
        }
        .summary-card {
            background: #ffffff;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 12px;
            text-align: center;
        }
        .summary-num { font-size: 22px; font-weight: 700; margin-top: 4px; }
        .summary-label { font-size: 11px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; }

        /* Actions bar */
        .report-actions {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            margin-top: 16px;
        }
        .btn-action {
            padding: 8px 14px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            cursor: pointer;
            border: 1px solid var(--border);
            background: #ffffff;
            color: var(--text-sub);
            transition: all 0.15s;
        }
        .btn-action:hover { background: #f8fafc; border-color: #cbd5e1; }
        .btn-action.highlight {
            background: #4f46e5;
            color: #ffffff;
            border-color: #4f46e5;
        }
        .btn-action.highlight:hover { background: #4338ca; }
    </style>
</head>
<body>
    <div class="container">
        <!-- Top Navbar -->
        <header class="navbar">
            <div class="nav-brand">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
                </svg>
                <div class="nav-title">LLM-Assisted API Fuzzing Console</div>
                <span class="nav-badge">Doanh Nghiệp / Enterprise Ready</span>
            </div>
            <div id="envStatusBadge" style="font-size: 12px; color: var(--text-muted);">
                Đang kiểm tra môi trường...
            </div>
        </header>

        <!-- Main Workspace -->
        <div class="main-grid">
            <!-- Left Column: Controls & Configuration -->
            <div>
                <form id="scanForm" onsubmit="startScan(event)">
                    <div class="card">
                        <div class="card-header">
                            <span class="card-title">
                                <svg style="width:18px;height:18px;color:var(--primary);" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
                                1. Cấu hình Mục Tiêu (Target)
                            </span>
                        </div>

                        <div class="form-group">
                            <label class="form-label">Loại Nguồn Đặc Tả (Spec Mode)</label>
                            <select id="specMode" class="form-select" onchange="handleSpecModeChange()">
                                <option value="auto">Tự động Dò tìm (Auto-Discovery từ URL/IP)</option>
                                <option value="remote_url">Remote URL (OpenAPI / Swagger từ xa)</option>
                                <option value="local_file">Tập tin Cục bộ (JSON / YAML có sẵn)</option>
                                <option value="raw_endpoints">Danh sách Endpoints thô (.txt / Postman)</option>
                            </select>
                        </div>

                        <div class="form-group">
                            <label class="form-label">Target URL hoặc IP Mục tiêu</label>
                            <input type="text" id="targetUrl" class="form-input" placeholder="vd: https://api.staging.corp.com hoặc http://192.168.1.100:8000" required>
                            <div class="form-hint">Địa chỉ máy chủ API cần thực thi kiểm thử Fuzzing.</div>
                        </div>

                        <div class="form-group">
                            <label class="form-label">Tên Ứng dụng Mục tiêu (Target App Name)</label>
                            <input type="text" id="targetName" class="form-input" placeholder="vd: CoreBankingService, OrderMicroservice">
                            <div class="form-hint">Dùng để gán nhãn trong báo cáo OASIS SARIF và HTML.</div>
                        </div>

                        <div class="form-group" id="specSourceGroup" style="display: none;">
                            <label class="form-label" id="specSourceLabel">Đường dẫn Spec / Tập tin</label>
                            <input type="text" id="specSource" class="form-input" placeholder="dataset/vampi_openapi.json">
                        </div>

                        <div class="form-group">
                            <label class="form-label">Xác thực Auth Token (Bearer Token / JWT)</label>
                            <input type="text" id="authToken" class="form-input" placeholder="Bearer eyJhbGciOi...">
                        </div>
                    </div>

                    <!-- Scan Settings Card -->
                    <div class="card">
                        <div class="card-header">
                            <span class="card-title">
                                <svg style="width:18px;height:18px;color:var(--primary);" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4"></path></svg>
                                2. Quy Trình & An Toàn Doanh Nghiệp
                            </span>
                        </div>

                        <div class="form-row">
                            <div class="form-group">
                                <label class="form-label">LLM Provider</label>
                                <select id="provider" class="form-select">
                                    <option value="gemini" selected>Google Gemini (Mặc định)</option>
                                    <option value="deepseek">DeepSeek AI</option>
                                    <option value="local">Local LLM / Ollama</option>
                                    <option value="vllm">vLLM Gateway</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label class="form-label">Ngưỡng Chặn (Security Gate)</label>
                                <select id="failOn" class="form-select">
                                    <option value="high" selected>Chặn từ HIGH trở lên</option>
                                    <option value="critical">Chỉ chặn CRITICAL</option>
                                    <option value="medium">Chặn từ MEDIUM</option>
                                    <option value="low">Chặn từ LOW</option>
                                </select>
                            </div>
                        </div>

                        <div class="form-row">
                            <div class="form-group">
                                <label class="form-label">Số luồng (Concurrency)</label>
                                <input type="number" id="concurrency" class="form-input" value="5" min="1" max="20">
                            </div>
                            <div class="form-group">
                                <label class="form-label">Độ trễ Delay (ms)</label>
                                <input type="number" id="delayMs" class="form-input" value="20" min="0" step="10">
                            </div>
                        </div>

                        <div class="form-group">
                            <label class="form-label">Upstream Proxy (Burp Suite / ZAP)</label>
                            <input type="text" id="proxyUrl" class="form-input" placeholder="http://127.0.0.1:8080 (bỏ trống nếu không dùng)">
                        </div>

                        <div class="form-group">
                            <label class="form-label">Custom HTTP Headers (mỗi dòng 1 header Key: Value)</label>
                            <textarea id="customHeaders" class="form-textarea" rows="2" placeholder="X-Tenant-Id: corp_vn&#10;X-Client-Version: 2.4.0"></textarea>
                        </div>

                        <!-- Safety Toggles -->
                        <div class="toggle-group">
                            <span class="toggle-label">Safe Mode (Chặn DELETE & Phá hoại)</span>
                            <input type="checkbox" id="safeMode" checked>
                        </div>
                        <div class="toggle-group">
                            <span class="toggle-label">Data Masking (Ẩn danh IP/PII gửi LLM)</span>
                            <input type="checkbox" id="maskData" checked>
                        </div>
                        <div class="toggle-group">
                            <span class="toggle-label">Insecure SSL (Cho phép SSL tự ký)</span>
                            <input type="checkbox" id="insecureSsl" checked>
                        </div>
                        <div class="toggle-group">
                            <span class="toggle-label">Chế độ Dry-Run (Không bắn mạng thật)</span>
                            <input type="checkbox" id="dryRun">
                        </div>

                        <div style="margin-top: 20px;">
                            <button type="submit" id="btnStart" class="btn-primary">
                                <svg style="width:18px;height:18px;" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                                Bắt Đầu Quét Fuzzing
                            </button>
                        </div>
                    </div>
                </form>
            </div>

            <!-- Right Column: Realtime Console & Results -->
            <div>
                <div class="card">
                    <div class="card-header">
                        <span class="card-title">
                            <svg style="width:18px;height:18px;color:var(--primary);" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
                            Tiến Trình Thực Thi & Kết Quả
                        </span>
                        <span id="scanStatusBadge" class="status-pill status-idle">Sẵn sàng</span>
                    </div>

                    <!-- Progress Bar -->
                    <div class="progress-bar-wrap">
                        <div id="progressBar" class="progress-bar-fill"></div>
                    </div>
                    <div id="currentStepText" style="font-size: 12px; color: var(--text-muted); margin-bottom: 12px;">Chờ khởi chạy...</div>

                    <!-- Summary Cards (Show after completed) -->
                    <div id="resultsSummarySection" style="display: none;">
                        <div class="summary-grid">
                            <div class="summary-card">
                                <div class="summary-label">Tổng phát hiện</div>
                                <div id="sumTotal" class="summary-num" style="color: var(--primary);">0</div>
                            </div>
                            <div class="summary-card">
                                <div class="summary-label">Critical</div>
                                <div id="sumCritical" class="summary-num" style="color: #b91c1c;">0</div>
                            </div>
                            <div class="summary-card">
                                <div class="summary-label">High</div>
                                <div id="sumHigh" class="summary-num" style="color: #c2410c;">0</div>
                            </div>
                            <div class="summary-card">
                                <div class="summary-label">Gate</div>
                                <div id="sumGate" class="summary-num" style="font-size: 16px; margin-top: 8px;">PASS</div>
                            </div>
                        </div>

                        <!-- Action buttons for downloading / viewing reports -->
                        <div class="report-actions">
                            <a href="/report" target="_blank" class="btn-action highlight">
                                <svg style="width:15px;height:15px;" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path></svg>
                                Mở Báo Cáo HTML Đầy Đủ
                            </a>
                            <a href="/artifacts/findings_summary.sarif" download class="btn-action">
                                Tải OASIS SARIF (.sarif)
                            </a>
                            <a href="/artifacts/findings_summary.csv" download class="btn-action">
                                Tải CSV Summary
                            </a>
                            <a href="/artifacts/payloads_validated.json" download class="btn-action">
                                Payloads JSON
                            </a>
                        </div>
                        <div style="margin-top: 16px; border-bottom: 1px solid var(--border);"></div>
                    </div>

                    <!-- Console Box -->
                    <div style="margin-top: 16px;">
                        <div class="form-label">Live Execution Terminal Log</div>
                        <div id="consoleBox" class="console-box">
                            <div class="console-line text-muted">[+] Sẵn sàng. Nhập thông tin mục tiêu và bấm "Bắt Đầu Quét Fuzzing".</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        var pollTimer = null;

        function handleSpecModeChange() {
            var mode = document.getElementById("specMode").value;
            var group = document.getElementById("specSourceGroup");
            var label = document.getElementById("specSourceLabel");
            var input = document.getElementById("specSource");

            if (mode === "auto") {
                group.style.display = "none";
            } else if (mode === "remote_url") {
                group.style.display = "block";
                label.innerText = "Remote OpenAPI Spec URL";
                input.placeholder = "https://staging-api.corp.com/v3/api-docs";
            } else if (mode === "local_file") {
                group.style.display = "block";
                label.innerText = "Đường dẫn file OpenAPI cục bộ";
                input.placeholder = "dataset/vampi_openapi.json";
            } else if (mode === "raw_endpoints") {
                group.style.display = "block";
                label.innerText = "Đường dẫn file danh sách Endpoints thô";
                input.placeholder = "endpoints.txt hoặc postman.json";
            }
        }

        function checkEnvStatus() {
            fetch('/api/env-status')
                .then(r => r.json())
                .then(data => {
                    var el = document.getElementById("envStatusBadge");
                    var items = [];
                    if (data.gemini_ready) items.push("Gemini: Sẵn sàng");
                    if (data.deepseek_ready) items.push("DeepSeek: Sẵn sàng");
                    if (data.local_ready) items.push("Local LLM: Kết nối OK");
                    el.innerText = items.length ? items.join(" • ") : "Chưa cấu hình API Key (dùng local hoặc dry-run)";
                });
        }

        function startScan(e) {
            e.preventDefault();
            var mode = document.getElementById("specMode").value;
            var targetUrl = document.getElementById("targetUrl").value.trim();
            var targetName = document.getElementById("targetName").value.trim();
            var specSource = document.getElementById("specSource").value.trim();

            var specPath = null;
            var rawEndpoints = null;
            var autoDiscover = false;

            if (mode === "auto") {
                autoDiscover = true;
                specPath = "auto";
            } else if (mode === "remote_url" || mode === "local_file") {
                specPath = specSource || null;
            } else if (mode === "raw_endpoints") {
                rawEndpoints = specSource || null;
            }

            var headersRaw = document.getElementById("customHeaders").value.split("\\n").map(s => s.trim()).filter(Boolean);

            var payload = {
                spec_path: specPath,
                target_url: targetUrl || null,
                target_name: targetName || null,
                provider: document.getElementById("provider").value,
                fail_on: document.getElementById("failOn").value,
                auth_token: document.getElementById("authToken").value.trim() || null,
                concurrency: parseInt(document.getElementById("concurrency").value) || 5,
                delay_ms: parseFloat(document.getElementById("delayMs").value) || 0.0,
                proxy: document.getElementById("proxyUrl").value.trim() || null,
                headers: headersRaw.length ? headersRaw : null,
                safe_mode: document.getElementById("safeMode").checked,
                mask_data: document.getElementById("maskData").checked,
                insecure: document.getElementById("insecureSsl").checked,
                dry_run: document.getElementById("dryRun").checked,
                auto_discover: autoDiscover,
                raw_endpoints: rawEndpoints,
            };

            document.getElementById("btnStart").disabled = true;
            document.getElementById("resultsSummarySection").style.display = "none";
            document.getElementById("consoleBox").innerHTML = '<div class="console-line text-muted">[*] Bắt đầu khởi động phiên quét...</div>';

            fetch('/api/scan/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            }).then(r => r.json()).then(res => {
                if (res.ok) {
                    if (pollTimer) clearInterval(pollTimer);
                    pollTimer = setInterval(pollStatus, 1000);
                } else {
                    alert("Lỗi: " + res.error);
                    document.getElementById("btnStart").disabled = false;
                }
            });
        }

        function pollStatus() {
            fetch('/api/scan/status')
                .then(r => r.json())
                .then(st => {
                    var badge = document.getElementById("scanStatusBadge");
                    var pBar = document.getElementById("progressBar");
                    var stepText = document.getElementById("currentStepText");

                    badge.className = "status-pill status-" + (st.status === "gate_failed" ? "error" : st.status);
                    badge.innerText = st.status.toUpperCase();
                    pBar.style.width = st.progress + "%";
                    stepText.innerText = st.current_step;

                    // Cập nhật Console Logs
                    var box = document.getElementById("consoleBox");
                    box.innerHTML = st.logs.map(l => {
                        var cls = "console-line";
                        if (l.indexOf("[OK]") > -1 || l.indexOf("THÀNH CÔNG") > -1) cls += " ok";
                        else if (l.indexOf("[ERROR]") > -1 || l.indexOf("[!]") > -1) cls += " err";
                        else if (l.indexOf("[*]") > -1 || l.indexOf("1/6") > -1 || l.indexOf("2/6") > -1 || l.indexOf("3/6") > -1 || l.indexOf("4/6") > -1 || l.indexOf("5/6") > -1 || l.indexOf("6/6") > -1) cls += " step";
                        return '<div class="' + cls + '">' + escapeHtml(l) + '</div>';
                    }).join("");
                    box.scrollTop = box.scrollHeight;

                    // Nếu hoàn tất
                    if (st.status === "completed" || st.status === "gate_failed" || st.status === "error") {
                        clearInterval(pollTimer);
                        document.getElementById("btnStart").disabled = false;
                        if (st.report_ready || st.status === "completed" || st.status === "gate_failed") {
                            document.getElementById("resultsSummarySection").style.display = "block";
                            document.getElementById("sumTotal").innerText = st.findings_count || 0;
                            document.getElementById("sumCritical").innerText = (st.summary && st.summary.critical) || 0;
                            document.getElementById("sumHigh").innerText = (st.summary && st.summary.high) || 0;
                            document.getElementById("sumGate").innerText = st.status === "completed" ? "PASS" : "FAIL";
                            document.getElementById("sumGate").style.color = st.status === "completed" ? "#166534" : "#b91c1c";
                        }
                    }
                });
        }

        function escapeHtml(text) {
            return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
        }

        checkEnvStatus();
    </script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(INDEX_HTML)


@app.route("/report")
def view_html_report():
    out_dir = Path(scan_state.get("out_dir", "results"))
    report_file = out_dir / "report.html"
    if not report_file.is_file():
        summary_html = out_dir / "findings_summary.html"
        if summary_html.is_file():
            return send_from_directory(out_dir, summary_html.name)
        return "<h3>Chưa có báo cáo HTML nào được sinh ra. Vui lòng thực hiện một lượt quét trước.</h3>", 404
    return send_from_directory(out_dir, report_file.name)


@app.route("/artifacts/<path:filename>")
def download_artifact(filename: str):
    out_dir = Path(scan_state.get("out_dir", "results"))
    file_path = out_dir / filename
    if not file_path.is_file():
        return jsonify({"error": f"Không tìm thấy tệp: {filename}"}), 404
    return send_from_directory(out_dir, filename, as_attachment=True)


@app.route("/api/env-status")
def get_env_status():
    gemini_key = bool(os.environ.get("GEMINI_API_KEY"))
    deepseek_key = bool(os.environ.get("DEEPSEEK_API_KEY"))
    local_url = os.environ.get("LOCAL_LLM_URL", "http://localhost:11434")

    local_ready = False
    try:
        req = urllib.request.Request(f"{local_url.rstrip('/')}/api/version", method="GET")
        with urllib.request.urlopen(req, timeout=1.0) as resp:
            local_ready = resp.status == 200
    except Exception:
        local_ready = False

    return jsonify({
        "gemini_ready": gemini_key,
        "deepseek_ready": deepseek_key,
        "local_ready": local_ready,
    })


@app.route("/api/scan/start", methods=["POST"])
def start_scan_endpoint():
    global scan_state
    if scan_state["status"] == "running":
        return jsonify({"ok": False, "error": "Một phiên quét khác đang chạy."}), 400

    data = request.json or {}
    out_dir = data.get("out_dir", "results")

    with scan_lock:
        scan_state["status"] = "running"
        scan_state["logs"] = ["[+] Đã tiếp nhận yêu cầu từ Web UI. Đang chuẩn bị môi trường..."]
        scan_state["progress"] = 5
        scan_state["current_step"] = "Khởi tạo tác vụ"
        scan_state["findings_count"] = 0
        scan_state["summary"] = {}
        scan_state["error_message"] = ""
        scan_state["out_dir"] = out_dir
        scan_state["report_ready"] = False

    worker_thread = threading.Thread(target=_background_scan_worker, args=(data,), daemon=True)
    worker_thread.start()

    return jsonify({"ok": True})


@app.route("/api/scan/status")
def get_scan_status():
    with scan_lock:
        return jsonify(dict(scan_state))


def start_web_ui(host: str = "127.0.0.1", port: int = 5000, open_browser: bool = False) -> int:
    """Khởi động Web UI điều khiển."""
    url = f"http://{host}:{port}"
    print("=" * 65)
    print(" LLM-ASSISTED API FUZZING — WEB MANAGEMENT CONSOLE")
    print(f" [*] Đang chạy tại địa chỉ: {url}")
    print(" [*] Nhấn Ctrl+C để dừng máy chủ.")
    print("=" * 65)

    if open_browser:
        def _open():
            time.sleep(1.0)
            webbrowser.open(url)
        threading.Thread(target=_open, daemon=True).start()

    try:
        app.run(host=host, port=port, debug=False)
        return 0
    except KeyboardInterrupt:
        print("\n[+] Đã dừng máy chủ Web UI.")
        return 0
    except Exception as exc:
        print(f"[ERROR] Không thể khởi động Web UI: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(start_web_ui(open_browser=True))
