"""
core/html_report.py — Module sinh báo cáo HTML tổng kết trực quan (Clean, Modern, Light Theme).

Thiết kế giao diện:
- Tông màu: Trắng - Xanh Indigo - Tím nhạt thanh lịch (Soft Slate / Indigo / Violet), không gây nhức mắt.
- Thống kê trực quan: Thẻ thống kê số lượng lỗ hổng theo từng cấp độ (Critical, High, Medium, Low, Info).
- Bảng chi tiết: Có filter lọc nhanh, badge method, badge severity với icon nhẹ nhàng, chi tiết bằng chứng Oracle.
- Xuất file độc lập (Single-file HTML, không phụ thuộc internet).
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _escape(val: Any) -> str:
    return html.escape(str(val) if val is not None else "")


def generate_html_report(
    findings: list[dict[str, Any]],
    *,
    target_name: str = "API Service",
    target_url: str = "",
    spec_source: str = "",
    provider: str = "",
    model: str = "",
    run_id: str = "",
    gate_status: str = "PASS",
    fail_on: str = "high",
    output_files: dict[str, str] | None = None,
) -> str:
    """Tạo chuỗi HTML hoàn chỉnh chứa báo cáo tổng kết kiểm thử bảo mật."""
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Thống kê
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    confirmed_count = 0
    anomaly_count = 0

    for f in findings:
        sev = str(f.get("severity", "info")).lower()
        if sev in counts:
            counts[sev] += 1
        else:
            counts["info"] += 1
        if f.get("confirmed"):
            confirmed_count += 1
        if "ANOMALY" in str(f.get("evidence", "")).upper():
            anomaly_count += 1

    total_findings = len(findings)
    gate_passed = "PASS" in gate_status.upper()
    gate_color = "#10b981" if gate_passed else "#ef4444"
    gate_bg = "#ecfdf5" if gate_passed else "#fef2f2"

    rows_html = []
    for idx, f in enumerate(findings, start=1):
        sev = str(f.get("severity", "info")).lower()
        method = str(f.get("method", "GET")).upper()
        endpoint = f.get("endpoint", "/")
        vuln_type = f.get("vuln_type", "Other")
        http_status = f.get("http_status")
        status_disp = str(http_status) if http_status is not None else "N/A"
        confirmed = f.get("confirmed", False)
        evidence = f.get("evidence", "")
        repro = f.get("reproduction", {})

        # Màu sắc và icon tinh tế theo mức độ
        if sev == "critical":
            sev_badge_bg = "#fee2e2"
            sev_badge_color = "#b91c1c"
            sev_icon = """<svg class="w-4 h-4 mr-1 text-red-600 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>"""
        elif sev == "high":
            sev_badge_bg = "#ffedd5"
            sev_badge_color = "#c2410c"
            sev_icon = """<svg class="w-4 h-4 mr-1 text-orange-600 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>"""
        elif sev == "medium":
            sev_badge_bg = "#fef3c7"
            sev_badge_color = "#b45309"
            sev_icon = """<svg class="w-4 h-4 mr-1 text-amber-600 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>"""
        elif sev == "low":
            sev_badge_bg = "#e0f2fe"
            sev_badge_color = "#0369a1"
            sev_icon = """<svg class="w-4 h-4 mr-1 text-sky-600 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>"""
        else:
            sev_badge_bg = "#f1f5f9"
            sev_badge_color = "#475569"
            sev_icon = """<svg class="w-4 h-4 mr-1 text-slate-500 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>"""

        # Method badge
        m_colors = {
            "GET": ("#ecfdf5", "#047857"),
            "POST": ("#eff6ff", "#1d4ed8"),
            "PUT": ("#fefce8", "#a16207"),
            "DELETE": ("#fef2f2", "#b91c1c"),
            "PATCH": ("#f5f3ff", "#6d28d9"),
        }
        m_bg, m_fg = m_colors.get(method, ("#f1f5f9", "#475569"))

        # Oracle Confirmation badge
        if confirmed:
            conf_html = '<span class="status-pill conf-yes">Đã xác nhận (Exploited)</span>'
        elif "ANOMALY" in str(evidence).upper():
            conf_html = '<span class="status-pill conf-ano">Bất thường (Anomaly)</span>'
        else:
            conf_html = '<span class="status-pill conf-none">Ứng viên (Unconfirmed)</span>'

        row_id = f"detail_{idx}"
        repro_str = json.dumps(repro, ensure_ascii=False, indent=2) if repro else ""

        rows_html.append(f"""
        <tr class="item-row sev-{sev}" data-sev="{sev}">
            <td class="text-center font-mono text-sm text-slate-400">{idx}</td>
            <td>
                <span class="badge" style="background-color: {sev_badge_bg}; color: {sev_badge_color};">
                    {sev_icon} {sev.upper()}
                </span>
            </td>
            <td>
                <span class="badge" style="background-color: {m_bg}; color: {m_fg}; font-family: monospace;">{method}</span>
            </td>
            <td>
                <span class="font-mono text-slate-800 font-semibold">{_escape(endpoint)}</span>
            </td>
            <td>
                <span class="font-medium text-indigo-700 bg-indigo-50 px-2 py-0.5 rounded text-xs">{_escape(vuln_type)}</span>
            </td>
            <td class="text-center">
                <span class="font-mono text-xs px-2 py-0.5 rounded bg-slate-100 text-slate-700">{status_disp}</span>
            </td>
            <td>{conf_html}</td>
            <td class="text-center">
                <button class="btn-toggle" onclick="toggleDetails('{row_id}')">Chi tiết</button>
            </td>
        </tr>
        <tr id="{row_id}" class="detail-row" style="display: none;">
            <td colspan="8">
                <div class="detail-box">
                    <div class="mb-2">
                        <strong class="text-slate-700 text-xs uppercase tracking-wider">Bằng chứng & Phản hồi Oracle:</strong>
                        <p class="evidence-text font-mono text-xs">{_escape(evidence)}</p>
                    </div>
                    {f'''
                    <div>
                        <strong class="text-slate-700 text-xs uppercase tracking-wider">Thông số Reproduction (Payload):</strong>
                        <pre class="repro-pre font-mono text-xs">{_escape(repro_str)}</pre>
                    </div>
                    ''' if repro_str else ''}
                </div>
            </td>
        </tr>
        """)

    table_body = "\n".join(rows_html) if rows_html else """
        <tr><td colspan="8" class="text-center py-8 text-slate-400">Không có phát hiện nào được ghi nhận.</td></tr>
    """

    # Danh sách artifact files
    files_html = []
    if output_files:
        for fname, fpath in output_files.items():
            files_html.append(f"""
            <div class="file-card">
                <div class="file-name">{_escape(fname)}</div>
                <div class="file-path">{_escape(fpath)}</div>
            </div>
            """)
    files_section = "\n".join(files_html)

    return f"""<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Báo cáo Fuzzing Bảo Mật API — {_escape(target_name)}</title>
    <style>
        :root {{
            --primary: #4f46e5;
            --primary-hover: #4338ca;
            --primary-light: #eef2ff;
            --slate-50: #f8fafc;
            --slate-100: #f1f5f9;
            --slate-200: #e2e8f0;
            --slate-600: #475569;
            --slate-700: #334155;
            --slate-800: #1e293b;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: #f8fafc;
            color: var(--slate-800);
            line-height: 1.5;
            padding: 32px 20px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        
        /* Header */
        .header {{
            background: #ffffff;
            border: 1px solid var(--slate-200);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.04);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 16px;
        }}
        .header-title h1 {{
            font-size: 22px;
            font-weight: 700;
            color: var(--slate-800);
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .header-title p {{
            font-size: 13px;
            color: var(--slate-600);
            margin-top: 4px;
        }}
        .gate-pill {{
            padding: 8px 16px;
            border-radius: 9999px;
            font-weight: 600;
            font-size: 14px;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }}

        /* Summary Cards */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .card {{
            background: #ffffff;
            border: 1px solid var(--slate-200);
            border-radius: 12px;
            padding: 16px 20px;
            box-shadow: 0 1px 2px rgba(0,0,0,0.03);
        }}
        .card-label {{
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--slate-600);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .card-value {{
            font-size: 28px;
            font-weight: 700;
            margin-top: 6px;
        }}
        .card-sub {{
            font-size: 11px;
            color: var(--slate-600);
            margin-top: 2px;
        }}

        /* Target Context Meta */
        .meta-strip {{
            background: #ffffff;
            border: 1px solid var(--slate-200);
            border-radius: 8px;
            padding: 12px 18px;
            margin-bottom: 24px;
            font-size: 13px;
            color: var(--slate-700);
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
        }}
        .meta-item {{ display: flex; align-items: center; gap: 6px; }}
        .meta-label {{ font-weight: 600; color: var(--slate-600); }}

        /* Filter bar */
        .filter-bar {{
            background: #ffffff;
            border: 1px solid var(--slate-200);
            border-radius: 10px;
            padding: 12px 16px;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 12px;
        }}
        .filter-group {{
            display: flex;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
        }}
        .filter-btn {{
            background: var(--slate-100);
            border: 1px solid var(--slate-200);
            padding: 4px 12px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            color: var(--slate-700);
            transition: all 0.15s;
        }}
        .filter-btn.active {{
            background: var(--primary);
            color: #ffffff;
            border-color: var(--primary);
        }}

        /* Table */
        .table-wrap {{
            background: #ffffff;
            border: 1px solid var(--slate-200);
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 1px 3px rgba(0,0,0,0.03);
            margin-bottom: 24px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 13px;
        }}
        th {{
            background: var(--slate-50);
            padding: 12px 16px;
            font-weight: 600;
            color: var(--slate-600);
            border-bottom: 1px solid var(--slate-200);
            text-transform: uppercase;
            font-size: 11px;
            letter-spacing: 0.05em;
        }}
        td {{
            padding: 12px 16px;
            border-bottom: 1px solid var(--slate-200);
            vertical-align: middle;
        }}
        tr:hover td {{ background-color: var(--slate-50); }}

        /* Badges & Pills */
        .badge {{
            display: inline-flex;
            align-items: center;
            padding: 2px 8px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.02em;
        }}
        .status-pill {{
            padding: 2px 8px;
            border-radius: 9999px;
            font-size: 11px;
            font-weight: 600;
        }}
        .conf-yes {{ background: #dcfce7; color: #15803d; }}
        .conf-ano {{ background: #fef3c7; color: #b45309; }}
        .conf-none {{ background: #f1f5f9; color: #64748b; }}

        .btn-toggle {{
            background: #ffffff;
            border: 1px solid var(--slate-200);
            color: var(--primary);
            font-weight: 600;
            font-size: 11px;
            padding: 4px 10px;
            border-radius: 6px;
            cursor: pointer;
        }}
        .btn-toggle:hover {{ background: var(--primary-light); }}

        /* Detail Box */
        .detail-row td {{ background: #fbfcfe; padding: 16px 20px; }}
        .detail-box {{
            background: #ffffff;
            border: 1px solid var(--slate-200);
            border-radius: 8px;
            padding: 14px 16px;
        }}
        .evidence-text {{
            color: #b91c1c;
            background: #fff5f5;
            padding: 8px 12px;
            border-radius: 6px;
            border: 1px solid #fee2e2;
            margin-top: 4px;
            white-space: pre-wrap;
            word-break: break-word;
        }}
        .repro-pre {{
            background: var(--slate-50);
            border: 1px solid var(--slate-200);
            padding: 8px 12px;
            border-radius: 6px;
            margin-top: 4px;
            overflow-x: auto;
            color: var(--slate-800);
        }}

        /* Artifacts section */
        .artifacts-card {{
            background: #ffffff;
            border: 1px solid var(--slate-200);
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 1px 2px rgba(0,0,0,0.03);
        }}
        .artifacts-card h3 {{
            font-size: 15px;
            font-weight: 700;
            color: var(--slate-800);
            margin-bottom: 12px;
        }}
        .artifacts-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 12px;
        }}
        .file-card {{
            background: var(--slate-50);
            border: 1px solid var(--slate-200);
            border-radius: 8px;
            padding: 10px 14px;
        }}
        .file-name {{ font-size: 13px; font-weight: 600; color: var(--primary); }}
        .file-path {{ font-size: 11px; color: var(--slate-600); font-family: monospace; word-break: break-all; margin-top: 2px; }}

        .text-center {{ text-align: center; }}
        .font-mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header class="header">
            <div class="header-title">
                <h1>
                    <svg style="width:26px; height:26px; color:#4f46e5;" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
                    </svg>
                    Báo cáo Tổng kết API Fuzzing — {_escape(target_name)}
                </h1>
                <p>Mục tiêu: <strong>{_escape(target_url or 'N/A')}</strong> &bull; Quét lúc: {now_str} &bull; Run ID: <span class="font-mono">{_escape(run_id)}</span></p>
            </div>
            <div>
                <span class="gate-pill" style="background-color: {gate_bg}; color: {gate_color}; border: 1px solid {gate_color}40;">
                    Security Gate ({fail_on.upper()}): {gate_status}
                </span>
            </div>
        </header>

        <!-- Meta strip -->
        <div class="meta-strip">
            <div class="meta-item"><span class="meta-label">Spec Source:</span> <span>{_escape(spec_source or 'Auto / Local')}</span></div>
            <div class="meta-item"><span class="meta-label">LLM Provider:</span> <span class="font-mono">{_escape(provider)} ({_escape(model or 'default')})</span></div>
            <div class="meta-item"><span class="meta-label">Xác nhận Exploit:</span> <strong style="color: #15803d;">{confirmed_count}</strong></div>
            <div class="meta-item"><span class="meta-label">Dấu hiệu Bất thường:</span> <strong style="color: #b45309;">{anomaly_count}</strong></div>
        </div>

        <!-- Summary Statistics -->
        <div class="stats-grid">
            <div class="card">
                <div class="card-label">Tổng phát hiện</div>
                <div class="card-value" style="color: var(--primary);">{total_findings}</div>
                <div class="card-sub">Test cases sinh bởi LLM</div>
            </div>
            <div class="card">
                <div class="card-label">Critical <span style="color: #b91c1c;">●</span></div>
                <div class="card-value" style="color: #b91c1c;">{counts["critical"]}</div>
                <div class="card-sub">Lỗ hổng nghiêm trọng</div>
            </div>
            <div class="card">
                <div class="card-label">High <span style="color: #c2410c;">●</span></div>
                <div class="card-value" style="color: #c2410c;">{counts["high"]}</div>
                <div class="card-sub">Mức độ cao</div>
            </div>
            <div class="card">
                <div class="card-label">Medium <span style="color: #b45309;">●</span></div>
                <div class="card-value" style="color: #b45309;">{counts["medium"]}</div>
                <div class="card-sub">Mức độ trung bình</div>
            </div>
            <div class="card">
                <div class="card-label">Low & Info <span style="color: #0284c7;">●</span></div>
                <div class="card-value" style="color: #0284c7;">{counts["low"] + counts["info"]}</div>
                <div class="card-sub">Thông tin / Thấp</div>
            </div>
        </div>

        <!-- Findings Table Filter -->
        <div class="filter-bar">
            <div class="filter-group">
                <span class="meta-label">Bộ lọc:</span>
                <button class="filter-btn active" onclick="filterSeverity('all')">Tất cả ({total_findings})</button>
                <button class="filter-btn" onclick="filterSeverity('critical')">Critical ({counts["critical"]})</button>
                <button class="filter-btn" onclick="filterSeverity('high')">High ({counts["high"]})</button>
                <button class="filter-btn" onclick="filterSeverity('medium')">Medium ({counts["medium"]})</button>
                <button class="filter-btn" onclick="filterSeverity('low-info')">Low & Info ({counts["low"] + counts["info"]})</button>
            </div>
            <div>
                <input type="text" id="searchBox" onkeyup="searchTable()" placeholder="Tìm kiếm endpoint, vuln..." style="padding: 6px 12px; border: 1px solid var(--slate-200); border-radius: 6px; font-size: 12px; width: 220px;">
            </div>
        </div>

        <!-- Findings Table -->
        <div class="table-wrap">
            <table id="findingsTable">
                <thead>
                    <tr>
                        <th style="width: 40px;" class="text-center">#</th>
                        <th style="width: 120px;">Mức độ</th>
                        <th style="width: 90px;">Method</th>
                        <th>Endpoint</th>
                        <th>Phân loại Lỗ hổng</th>
                        <th style="width: 80px;" class="text-center">Status</th>
                        <th style="width: 180px;">Trạng thái Oracle</th>
                        <th style="width: 80px;" class="text-center">Chi tiết</th>
                    </tr>
                </thead>
                <tbody>
                    {table_body}
                </tbody>
            </table>
        </div>

        <!-- Artifacts Output Section -->
        <div class="artifacts-card">
            <h3>Tệp Báo cáo & Dữ liệu Sinh ra (Output Artifacts)</h3>
            <div class="artifacts-grid">
                {files_section}
            </div>
        </div>
    </div>

    <script>
        function toggleDetails(rowId) {{
            var el = document.getElementById(rowId);
            if (el) {{
                el.style.display = (el.style.display === 'none' || el.style.display === '') ? 'table-row' : 'none';
            }}
        }}

        function filterSeverity(type) {{
            document.querySelectorAll('.filter-btn').forEach(function(b) {{ b.classList.remove('active'); }});
            event.target.classList.add('active');

            var rows = document.querySelectorAll('.item-row');
            rows.forEach(function(row) {{
                var sev = row.getAttribute('data-sev');
                var detailRow = row.nextElementSibling;
                if (type === 'all') {{
                    row.style.display = '';
                }} else if (type === 'low-info') {{
                    row.style.display = (sev === 'low' || sev === 'info') ? '' : 'none';
                }} else {{
                    row.style.display = (sev === type) ? '' : 'none';
                }}
                if (detailRow && detailRow.classList.contains('detail-row') && row.style.display === 'none') {{
                    detailRow.style.display = 'none';
                }}
            }});
        }}

        function searchTable() {{
            var input = document.getElementById("searchBox").value.toLowerCase();
            var rows = document.querySelectorAll(".item-row");
            rows.forEach(function(row) {{
                var text = row.innerText.toLowerCase();
                var detailRow = row.nextElementSibling;
                if (text.indexOf(input) > -1) {{
                    row.style.display = "";
                }} else {{
                    row.style.display = "none";
                    if (detailRow && detailRow.classList.contains('detail-row')) {{
                        detailRow.style.display = 'none';
                    }}
                }}
            }});
        }}
    </script>
</body>
</html>
"""
