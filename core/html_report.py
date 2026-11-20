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

from core.compliance import build_owasp_compliance_matrix, map_vulnerability_to_compliance
from core.curl_builder import build_curl_command
from core.remediation import generate_remediation


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
    baseline_diff: Any = None,
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

    baseline_html = ""
    if baseline_diff is not None:
        new_cnt = len(getattr(baseline_diff, "new", []))
        res_cnt = len(getattr(baseline_diff, "resolved", []))
        unchanged_cnt = len(getattr(baseline_diff, "unchanged", []))
        baseline_html = (
            f'<div class="meta-item"><span class="meta-label">Baseline Drift:</span> '
            f'<strong style="color: #b91c1c;">+{new_cnt} mới</strong> &bull; '
            f'<strong style="color: #15803d;">-{res_cnt} đã sửa</strong> &bull; '
            f'<span>{unchanged_cnt} không đổi</span></div>'
        )

    # Compliance Matrix (OWASP API Top 10 & CWE)
    compliance_data = build_owasp_compliance_matrix(findings)
    comp_score = compliance_data["compliance_score"]
    passed_cats = compliance_data["passed_categories"]
    violated_cats = compliance_data["violated_categories"]
    warning_cats = compliance_data["warning_categories"]
    total_cats = compliance_data["total_categories"]

    if comp_score >= 80:
        score_bg = "#dcfce7"
        score_color = "#15803d"
    elif comp_score >= 50:
        score_bg = "#fef3c7"
        score_color = "#b45309"
    else:
        score_bg = "#fee2e2"
        score_color = "#b91c1c"

    comp_rows_html = []
    for item in compliance_data["matrix"]:
        c_status = item["status"]
        if c_status == "PASSED":
            st_class = "status-passed"
            st_text = "PASS"
        elif c_status == "WARNING":
            st_class = "status-warning"
            st_text = f"CẢNH BÁO ({item['findings_count']})"
        else:
            st_class = "status-violated"
            st_text = f"VI PHẠM ({item['findings_count']})"

        cwes_str = ", ".join(item["cwe"])
        comp_rows_html.append(f"""
        <tr>
            <td class="font-mono font-semibold text-indigo-700" style="white-space:nowrap;">{_escape(item["id"])}</td>
            <td><strong>{_escape(item["title"])}</strong><br><span class="text-xs text-slate-500">{_escape(item["remediation"])}</span></td>
            <td class="font-mono text-xs text-slate-600" style="white-space:nowrap;">{_escape(cwes_str)}</td>
            <td class="text-center font-mono font-semibold">{item["findings_count"]}</td>
            <td class="text-center"><span class="status-tag {st_class}">{st_text}</span></td>
        </tr>
        """)
    comp_table_body = "\n".join(comp_rows_html)

    rows_html = []
    for idx, f in enumerate(findings, start=1):
        sev = str(f.get("severity", "info")).lower()
        method = str(f.get("method", "GET")).upper()
        endpoint = f.get("endpoint", "/")
        vuln_type = f.get("vuln_type") or f.get("vulnerability") or "Other"
        http_status = f.get("http_status")
        status_disp = str(http_status) if http_status is not None else "N/A"
        confirmed = f.get("confirmed", False)
        evidence = f.get("evidence", "")
        repro = f.get("reproduction", {})

        mapping = map_vulnerability_to_compliance(vuln_type)
        owasp_id = mapping["owasp_id"]
        primary_cwe = mapping["primary_cwe"]
        rem_info = generate_remediation(f)

        curl_cmd = f.get("curl_command")
        if not curl_cmd:
            target_endpoint = endpoint
            full_url = target_url.rstrip("/") + "/" + target_endpoint.lstrip("/") if target_url else target_endpoint
            curl_cmd = build_curl_command(
                method=method,
                url=full_url,
                headers=repro.get("headers"),
                params=repro.get("params"),
                json_data=repro.get("body") or repro.get("json"),
            )

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
        if "DEEP STATE LOOPBACK VERIFIED" in str(evidence).upper():
            conf_html = '<span class="status-pill" style="background:#dcfce7; color:#15803d; border:1px solid #86efac; font-weight:600;">Deep State Verified</span>'
        elif "ECHO ONLY" in str(evidence).upper():
            conf_html = '<span class="status-pill" style="background:#f1f5f9; color:#475569; border:1px solid #cbd5e1;">Echo Only (Safe)</span>'
        elif confirmed:
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
                <div style="margin-top: 4px; display: flex; gap: 4px; flex-wrap: wrap;">
                    <span class="badge" style="background-color: #ede9fe; color: #5b21b6; font-size: 10px; padding: 1px 6px;">{owasp_id}</span>
                    <span class="badge" style="background-color: #f1f5f9; color: #475569; font-size: 10px; padding: 1px 6px;">{primary_cwe}</span>
                </div>
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
                    <div style="margin-bottom: 12px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                            <strong class="text-slate-700 text-xs uppercase tracking-wider">Lệnh cURL Tái hiện (1-Click Reproduce):</strong>
                            <button class="btn-copy-curl" onclick="copyCurl(this, 'curl_{idx}')" title="Sao chép cURL để dán vào Terminal tái hiện ngay">
                                📋 Sao chép cURL
                            </button>
                        </div>
                        <pre id="curl_{idx}" class="curl-pre font-mono text-xs">{_escape(curl_cmd)}</pre>
                    </div>
                    <div class="mb-2">
                        <strong class="text-slate-700 text-xs uppercase tracking-wider">Bằng chứng & Phản hồi Oracle:</strong>
                        <p class="evidence-text font-mono text-xs">{_escape(evidence)}</p>
                    </div>
                    <div class="mb-2">
                        <strong class="text-slate-700 text-xs uppercase tracking-wider">Chuẩn An ninh & Khuyến nghị Khắc phục:</strong>
                        <div style="background: #f8fafc; border: 1px solid var(--slate-200); border-radius: 6px; padding: 8px 12px; margin-top: 4px; font-size: 12px;">
                            <span class="font-semibold text-indigo-700">{_escape(mapping['owasp_id'])} - {_escape(mapping['owasp_title'])}</span>
                            <span class="text-slate-500 font-mono text-xs ml-2">({_escape(', '.join(mapping['cwe_ids']))})</span>
                            <p class="text-slate-600 mt-1">{_escape(mapping['remediation'])}</p>
                        </div>
                    </div>
                    <div class="mb-2">
                        <strong class="text-slate-700 text-xs uppercase tracking-wider">💡 Mã nguồn vá lỗi đề xuất (AI Code Patch):</strong>
                        <div style="background: #f8fafc; border: 1px solid var(--slate-200); border-radius: 6px; padding: 8px 12px; margin-top: 4px; font-size: 12px;">
                            <span class="font-semibold text-emerald-700">{_escape(rem_info['title'])} ({_escape(rem_info['framework'].upper())})</span>
                            <pre class="font-mono text-xs mt-2" style="background: #0f172a; color: #38bdf8; padding: 10px; border-radius: 4px; overflow-x: auto; white-space: pre-wrap;">{_escape(rem_info['remediation_code_patch'])}</pre>
                        </div>
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

        /* Compliance Section */
        .compliance-card {{
            background: #ffffff;
            border: 1px solid var(--slate-200);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 24px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.03);
        }}
        .compliance-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 12px;
            margin-bottom: 16px;
        }}
        .compliance-header h2 {{
            font-size: 16px;
            font-weight: 700;
            color: var(--slate-800);
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .compliance-pill {{
            padding: 6px 14px;
            border-radius: 9999px;
            font-size: 13px;
            font-weight: 700;
        }}
        .comp-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 12px;
        }}
        .comp-table th {{
            background: var(--slate-50);
            padding: 10px 12px;
            font-size: 11px;
            text-transform: uppercase;
            color: var(--slate-600);
            border-bottom: 1px solid var(--slate-200);
        }}
        .comp-table td {{
            padding: 10px 12px;
            border-bottom: 1px solid var(--slate-100);
            vertical-align: middle;
        }}
        .status-tag {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 9999px;
            font-weight: 700;
            font-size: 10px;
            letter-spacing: 0.03em;
        }}
        .status-passed {{ background: #dcfce7; color: #15803d; border: 1px solid #86efac; }}
        .status-warning {{ background: #fef3c7; color: #b45309; border: 1px solid #fde68a; }}
        .status-violated {{ background: #fee2e2; color: #b91c1c; border: 1px solid #fca5a5; }}

        /* Copy cURL button & pre */
        .btn-copy-curl {{
            background: var(--primary);
            color: #ffffff;
            border: 1px solid var(--primary-hover);
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            display: inline-flex;
            align-items: center;
            gap: 4px;
        }}
        .btn-copy-curl:hover {{
            background: var(--primary-hover);
        }}
        .curl-pre {{
            background: #0f172a;
            color: #f8fafc;
            border: 1px solid #334155;
            padding: 10px 14px;
            border-radius: 6px;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
            line-height: 1.4;
            user-select: all;
        }}
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
            {baseline_html}
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

        <!-- OWASP API Security Top 10 (2023) Compliance Dashboard -->
        <div class="compliance-card">
            <div class="compliance-header">
                <h2>
                    <svg style="width:20px; height:20px; color:#4f46e5;" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
                    </svg>
                    Ma trận Tuân thủ OWASP API Security Top 10 (2023)
                </h2>
                <div>
                    <span class="compliance-pill" style="background-color: {score_bg}; color: {score_color}; border: 1px solid {score_color}40;">
                        Chỉ số Tuân thủ: {comp_score}% ({passed_cats}/{total_cats} Danh mục An toàn)
                    </span>
                </div>
            </div>
            <div style="overflow-x: auto;">
                <table class="comp-table">
                    <thead>
                        <tr>
                            <th style="width: 100px;">Mã chuẩn</th>
                            <th>Mô tả Danh mục & Khuyến nghị Khắc phục</th>
                            <th style="width: 140px;">Mã CWE</th>
                            <th style="width: 90px;" class="text-center">Số lỗi</th>
                            <th style="width: 130px;" class="text-center">Trạng thái</th>
                        </tr>
                    </thead>
                    <tbody>
                        {comp_table_body}
                    </tbody>
                </table>
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

        function copyCurl(btn, elementId) {{
            var pre = document.getElementById(elementId);
            if (!pre) return;
            var text = pre.innerText || pre.textContent;
            if (navigator.clipboard && navigator.clipboard.writeText) {{
                navigator.clipboard.writeText(text).then(function() {{
                    showCopiedFeedback(btn);
                }}).catch(function() {{
                    fallbackCopy(text, btn);
                }});
            }} else {{
                fallbackCopy(text, btn);
            }}
        }}

        function fallbackCopy(text, btn) {{
            var textArea = document.createElement("textarea");
            textArea.value = text;
            textArea.style.position = "fixed";
            textArea.style.opacity = "0";
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();
            try {{
                document.execCommand('copy');
                showCopiedFeedback(btn);
            }} catch(e) {{
                alert("Vui lòng sao chép thủ công từ khung cURL: " + e);
            }}
            document.body.removeChild(textArea);
        }}

        function showCopiedFeedback(btn) {{
            var oldText = btn.innerText;
            btn.innerText = "✓ Đã sao chép!";
            btn.style.backgroundColor = "#16a34a";
            btn.style.borderColor = "#15803d";
            setTimeout(function() {{
                btn.innerText = oldText;
                btn.style.backgroundColor = "";
                btn.style.borderColor = "";
            }}, 2000);
        }}
    </script>
</body>
</html>
"""
