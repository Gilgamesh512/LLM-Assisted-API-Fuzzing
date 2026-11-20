"""
core/pr_commenter.py — CI/CD Pull Request Security Commenter & GitHub Action Formatter.

Tự động định dạng kết quả kiểm thử bảo mật thành bình luận trực quan trên GitHub PR / GitLab MR,
giúp Developer và Security Team nắm bắt rủi ro ngay trên giao diện Code Review trước khi Merge:
- Trạng thái Security Gate (Pass/Fail)
- Bảng tổng hợp CWE & OWASP API Top 10 Compliance
- Danh sách lỗ hổng nghiêm trọng kèm lệnh cURL tái hiện tức thì
- Tùy chọn tự động post bình luận trực tiếp qua GitHub API
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any
import requests
from core.curl_builder import build_curl_command


def format_github_pr_comment(
    run_summary: dict[str, Any],
    findings: list[dict[str, Any]],
    compliance_matrix: dict[str, Any] | None = None,
) -> str:
    """Tạo nội dung bình luận Markdown chuẩn mực cho GitHub Pull Request."""
    gate_status = run_summary.get("gate_status", "PASS")
    target_name = run_summary.get("target_name", "Target API")
    run_id = run_summary.get("run_id", "N/A")
    provider = run_summary.get("provider", "gemini")
    model = run_summary.get("model", "default")
    comp_score = float(run_summary.get("compliance_score", 100.0))

    crit = run_summary.get("critical_count", 0)
    high = run_summary.get("high_count", 0)
    med = run_summary.get("medium_count", 0)
    low = run_summary.get("low_count", 0)
    total = run_summary.get("total_findings", len(findings))

    gate_badge = "🟢 **PASSED**" if gate_status == "PASS" else "🔴 **SECURITY GATE BLOCKED**"

    lines: list[str] = [
        f"## 🛡️ LLM-Assisted API Fuzzing — Báo cáo Kiểm thử Bảo mật PR",
        f"**Trạng thái Security Gate:** {gate_badge} | **Target:** `{target_name}`",
        "",
        f"> **Phiên quét ID:** `{run_id}` | **AI Engine:** `{provider}` (`{model}`)",
        "",
        "### 📊 Tổng quan Kết quả Kiểm thử",
        "",
        "| Chỉ số | Kết quả | Trạng thái |",
        "| :--- | :---: | :--- |",
        f"| **Tổng phát hiện** | **{total}** | {'⚠️ Cần xem xét' if total > 0 else '✅ Không có lỗi'} |",
        f"| 🔴 **Critical** | **{crit}** | {'Chặn Merge ngay lập tức' if crit > 0 else 'Sạch'} |",
        f"| 🟠 **High** | **{high}** | {'Cần vá trước khi release' if high > 0 else 'Sạch'} |",
        f"| 🟡 **Medium** | **{med}** | Khuyến nghị cải thiện |",
        f"| 🔵 **Low / Info** | **{low}** | Ghi nhận |",
        f"| 🏆 **OWASP Compliance** | **{comp_score:.1f}%** | {'Tuân thủ tốt' if comp_score >= 80 else 'Chưa đạt chuẩn'} |",
        "",
    ]

    # Danh sách lỗ hổng Critical & High cần chú ý đặc biệt
    priority_findings = [
        f for f in findings if str(f.get("severity", "")).lower() in ("critical", "high")
    ]

    if priority_findings:
        lines.extend([
            f"### 🚨 Các Lỗ hổng Cần Khắc phục Ngay ({len(priority_findings)} phát hiện)",
            "",
        ])
        for idx, f in enumerate(priority_findings[:10], 1):
            sev_badge = "🔴 CRITICAL" if str(f.get("severity", "")).lower() == "critical" else "🟠 HIGH"
            vuln_type = f.get("vuln_type", "Security Vulnerability")
            method = f.get("method", "GET")
            endpoint = f.get("endpoint", "/")
            param = f.get("target_param") or f.get("param") or "body"

            repro = f.get("reproduction", {})
            target_url = repro.get("url") or (f"{run_summary.get('target_url', 'http://localhost').rstrip('/')}/{endpoint.lstrip('/')}")
            curl_cmd = build_curl_command(
                method=method,
                url=target_url,
                headers=repro.get("headers"),
                params=repro.get("params"),
                json_data=repro.get("body") or repro.get("json"),
            )

            lines.extend([
                f"<details>",
                f"<summary><b>{idx}. [{sev_badge}] {vuln_type}</b> tại <code>{method} {endpoint}</code> (Param: <code>{param}</code>)</summary>",
                "",
                f"- **Bằng chứng (Evidence):**",
                f"  ```text",
                f"  {str(f.get('evidence', 'Phát hiện phản hồi bất thường từ máy chủ'))[:250]}",
                f"  ```",
                f"- **Lệnh cURL Tái hiện (1-Click Reproduce):**",
                f"  ```bash",
                f"  {curl_cmd}",
                f"  ```",
                f"</details>",
                "",
            ])
    else:
        lines.extend([
            "### ✅ Không phát hiện lỗ hổng nghiêm trọng (Critical/High).",
            "Mã nguồn đáp ứng tiêu chuẩn an toàn cho PR này.",
            "",
        ])

    lines.extend([
        "---",
        "💡 *Báo cáo chi tiết dạng HTML (`report.html`), OASIS SARIF v2.1.0 (`findings_summary.sarif`), và mã nguồn vá lỗi (`remediations.md`) đã được lưu trong thư mục Artifacts.*",
    ])

    return "\n".join(lines)


def post_github_pr_comment(
    comment_body: str,
    repo: str,
    pr_number: int,
    github_token: str | None = None,
) -> bool:
    """Gửi trực tiếp nội dung bình luận vào GitHub Pull Request qua GitHub REST API."""
    token = github_token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        print("[!] Không tìm thấy GITHUB_TOKEN để gửi bình luận tự động.")
        return False

    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "LLM-Assisted-API-Fuzzer",
    }

    try:
        resp = requests.post(url, headers=headers, json={"body": comment_body}, timeout=10.0)
        if resp.status_code in (200, 201):
            return True
        else:
            print(f"[-] Gửi comment PR thất bại (Mã {resp.status_code}): {resp.text[:200]}")
            return False
    except Exception as exc:
        print(f"[-] Lỗi kết nối GitHub API: {exc}")
        return False


def export_pr_comment_file(comment_body: str, out_file: Path | str) -> Path:
    """Ghi nội dung bình luận PR ra file Markdown."""
    p = Path(out_file)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(comment_body, encoding="utf-8")
    return p
