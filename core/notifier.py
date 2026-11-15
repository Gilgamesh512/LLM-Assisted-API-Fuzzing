"""
core/notifier.py — Enterprise Webhook Alerting & Notification Dispatcher.

Hỗ trợ gửi thông báo tức thời về phiên quét bảo mật tới:
- Slack Incoming Webhooks (Block Kit)
- Microsoft Teams Connectors
- Discord Webhooks
- Generic JSON Webhook Server
"""

from __future__ import annotations

import json
import urllib.request
from typing import Any


def send_webhook_notification(
    webhook_url: str,
    scan_summary: dict[str, Any],
    *,
    timeout: float = 10.0,
) -> bool:
    """Gửi bản tin tóm tắt kết quả quét tới Webhook URL.
    
    Tự động format phù hợp với Slack, Discord, hoặc payload chuẩn REST.
    """
    if not webhook_url or not webhook_url.startswith("http"):
        return False

    target_app = scan_summary.get("target_app", "API Target")
    target_url = scan_summary.get("target_url", "")
    total = scan_summary.get("total_findings", 0)
    critical = scan_summary.get("critical_count", 0)
    high = scan_summary.get("high_count", 0)
    gate_status = scan_summary.get("gate_status", "PASS")
    compliance_score = scan_summary.get("compliance_score", 100)
    run_id = scan_summary.get("run_id", "N/A")

    status_emoji = "🟢 PASS" if gate_status == "PASS" else "🔴 FAIL"

    # Định dạng Generic / Slack / Discord payload
    payload: dict[str, Any] = {
        "text": f"🛡️ [API Fuzzing] Scan Completed for *{target_app}* | Status: {status_emoji}",
        "run_id": run_id,
        "target_app": target_app,
        "target_url": target_url,
        "gate_status": gate_status,
        "compliance_score": f"{compliance_score}%",
        "summary": {
            "total_findings": total,
            "critical": critical,
            "high": high,
            "medium": scan_summary.get("medium_count", 0),
            "low": scan_summary.get("low_count", 0),
        },
        "details_markdown": (
            f"*Target:* {target_app} ({target_url})\n"
            f"*Security Gate:* {status_emoji}\n"
            f"*OWASP API Compliance:* {compliance_score}%\n"
            f"*Findings:* {total} (Critical: {critical}, High: {high})\n"
            f"*Run ID:* `{run_id}`"
        ),
    }

    # Nếu là Slack URL
    if "slack.com" in webhook_url:
        payload["blocks"] = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"🛡️ *LLM-Assisted API Fuzzing Report: {target_app}*\nStatus: *{status_emoji}* | Compliance: *{compliance_score}%*",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Total Findings:* {total}"},
                    {"type": "mrkdwn", "text": f"*Critical / High:* {critical} / {high}"},
                    {"type": "mrkdwn", "text": f"*Gate Status:* {gate_status}"},
                    {"type": "mrkdwn", "text": f"*Run ID:* `{run_id}`"},
                ],
            },
        ]
    elif "discord.com" in webhook_url:
        payload["content"] = payload["text"]
        payload["embeds"] = [
            {
                "title": f"API Security Report: {target_app}",
                "description": f"Gate Status: **{gate_status}**\nCompliance Score: **{compliance_score}%**",
                "color": 3066993 if gate_status == "PASS" else 15158332,
                "fields": [
                    {"name": "Total Issues", "value": str(total), "inline": True},
                    {"name": "Critical", "value": str(critical), "inline": True},
                    {"name": "High", "value": str(high), "inline": True},
                ],
            }
        ]

    data_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=data_bytes,
        headers={"Content-Type": "application/json", "User-Agent": "LLM-API-Fuzzer-Notifier/1.0"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except Exception:
        return False


__all__ = ["send_webhook_notification"]
