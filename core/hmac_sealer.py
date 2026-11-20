"""core/hmac_sealer.py — Cryptographic HMAC Sealing & Tamper-Evident Reporting.

Niêm phong chữ ký số chống giả mạo báo cáo bảo mật HTML và SARIF,
đáp ứng tiêu chuẩn kiểm toán doanh nghiệp (Audit Integrity).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from typing import Optional

DEFAULT_AUDIT_SECRET = "LLM-Fuzzer-Audit-Integrity-Key-2026"
SEAL_START_MARKER = "<!-- INTEGRITY_SEAL_START -->"
SEAL_END_MARKER = "<!-- INTEGRITY_SEAL_END -->"
_SIG_EXTRACT_PATTERN = re.compile(r"signature=([a-fA-F0-9]{64})")


def compute_hmac_seal(content: str, secret_key: Optional[str] = None) -> str:
    """Tạo chữ ký HMAC-SHA256 cho nội dung báo cáo."""
    key = (secret_key or os.environ.get("REPORT_SIGNING_KEY", DEFAULT_AUDIT_SECRET)).encode("utf-8")
    return hmac.new(key, content.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_hmac_seal(content: str, expected_signature: str, secret_key: Optional[str] = None) -> bool:
    """Kiểm tra tính toàn vẹn của báo cáo so với chữ ký niêm phong."""
    computed = compute_hmac_seal(content, secret_key)
    return hmac.compare_digest(computed.lower(), expected_signature.strip().lower())


def seal_html_report(html_content: str, secret_key: Optional[str] = None) -> str:
    """Gắn con dấu niêm phong bảo mật vào cuối báo cáo HTML."""
    sig = compute_hmac_seal(html_content, secret_key)
    footer_badge = (
        f"{SEAL_START_MARKER}\n"
        '<footer style="margin-top: 40px; padding: 20px; border-top: 1px solid #cbd5e1; text-align: center; font-size: 13px; color: #64748b; background: #f8fafc;">\n'
        '    <div>🛡️ <strong>Tamper-Evident Security Audit Seal</strong></div>\n'
        '    <div style="font-family: monospace; margin-top: 6px; word-break: break-all; color: #475569;">\n'
        f"        HMAC-SHA256: {sig}\n"
        "    </div>\n"
        "</footer>\n"
        f"<!-- INTEGRITY_SIGNATURE: alg=HMAC-SHA256, signature={sig} -->\n"
        f"{SEAL_END_MARKER}"
    )
    if "</body>" in html_content:
        return html_content.replace("</body>", f"{footer_badge}</body>")
    return f"{html_content}{footer_badge}"


def verify_sealed_html_report(sealed_html: str, secret_key: Optional[str] = None) -> bool:
    """Tự động bóc tách con dấu, trích xuất chữ ký và kiểm tra tính toàn vẹn của báo cáo HTML đã niêm phong."""
    sig_match = _SIG_EXTRACT_PATTERN.search(sealed_html)
    if not sig_match:
        return False
    signature = sig_match.group(1)

    start_idx = sealed_html.find(SEAL_START_MARKER)
    end_idx = sealed_html.find(SEAL_END_MARKER)
    if start_idx == -1 or end_idx == -1 or end_idx < start_idx:
        return False

    # Khôi phục chính xác từng ký tự (bit-for-bit) của nội dung gốc trước khi gắn seal
    original_html = sealed_html[:start_idx] + sealed_html[end_idx + len(SEAL_END_MARKER):]
    return verify_hmac_seal(original_html, signature, secret_key=secret_key)
