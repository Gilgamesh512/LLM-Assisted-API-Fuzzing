"""
core/websocket_fuzzer.py — Kiểm thử bảo mật Real-time API: WebSocket & Server-Sent Events (SSE).

Kiểm tra các rủi ro bảo mật đặc thù của giao tiếp thời gian thực:
1. CSWSH (Cross-Site WebSocket Hijacking): Thiếu kiểm tra Header Origin khi Handshake.
2. Broken WebSocket Authentication: Cho phép Handshake và trao đổi dữ liệu khi không có Auth token.
3. Malformed Frame / Message Flooding DoS: Gửi bản tin JSON dị dạng hoặc quá kích thước gây sập socket worker.
4. Server-Sent Events (SSE) Unprotected Stream: Endpoint text/event-stream rò rỉ dữ liệu nhạy cảm mà không xác thực.
"""

from __future__ import annotations

import base64
import os
import socket
import ssl
import time
import urllib.parse
from typing import Any
import requests


def _generate_sec_websocket_key() -> str:
    """Tạo Sec-WebSocket-Key ngẫu nhiên chuẩn RFC 6455 (16 bytes base64)."""
    return base64.b64encode(os.urandom(16)).decode("ascii")


def audit_websocket_handshake(
    ws_url: str,
    headers: dict[str, str] | None = None,
    timeout: float = 5.0,
    check_cswsh: bool = True,
) -> list[dict[str, Any]]:
    """Kiểm tra lỗ hổng bảo mật trong quá trình bắt tay WebSocket Handshake (RFC 6455)."""
    findings: list[dict[str, Any]] = []
    parsed = urllib.parse.urlparse(ws_url)
    scheme = parsed.scheme.lower()

    if scheme not in ("ws", "wss", "http", "https"):
        return findings

    is_ssl = scheme in ("wss", "https")
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if is_ssl else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    custom_hdrs = headers.copy() if headers else {}

    # 1. Kiểm tra Broken Authentication (Bỏ auth token khi handshake)
    unauth_hdrs = {k: v for k, v in custom_hdrs.items() if k.lower() not in ("authorization", "cookie", "x-api-key")}
    key = _generate_sec_websocket_key()

    req_lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}:{port}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
    ]
    for k, v in unauth_hdrs.items():
        req_lines.append(f"{k}: {v}")
    req_lines.extend(["", ""])
    raw_req = "\r\n".join(req_lines).encode("utf-8")

    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if is_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)

        sock.sendall(raw_req)
        resp_data = sock.recv(4096).decode("utf-8", errors="replace")
        sock.close()

        if "101 Switching Protocols" in resp_data:
            findings.append({
                "tool": "websocket_fuzzer",
                "endpoint": path,
                "method": "WS_HANDSHAKE",
                "target_param": "Authorization",
                "vuln_type": "Broken WebSocket Authentication",
                "severity": "high",
                "http_status": 101,
                "confirmed": True,
                "evidence": f"WebSocket server chấp nhận kết nối Handshake (101 Switching Protocols) mà không cần header xác thực.\nPhản hồi:\n{resp_data[:300]}",
                "reproduction": {"method": "GET", "url": ws_url, "headers": {"Upgrade": "websocket"}},
            })
    except Exception:
        pass

    # 2. Kiểm tra CSWSH (Cross-Site WebSocket Hijacking) với Origin giả mạo
    if check_cswsh:
        cswsh_key = _generate_sec_websocket_key()
        evil_origin = "https://evil-attacker-site.com"
        cswsh_lines = [
            f"GET {path} HTTP/1.1",
            f"Host: {host}:{port}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {cswsh_key}",
            "Sec-WebSocket-Version: 13",
            f"Origin: {evil_origin}",
        ]
        for k, v in custom_hdrs.items():
            if k.lower() != "origin":
                cswsh_lines.append(f"{k}: {v}")
        cswsh_lines.extend(["", ""])
        cswsh_raw = "\r\n".join(cswsh_lines).encode("utf-8")

        try:
            sock2 = socket.create_connection((host, port), timeout=timeout)
            if is_ssl:
                ctx2 = ssl.create_default_context()
                ctx2.check_hostname = False
                ctx2.verify_mode = ssl.CERT_NONE
                sock2 = ctx2.wrap_socket(sock2, server_hostname=host)

            sock2.sendall(cswsh_raw)
            resp2 = sock2.recv(4096).decode("utf-8", errors="replace")
            sock2.close()

            if "101 Switching Protocols" in resp2:
                findings.append({
                    "tool": "websocket_fuzzer",
                    "endpoint": path,
                    "method": "WS_HANDSHAKE",
                    "target_param": "Origin",
                    "vuln_type": "Cross-Site WebSocket Hijacking (CSWSH)",
                    "severity": "high",
                    "http_status": 101,
                    "confirmed": True,
                    "evidence": f"WebSocket server không kiểm tra Origin hợp lệ, chấp nhận kết nối từ '{evil_origin}' với mã 101 Switching Protocols (OWASP API8 / CWE-346).",
                    "reproduction": {"method": "GET", "url": ws_url, "headers": {"Origin": evil_origin, "Upgrade": "websocket"}},
                })
        except Exception:
            pass

    return findings


def audit_sse_endpoint(
    sse_url: str,
    headers: dict[str, str] | None = None,
    timeout: float = 4.0,
    insecure: bool = False,
) -> list[dict[str, Any]]:
    """Kiểm tra endpoint Server-Sent Events (SSE) rò rỉ dữ liệu hoặc thiếu xác thực."""
    findings: list[dict[str, Any]] = []
    req_hdrs = {"Accept": "text/event-stream"}
    if headers:
        for k, v in headers.items():
            if k.lower() not in ("authorization", "cookie"):
                req_hdrs[k] = v

    try:
        resp = requests.get(sse_url, headers=req_hdrs, timeout=timeout, verify=not insecure, stream=True)
        content_type = resp.headers.get("Content-Type", "").lower()

        if resp.status_code == 200 and "text/event-stream" in content_type:
            # Đọc 1 đoạn stream mẫu
            chunk = ""
            for raw_line in resp.iter_lines():
                if raw_line:
                    line_text = raw_line.decode("utf-8", errors="replace") if isinstance(raw_line, (bytes, bytearray)) else str(raw_line)
                    chunk += line_text + "\n"
                if len(chunk) > 200:
                    break

            findings.append({
                "tool": "websocket_fuzzer",
                "endpoint": urllib.parse.urlparse(sse_url).path,
                "method": "GET",
                "target_param": "Accept: text/event-stream",
                "vuln_type": "Unauthenticated Server-Sent Events (SSE) Stream",
                "severity": "medium",
                "http_status": 200,
                "confirmed": True,
                "evidence": f"SSE Stream mở công khai không yêu cầu xác thực người dùng. Dữ liệu rò rỉ mẫu:\n{chunk[:250]}",
                "reproduction": {"method": "GET", "url": sse_url, "headers": {"Accept": "text/event-stream"}},
            })
    except Exception:
        pass

    return findings
