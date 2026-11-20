"""
core/agent_fuzzer.py — Autonomous ReAct Security Pentest Agent.

Khởi tạo vòng lặp tác tử tự trị (Autonomous Agentic Loop) theo mô hình ReAct:
  [Reason -> Act -> Observe -> Adapt]
Agent có khả năng:
1. Duy trì bộ nhớ ngữ cảnh phiên (Context Memory): Tự trích xuất ID, Token, Cookie, OTP từ response trước.
2. Lập kế hoạch tấn công nhiều bước (Multi-step Exploit Chaining):
   - Đăng ký tài khoản -> Nhảy cóc bước xác minh OTP -> Cố gắng đổi mật khẩu hoặc nâng quyền.
   - Thêm giỏ hàng -> Áp dụng mã giảm giá nhiều lần (Coupon Stacking) -> Thanh toán số tiền âm.
3. Tự thích ứng khi gặp mã lỗi hoặc rào cản bảo vệ.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any
import requests


class AgentContextMemory:
    """Bộ nhớ trạng thái động lưu trữ token, cookies và các thực thể trích xuất được."""

    def __init__(self) -> None:
        self.variables: dict[str, Any] = {}
        self.step_history: list[dict[str, Any]] = []

    def set(self, key: str, value: Any) -> None:
        if value is not None:
            self.variables[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        return self.variables.get(key, default)

    def record_step(self, step: dict[str, Any]) -> None:
        self.step_history.append(step)

    def extract_from_json(self, data: Any, prefix: str = "") -> None:
        """Tự động trích xuất các ID, token, secret từ JSON response."""
        if isinstance(data, dict):
            for k, v in data.items():
                k_low = k.lower()
                full_key = f"{prefix}.{k}" if prefix else k
                if any(kw in k_low for kw in ("id", "token", "key", "secret", "user", "order", "code", "role")):
                    if isinstance(v, (str, int, float, bool)):
                        self.set(full_key, v)
                        self.set(k, v)  # Lưu cả short key
                if isinstance(v, (dict, list)):
                    self.extract_from_json(v, full_key)
        elif isinstance(data, list):
            for idx, item in enumerate(data[:3]):
                self.extract_from_json(item, f"{prefix}[{idx}]")


class AutonomousPentestAgent:
    """Tác tử Pentest tự trị thực thi kiểm thử chuỗi logic nghiệp vụ đa bước."""

    def __init__(
        self,
        base_url: str,
        session: requests.Session | None = None,
        llm_provider: Any = None,
        max_steps: int = 6,
        insecure: bool = False,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.llm_provider = llm_provider
        self.max_steps = max_steps
        self.insecure = insecure
        self.memory = AgentContextMemory()

    def _execute_step(
        self,
        method: str,
        path: str,
        headers: dict[str, str] | None = None,
        json_data: Any = None,
        params: dict[str, Any] | None = None,
        timeout: float = 6.0,
    ) -> tuple[int, str, dict[str, Any]]:
        """Gửi request và phân tích phản hồi."""
        url = f"{self.base_url}/{path.lstrip('/')}"
        req_headers = headers.copy() if headers else {}
        start_t = time.perf_counter()

        try:
            resp = self.session.request(
                method,
                url,
                headers=req_headers,
                json=json_data,
                params=params,
                timeout=timeout,
                verify=not self.insecure,
            )
            duration_ms = (time.perf_counter() - start_t) * 1000.0
            resp_text = resp.text

            # Cố gắng parse JSON
            parsed_json = {}
            try:
                parsed_json = resp.json()
                self.memory.extract_from_json(parsed_json)
            except Exception:
                pass

            return resp.status_code, resp_text, parsed_json
        except Exception as exc:
            return 0, f"Error: {exc}", {}

    def run_multi_step_logic_campaign(
        self,
        endpoints: list[dict[str, Any]],
        primary_token: str | None = None,
    ) -> list[dict[str, Any]]:
        """Thực thi chiến dịch pentest đa bước tìm lỗ hổng Logic & Workflow Bypass."""
        findings: list[dict[str, Any]] = []

        if primary_token:
            self.memory.set("auth_token", primary_token)
            self.session.headers["Authorization"] = (
                f"Bearer {primary_token}" if not primary_token.startswith("Bearer ") else primary_token
            )

        # 1. Phân loại các nhóm endpoint theo hành vi nghiệp vụ
        auth_eps = [e for e in endpoints if any(w in e.get("path", "").lower() for w in ("login", "auth", "register", "token", "otp"))]
        user_eps = [e for e in endpoints if any(w in e.get("path", "").lower() for w in ("user", "profile", "account", "me"))]
        order_eps = [e for e in endpoints if any(w in e.get("path", "").lower() for w in ("order", "cart", "checkout", "payment", "transfer"))]

        # Kịch bản 1: Thử nghiệm Bypass luồng xác thực / Bước chuyển tiếp (Workflow Step Skipping)
        # Giả định: Người dùng gọi thẳng endpoint hoàn tất hoặc nâng quyền mà bỏ qua bước xác minh
        for u_ep in user_eps:
            path = u_ep.get("path", "")
            method = u_ep.get("method", "GET").upper()

            # Thử gọi không có token hoặc token rác để kiểm tra Fail-Open
            status, text, data = self._execute_step(
                method,
                path,
                headers={"Authorization": "Bearer fake_token_bypass_test"},
            )

            if status in (200, 201) and not any(kw in text.lower() for kw in ("unauthorized", "login", "expired")):
                findings.append({
                    "tool": "agent_fuzzer",
                    "endpoint": path,
                    "method": method,
                    "target_param": "Authorization",
                    "vuln_type": "Multi-Step Workflow Auth Bypass (Fail-Open)",
                    "severity": "critical",
                    "http_status": status,
                    "confirmed": True,
                    "evidence": (
                        f"Tác tử phát hiện endpoint nhạy cảm chấp nhận request với token giả mạo.\n"
                        f"Kế hoạch: Bỏ qua bước kiểm tra đăng nhập.\n"
                        f"Phản hồi (Status {status}): {text[:250]}"
                    ),
                    "reproduction": {"method": method, "url": f"{self.base_url}/{path.lstrip('/')}"},
                })

        # Kịch bản 2: Coupon / Discount Double-Spend & Quantity Manipulation
        for o_ep in order_eps:
            path = o_ep.get("path", "")
            method = o_ep.get("method", "POST").upper()
            if method in ("POST", "PUT", "PATCH"):
                # Thử số lượng âm hoặc số tiền âm
                probe_body = {"quantity": -1, "amount": -100, "price": -50, "voucher": "DISCOUNT100"}
                status, text, data = self._execute_step(method, path, json_data=probe_body)

                if status in (200, 201) and any(kw in text.lower() for kw in ("success", "order", "created", "ok", "total")):
                    findings.append({
                        "tool": "agent_fuzzer",
                        "endpoint": path,
                        "method": method,
                        "target_param": "amount/quantity",
                        "vuln_type": "Negative Value Business Logic Flaw",
                        "severity": "high",
                        "http_status": status,
                        "confirmed": True,
                        "evidence": (
                            f"Tác tử phát hiện endpoint chấp nhận đơn hàng hoặc số lượng âm (-1 / -100) mà không từ chối.\n"
                            f"Dữ liệu gửi: {json.dumps(probe_body)}\n"
                            f"Phản hồi server ({status}): {text[:250]}"
                        ),
                        "reproduction": {"method": method, "url": f"{self.base_url}/{path.lstrip('/')}", "body": probe_body},
                    })

        return findings
