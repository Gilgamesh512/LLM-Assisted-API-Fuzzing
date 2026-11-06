"""
core/tampering.py — Parameter Tampering (Mass Assignment) & HTTP Verb Tampering Module.

Module kiểm thử bảo mật chuyên sâu không phụ thuộc vào payload tấn công độc hại:
1. Mass Assignment (OWASP API3: Broken Object Property Level Authorization):
   - Tự động tiêm các thuộc tính nhạy cảm/đặc quyền (role, is_admin, balance, status, permissions) vào request body (JSON).
   - Phán đoán Differential Oracle: Xác nhận lỗ hổng khi server trả về 2xx và phản hồi (echo) hoặc ghi nhận thuộc tính trái phép.
2. HTTP Verb / Method Tampering & Tunneling (OWASP Testing Guide):
   - Đổi HTTP Method (HEAD, OPTIONS, PUT, PATCH, TRACE) nhằm bypass Auth Middleware hoặc WAF rules.
   - Header-based Method Tunneling (X-HTTP-Method-Override, X-HTTP-Method, X-Method-Override).
   - Phát hiện phương thức TRACE nguy hiểm (Cross-Site Tracing / XST).
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable

_PARAM_REGEX = re.compile(r"\{([a-zA-Z0-9_]+)\}")

# Các bộ thuộc tính nhạy cảm dùng để tiêm thử nghiệm Mass Assignment
MASS_ASSIGNMENT_PROBES: list[dict[str, Any]] = [
    # 1. Role & Admin Escalation
    {"role": "admin"},
    {"roles": ["admin"]},
    {"is_admin": True},
    {"isAdmin": True},
    {"admin": True},
    {"account_type": "admin"},
    {"user_type": "administrator"},
    # 2. Permissions & Privileges
    {"permissions": ["*", "admin", "superuser"]},
    {"superuser": True},
    {"is_superuser": True},
    {"scope": "admin:all"},
    # 3. Account Status & Verification Bypass
    {"is_verified": True},
    {"verified": True},
    {"status": "active"},
    {"state": "approved"},
    {"email_verified": True},
    # 4. Financial & Tier Escalation
    {"balance": 999999},
    {"credit": 999999},
    {"plan": "enterprise"},
    {"tier": "premium"},
    {"discount": 100},
    # 5. Multi-tenant & Ownership Tampering
    {"tenant_id": 1},
    {"organization_id": 1},
    {"owner_id": 1},
]

# Các header ghi đè HTTP method thường được hỗ trợ bởi các web framework
METHOD_OVERRIDE_HEADERS = [
    "X-HTTP-Method-Override",
    "X-HTTP-Method",
    "X-Method-Override",
]


def generate_baseline_body(parameters: list[dict[str, Any]] | None) -> dict[str, Any]:
    """Sinh JSON body mẫu hợp lệ từ danh sách parameters của endpoint."""
    body: dict[str, Any] = {}
    if not parameters:
        return {"name": "fuzz_test", "email": "fuzz@example.com", "description": "baseline probe"}

    for p in parameters:
        loc = p.get("location", "")
        if loc != "body":
            continue
        p_name = p.get("name", "")
        p_type = str(p.get("type", "string")).lower()

        # Xử lý nested name như user.email
        clean_name = p_name.split(".")[-1].replace("[]", "")
        if not clean_name:
            continue

        if "int" in p_type or p_type == "number":
            body[clean_name] = 1
        elif "bool" in p_type:
            body[clean_name] = False
        elif "array" in p_type:
            body[clean_name] = ["test"]
        else:
            if "email" in clean_name.lower():
                body[clean_name] = "test@example.com"
            elif "pass" in clean_name.lower():
                body[clean_name] = "Password123!"
            else:
                body[clean_name] = f"test_{clean_name}"

    if not body:
        body = {"title": "fuzz_probe", "status": "pending", "value": "test"}
    return body


def resolve_endpoint_url(base_url: str, path: str) -> str:
    """Thay thế các placeholder {id}, {user_id} bằng giá trị an toàn mẫu (ví dụ: '1')."""
    clean_path = _PARAM_REGEX.sub("1", path)
    return f"{base_url.rstrip('/')}/{clean_path.lstrip('/')}"


def check_mass_assignment_reflection(probe: dict[str, Any], response_data: Any) -> tuple[bool, str]:
    """Kiểm tra xem thuộc tính nhạy cảm tiêm vào có được phản hồi trong dữ liệu trả về hay không."""
    if not isinstance(response_data, (dict, list)):
        return False, ""

    for probe_key, probe_val in probe.items():
        if isinstance(response_data, dict):
            if probe_key in response_data:
                actual_val = response_data[probe_key]
                # Chỉ coi là phản hồi thành công nếu giá trị phản hồi khớp với giá trị đặc quyền đã tiêm
                # Hoặc nếu là cờ boolean, giá trị thực tế phải là True (được kích hoạt)
                if isinstance(probe_val, bool):
                    if actual_val is True or str(actual_val).lower() in ("true", "1"):
                        return True, f"Thuộc tính nhạy cảm '{probe_key}' được kích hoạt thành {actual_val} trong response."
                elif isinstance(probe_val, list):
                    if isinstance(actual_val, list) and any(str(x).lower() in [str(y).lower() for y in probe_val] for x in actual_val):
                        return True, f"Thuộc tính nhạy cảm '{probe_key}' ghi nhận danh sách đặc quyền {actual_val}."
                elif str(actual_val).strip().lower() == str(probe_val).strip().lower():
                    return True, f"Thuộc tính nhạy cảm '{probe_key}': {probe_val} được ghi nhận và phản hồi trong response body."

            # Kiểm tra lồng trong object con (ví dụ: data.role, user.is_admin)
            for sub_val in response_data.values():
                if isinstance(sub_val, (dict, list)):
                    found, msg = check_mass_assignment_reflection(probe, sub_val)
                    if found:
                        return True, msg
        elif isinstance(response_data, list):
            for item in response_data:
                if isinstance(item, (dict, list)):
                    found, msg = check_mass_assignment_reflection(probe, item)
                    if found:
                        return True, msg

    return False, ""


def execute_mass_assignment_scan(
    endpoints: list[dict[str, Any]],
    base_url: str,
    session: Any,
    auth_token: str | None = None,
    auth_header: str = "Authorization",
    auth_prefix: str = "Bearer ",
    timeout: float = 8.0,
    scope_guard: Any | None = None,
    rate_limiter: Any | None = None,
    target_name: str = "API Target",
    abort_event: Any | None = None,
) -> list[dict[str, Any]]:
    """Tự động kiểm thử Mass Assignment (Parameter Tampering) trên các mutate endpoints (POST, PUT, PATCH)."""
    findings: list[dict[str, Any]] = []
    mutate_methods = {"POST", "PUT", "PATCH"}

    # Lọc ra các endpoint có method mutate
    target_endpoints = [e for e in endpoints if e.get("method", "").upper() in mutate_methods]
    if not target_endpoints:
        return findings

    headers: dict[str, str] = {"Content-Type": "application/json"}
    if auth_token:
        headers[auth_header] = f"{auth_prefix}{auth_token}" if auth_prefix else auth_token

    for ep in target_endpoints:
        if abort_event and abort_event.is_set():
            break

        path = ep.get("path", "")
        method = ep.get("method", "POST").upper()
        url = resolve_endpoint_url(base_url, path)

        if scope_guard and not scope_guard.is_in_scope(url):
            continue

        baseline_body = generate_baseline_body(ep.get("parameters"))

        for probe in MASS_ASSIGNMENT_PROBES:
            if abort_event and abort_event.is_set():
                break

            if rate_limiter:
                rate_limiter.wait()

            tampered_body = dict(baseline_body)
            tampered_body.update(probe)
            probe_keys = list(probe.keys())

            try:
                resp = session.request(
                    method=method,
                    url=url,
                    json=tampered_body,
                    headers=headers,
                    timeout=timeout,
                )
            except Exception:
                continue

            status = resp.status_code

            # Nếu API chấp nhận body (200 OK, 201 Created, 204 No Content)
            if 200 <= status < 300:
                resp_json = None
                try:
                    resp_json = resp.json()
                except Exception:
                    pass

                reflected = False
                reflect_msg = ""
                if resp_json:
                    reflected, reflect_msg = check_mass_assignment_reflection(probe, resp_json)

                if reflected:
                    # Đã xác nhận: Server nhận và phản hồi giá trị nhạy cảm được gán
                    probe_key_str = ", ".join(probe_keys)
                    is_critical = any(k in probe for k in ("role", "roles", "is_admin", "isAdmin", "admin", "balance"))
                    findings.append({
                        "tool": "mass_assignment_fuzzer",
                        "target_app": target_name,
                        "endpoint": path,
                        "method": method,
                        "vuln_type": "Mass Assignment",
                        "severity": "critical" if is_critical else "high",
                        "confidence": 95,
                        "http_status": status,
                        "confirmed": True,
                        "evidence": (
                            f"[CONFIRMED MASS ASSIGNMENT] Endpoint {method} {path} chấp nhận và phản ánh thuộc tính đặc quyền {probe}. "
                            f"{reflect_msg} (HTTP {status})"
                        ),
                        "reproduction": {
                            "method": method,
                            "url": url,
                            "tampered_payload": tampered_body,
                            "injected_properties": probe,
                            "http_status": status,
                        },
                        "recommendation": (
                            "Áp dụng DTO (Data Transfer Object) nghiêm ngặt hoặc cấu hình allowlist các thuộc tính được phép bind. "
                            "Từ chối hoặc loại bỏ các thuộc tính quản trị/đặc quyền từ request của người dùng."
                        ),
                    })
                    # Đã xác nhận lỗ hổng nghiêm trọng trên endpoint này, có thể chuyển sang endpoint tiếp theo
                    break
                elif status in (200, 201) and not ep.get("safe_mode_skip"):
                    # Tiềm ẩn: Server chấp nhận 200/201 mà không từ chối 400/422 với thuộc tính ngoài đặc tả
                    # Chỉ ghi nhận nếu chưa có finding confirmed
                    pass

    return findings


def execute_verb_tampering_scan(
    endpoints: list[dict[str, Any]],
    base_url: str,
    session: Any,
    auth_token: str | None = None,
    auth_header: str = "Authorization",
    auth_prefix: str = "Bearer ",
    timeout: float = 8.0,
    scope_guard: Any | None = None,
    rate_limiter: Any | None = None,
    target_name: str = "API Target",
    abort_event: Any | None = None,
) -> list[dict[str, Any]]:
    """Tự động kiểm thử HTTP Verb Tampering, Insecure HTTP Methods và Verb Tunneling qua Headers."""
    findings: list[dict[str, Any]] = []
    alternate_verbs = ["HEAD", "OPTIONS", "PUT", "PATCH", "TRACE"]

    # Ưu tiên các endpoint có authentication hoặc phương thức mutate/nhạy cảm
    for ep in endpoints:
        if abort_event and abort_event.is_set():
            break

        path = ep.get("path", "")
        orig_method = ep.get("method", "GET").upper()
        requires_auth = ep.get("authentication", False) or ep.get("jwt", False)
        url = resolve_endpoint_url(base_url, path)

        if scope_guard and not scope_guard.is_in_scope(url):
            continue

        # 1. Kiểm tra Insecure HTTP TRACE Method (Cross-Site Tracing - XST)
        if rate_limiter:
            rate_limiter.wait()
        try:
            trace_resp = session.request("TRACE", url, timeout=timeout)
            if trace_resp.status_code == 200:
                resp_text = trace_resp.text or ""
                if "TRACE" in resp_text or "Host:" in resp_text:
                    findings.append({
                        "tool": "verb_tampering_fuzzer",
                        "target_app": target_name,
                        "endpoint": path,
                        "method": "TRACE",
                        "vuln_type": "Insecure HTTP Methods (XST)",
                        "severity": "medium",
                        "confidence": 90,
                        "http_status": 200,
                        "confirmed": True,
                        "evidence": f"Phương thức TRACE được bật trên {path} và phản chiếu lại request headers (HTTP 200). Nguy cơ rò rỉ cookie/credentials.",
                        "reproduction": {"method": "TRACE", "url": url, "http_status": 200},
                        "recommendation": "Tắt hoàn toàn phương thức HTTP TRACE trên web server/reverse proxy.",
                    })
        except Exception:
            pass

        # 2. Kiểm tra Verb Tampering Auth Bypass (Gửi Verb thay thế khi KHÔNG có token)
        if requires_auth:
            for alt_verb in ("HEAD", "OPTIONS", "PUT", "PATCH"):
                if alt_verb == orig_method:
                    continue
                if abort_event and abort_event.is_set():
                    break

                if rate_limiter:
                    rate_limiter.wait()

                # Gửi request KHÔNG có authentication header
                unauth_headers = {"Accept": "application/json"}
                try:
                    alt_resp = session.request(alt_verb, url, headers=unauth_headers, timeout=timeout)
                except Exception:
                    continue

                # Nếu phương thức thay thế trả về 200 OK (trong khi endpoint này yêu cầu auth)
                if alt_resp.status_code == 200 and alt_verb == "HEAD":
                    findings.append({
                        "tool": "verb_tampering_fuzzer",
                        "target_app": target_name,
                        "endpoint": path,
                        "method": "HEAD",
                        "vuln_type": "HTTP Verb Tampering (Auth Bypass)",
                        "severity": "high",
                        "confidence": 90,
                        "http_status": 200,
                        "confirmed": True,
                        "evidence": (
                            f"[VERB TAMPERING] Endpoint {orig_method} {path} yêu cầu xác thực, nhưng gửi HTTP HEAD "
                            f"không có token nhận được HTTP 200 OK. Auth filter có thể đã bị bypass."
                        ),
                        "reproduction": {"orig_method": orig_method, "tampered_verb": "HEAD", "url": url, "http_status": 200},
                        "recommendation": "Cấu hình bộ lọc xác thực (Authentication Filter/Middleware) áp dụng đồng nhất cho mọi HTTP method.",
                    })
                    break

        # 3. Kiểm tra Header-based Method Tunneling (X-HTTP-Method-Override, X-HTTP-Method, X-Method-Override)
        if orig_method in ("POST", "PUT"):
            for override_header in METHOD_OVERRIDE_HEADERS:
                if abort_event and abort_event.is_set():
                    break

                if rate_limiter:
                    rate_limiter.wait()

                tunnel_headers = {
                    override_header: "DELETE",
                    "Content-Type": "application/json",
                }
                if auth_token:
                    tunnel_headers[auth_header] = f"{auth_prefix}{auth_token}" if auth_prefix else auth_token

                try:
                    tunnel_resp = session.request(
                        method="POST",
                        url=url,
                        headers=tunnel_headers,
                        json={},
                        timeout=timeout,
                    )
                except Exception:
                    continue

                # Nếu server chấp nhận DELETE qua override header hoặc trả về lỗi cụ thể cho DELETE (ví dụ: method not allowed hoặc 204 deleted)
                if tunnel_resp.status_code in (200, 204):
                    findings.append({
                        "tool": "verb_tampering_fuzzer",
                        "target_app": target_name,
                        "endpoint": path,
                        "method": "POST",
                        "vuln_type": "HTTP Verb Tunneling (Method Override)",
                        "severity": "medium",
                        "confidence": 85,
                        "http_status": tunnel_resp.status_code,
                        "confirmed": True,
                        "evidence": (
                            f"Máy chủ chấp nhận ghi đè HTTP Method qua header '{override_header}: DELETE' "
                            f"(HTTP {tunnel_resp.status_code}). WAF kiểm tra method có thể bị vượt qua."
                        ),
                        "reproduction": {
                            "method": "POST",
                            "header_override": f"{override_header}: DELETE",
                            "url": url,
                            "http_status": tunnel_resp.status_code,
                        },
                        "recommendation": "Tắt hỗ trợ X-HTTP-Method-Override trên reverse proxy hoặc backend nếu không sử dụng clients cũ.",
                    })
                    break

    return findings
