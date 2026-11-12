"""
core/tampering.py — Parameter Tampering (Mass Assignment) & HTTP Verb Tampering Module.

Module kiểm thử bảo mật chuyên sâu không phụ thuộc vào payload tấn công độc hại:
1. Mass Assignment (OWASP API3: Broken Object Property Level Authorization):
   - Tự động tiêm các thuộc tính nhạy cảm/đặc quyền (role, is_admin, balance, status, permissions) vào request body (JSON).
   - Nạp hạt giống thực tế (Live Seed Body) từ lưu lượng HAR để vượt qua 100% hàng rào DTO / Schema validation.
   - Deep State Loopback Verification: Tự động gửi request GET đối ứng để xác thực CSDL có thực sự bị biến đổi ngầm hay không,
     triệt tiêu hoàn toàn báo động giả (Echo-only DTO) và bắt trọn các lỗi ghi đè âm thầm (Silent Persistence).
2. HTTP Verb / Method Tampering & Tunneling (OWASP Testing Guide):
   - Đổi HTTP Method (HEAD, OPTIONS, PUT, PATCH, TRACE) nhằm bypass Auth Middleware hoặc WAF rules.
   - Header-based Method Tunneling (X-HTTP-Method-Override, X-HTTP-Method, X-Method-Override).
   - Phát hiện phương thức TRACE nguy hiểm (Cross-Site Tracing / XST).
"""

from __future__ import annotations

import json
import re
import time
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


def generate_baseline_body(
    parameters: list[dict[str, Any]] | None,
    seed_body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Sinh JSON body mẫu hợp lệ từ đặc tả parameters hoặc từ hạt giống lưu lượng sống (seed_body)."""
    if seed_body and isinstance(seed_body, dict):
        return dict(seed_body)

    body: dict[str, Any] = {}
    if not parameters:
        return {"name": "fuzz_test", "email": "fuzz@example.com", "description": "baseline probe"}

    for p in parameters:
        loc = p.get("location", "")
        if loc != "body":
            continue
        p_name = p.get("name", "")
        p_type = str(p.get("type", "string")).lower()
        sample = p.get("sample_value")

        # Xử lý nested name như user.email
        clean_name = p_name.split(".")[-1].replace("[]", "")
        if not clean_name:
            continue

        if sample is not None:
            body[clean_name] = sample
        elif "int" in p_type or p_type == "number":
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


def resolve_endpoint_url(
    base_url: str,
    path: str,
    sample_params: dict[str, Any] | None = None,
) -> str:
    """Thay thế các placeholder {id}, {user_id} bằng giá trị thực tế hoặc giá trị an toàn mẫu (ví dụ: '1')."""
    clean_path = path

    def _replace_var(match: re.Match[str]) -> str:
        var_name = match.group(1)
        if sample_params and var_name in sample_params:
            return str(sample_params[var_name])
        return "1"

    clean_path = _PARAM_REGEX.sub(_replace_var, clean_path)
    return f"{base_url.rstrip('/')}/{clean_path.lstrip('/')}"


def find_matching_getter(ep: dict[str, Any], endpoints: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Tìm endpoint GET tương ứng để phục vụ kiểm chứng trạng thái ngầm (Deep State Loopback Verification)."""
    target_path = str(ep.get("path", "")).strip()
    clean_target = target_path.rstrip("/")

    # Ưu tiên 1: Cùng path chính xác nhưng method là GET (vd: PUT /api/profile -> GET /api/profile)
    for other in endpoints:
        if str(other.get("method", "")).upper() == "GET":
            other_path = str(other.get("path", "")).strip().rstrip("/")
            if other_path == clean_target:
                return other

    # Ưu tiên 2: Path của getter là item cụ thể của collection (vd: POST /users -> GET /users/{id} hoặc GET /users/me)
    for other in endpoints:
        if str(other.get("method", "")).upper() == "GET":
            other_path = str(other.get("path", "")).strip().rstrip("/")
            if other_path.startswith(clean_target + "/"):
                sub_part = other_path[len(clean_target) + 1 :]
                # Chỉ match 1 cấp con (vd: {id} hoặc me hoặc profile), không match nhánh xa
                if "/" not in sub_part and ("{" in sub_part or sub_part in ("me", "profile", "current", "self")):
                    return other

    # Ưu tiên 3: Target là hành động con, getter là resource cha (vd: PUT /users/1/profile hoặc POST /users/update -> GET /users/1)
    t_parts = [p for p in clean_target.split("/") if p]
    if len(t_parts) >= 2:
        last_segment = t_parts[-1].lower()
        if last_segment in ("update", "edit", "modify", "profile", "settings", "me"):
            parent_resource = "/" + "/".join(t_parts[:-1])
            for other in endpoints:
                if str(other.get("method", "")).upper() == "GET":
                    other_path = str(other.get("path", "")).strip().rstrip("/")
                    if other_path == parent_resource or other_path.startswith(parent_resource + "/{"):
                        return other

    return None


def check_mass_assignment_reflection(probe: dict[str, Any], response_data: Any) -> tuple[bool, str]:
    """Kiểm tra xem thuộc tính nhạy cảm tiêm vào có được phản hồi trong dữ liệu trả về hay không."""
    if not isinstance(response_data, (dict, list)):
        return False, ""

    for probe_key, probe_val in probe.items():
        if isinstance(response_data, dict):
            if probe_key in response_data:
                actual_val = response_data[probe_key]
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
    deep_verify: bool = True,
    seed_corpus: Any | None = None,
) -> list[dict[str, Any]]:
    """Tự động kiểm thử Mass Assignment (Parameter Tampering) trên các mutate endpoints (POST, PUT, PATCH).
    
    Hỗ trợ:
    - Nạp hạt giống thực tế từ Live Seed Body (seed_corpus hoặc ep['seed_body']).
    - Deep State Loopback Verification: Gửi request GET đối ứng kiểm tra CSDL có thực sự lưu thuộc tính đặc quyền hay không.
    """
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

        # Thu thập sample params để resolve path chính xác
        sample_params: dict[str, Any] = {}
        for p in ep.get("parameters", []) or []:
            if isinstance(p, dict) and p.get("sample_value") is not None:
                sample_params[p.get("name", "")] = p["sample_value"]

        url = resolve_endpoint_url(base_url, path, sample_params)

        if scope_guard and not scope_guard.is_in_scope(url):
            continue

        # Nạp hạt giống sống nếu có từ endpoint hoặc seed_corpus
        seed_body = ep.get("seed_body")
        if not seed_body and seed_corpus:
            seed_body = seed_corpus.get_body_seed(method, path)

        baseline_body = generate_baseline_body(ep.get("parameters"), seed_body=seed_body)

        for probe in MASS_ASSIGNMENT_PROBES:
            if abort_event and abort_event.is_set():
                break

            if rate_limiter:
                rate_limiter.wait()

            tampered_body = dict(baseline_body)
            tampered_body.update(probe)
            probe_keys = list(probe.keys())
            is_critical = any(k in probe for k in ("role", "roles", "is_admin", "isAdmin", "admin", "balance", "permissions"))

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

                # ==============================================================
                # DEEP STATE LOOPBACK VERIFICATION: Xác minh CSDL thực tế qua GET
                # ==============================================================
                getter_ep = find_matching_getter(ep, endpoints) if deep_verify else None
                loopback_verified = False
                loopback_evidence = ""
                echo_only_detected = False

                if getter_ep and 200 <= status < 300:
                    getter_path = getter_ep.get("path", "")
                    verify_url = resolve_endpoint_url(base_url, getter_path, sample_params)

                    if rate_limiter:
                        rate_limiter.wait()

                    try:
                        verify_resp = session.request("GET", verify_url, headers=headers, timeout=timeout)
                        if verify_resp.status_code == 200:
                            v_json = verify_resp.json()
                            getter_reflected, getter_msg = check_mass_assignment_reflection(probe, v_json)

                            if getter_reflected:
                                # [XÁC MINH 100% THÀNH CÔNG] Thuộc tính đặc quyền đã thực sự lưu vào CSDL
                                loopback_verified = True
                                loopback_evidence = (
                                    f"[DEEP STATE LOOPBACK VERIFIED] Mutation {method} {path} được server chấp nhận (HTTP {status}) "
                                    f"và request kiểm tra ngầm GET {getter_path} XÁC NHẬN thuộc tính đặc quyền {probe} đã được lưu trữ vĩnh viễn "
                                    f"trong cơ sở dữ liệu! ({getter_msg})"
                                )
                            elif reflected:
                                # [TRÁNH BÁO ĐỘNG GIẢ] Server phản hồi thuộc tính trong PUT/POST nhưng GET không có -> Chỉ là echo DTO
                                echo_only_detected = True
                                loopback_evidence = (
                                    f"[ECHO ONLY - NOT PERSISTED] Endpoint {method} {path} phản chiếu thuộc tính {probe} trong response, "
                                    f"nhưng kiểm tra trạng thái ngầm qua GET {getter_path} xác nhận thuộc tính KHÔNG được lưu vào CSDL. "
                                    f"Đã triệt tiêu báo động giả thành công."
                                )
                    except Exception:
                        pass

                # Xử lý phân loại kết quả
                if loopback_verified:
                    findings.append({
                        "tool": "mass_assignment_fuzzer",
                        "target_app": target_name,
                        "endpoint": path,
                        "method": method,
                        "vuln_type": "Mass Assignment",
                        "severity": "critical" if is_critical else "high",
                        "confidence": 100,
                        "http_status": status,
                        "confirmed": True,
                        "evidence": loopback_evidence,
                        "reproduction": {
                            "method": method,
                            "url": url,
                            "tampered_payload": tampered_body,
                            "injected_properties": probe,
                            "verified_getter": getter_ep.get("path") if getter_ep else None,
                            "http_status": status,
                        },
                        "recommendation": (
                            "Áp dụng DTO (Data Transfer Object) nghiêm ngặt hoặc cấu hình allowlist các thuộc tính được phép bind. "
                            "Từ chối hoặc loại bỏ các thuộc tính quản trị/đặc quyền từ request của người dùng."
                        ),
                    })
                    break

                elif echo_only_detected:
                    # Ghi nhận mức Info/Low để lập trình viên biết server có echo thừa, nhưng không kích hoạt chuông báo động giả
                    findings.append({
                        "tool": "mass_assignment_fuzzer",
                        "target_app": target_name,
                        "endpoint": path,
                        "method": method,
                        "vuln_type": "Mass Assignment (Echo-only DTO)",
                        "severity": "info",
                        "confidence": 40,
                        "http_status": status,
                        "confirmed": False,
                        "evidence": loopback_evidence,
                        "reproduction": {
                            "method": method,
                            "url": url,
                            "tampered_payload": tampered_body,
                            "injected_properties": probe,
                            "http_status": status,
                        },
                        "recommendation": "Loại bỏ việc nhại lại (echo) các thuộc tính không xác định trong DTO response.",
                    })
                    continue

                elif reflected:
                    # Đã phản hồi nhưng không có getter để loopback (hoặc getter lỗi) -> Đánh giá theo phản hồi trực tiếp
                    probe_key_str = ", ".join(probe_keys)
                    findings.append({
                        "tool": "mass_assignment_fuzzer",
                        "target_app": target_name,
                        "endpoint": path,
                        "method": method,
                        "vuln_type": "Mass Assignment",
                        "severity": "critical" if is_critical else "high",
                        "confidence": 90,
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
                    break

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

        sample_params: dict[str, Any] = {}
        for p in ep.get("parameters", []) or []:
            if isinstance(p, dict) and p.get("sample_value") is not None:
                sample_params[p.get("name", "")] = p["sample_value"]

        url = resolve_endpoint_url(base_url, path, sample_params)

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
