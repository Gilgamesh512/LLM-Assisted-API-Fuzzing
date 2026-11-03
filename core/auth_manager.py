"""
core/auth_manager.py — Enterprise IAM & Dynamic Token Refresh Manager.

Quản lý vòng đời Authentication cho quá trình Fuzzing dài hạn:
- Hỗ trợ Static Bearer Token, Login Flow, OAuth2 Client Credentials.
- Tự động Refresh Token khi token hết hạn (TTL) hoặc khi gặp phản hồi HTTP 401 Unauthorized.
"""

from __future__ import annotations

import time
from typing import Any, Callable

import requests


class AuthProviderError(RuntimeError):
    """Lỗi khi xác thực hoặc refresh token."""


class TokenManager:
    """Quản lý và tự động refresh Auth Token cho phiên fuzzing."""

    def __init__(
        self,
        *,
        auth_type: str = "static",  # "static" | "login" | "oauth2"
        static_token: str | None = None,
        login_url: str | None = None,
        credentials: dict[str, Any] | None = None,
        token_extractor: Callable[[dict[str, Any]], str] | None = None,
        header_name: str = "Authorization",
        token_prefix: str = "Bearer ",
        ttl_seconds: int = 3600,
    ) -> None:
        self.auth_type = auth_type.lower()
        self.static_token = static_token
        self.login_url = login_url
        self.credentials = dict(credentials or {})
        self.token_extractor = token_extractor
        self.header_name = header_name
        self.token_prefix = token_prefix
        self.ttl_seconds = ttl_seconds

        self._current_token: str | None = static_token
        self._expires_at: float = time.time() + ttl_seconds if static_token else 0.0

    @property
    def is_expired(self) -> bool:
        if self.auth_type == "static":
            return False
        # Đệm 10% TTL hoặc tối đa 30s
        buffer = min(30.0, self.ttl_seconds * 0.1)
        return time.time() >= (self._expires_at - buffer)

    def refresh(self, session: requests.Session | None = None) -> str:
        """Thực hiện login lại hoặc gọi OAuth2 endpoint để lấy token mới."""
        if self.auth_type == "static":
            return self.static_token or ""

        if not self.login_url:
            raise AuthProviderError("Cần login_url để thực hiện refresh token.")

        client = session or requests
        try:
            resp = client.post(self.login_url, json=self.credentials, timeout=15)
        except Exception as exc:
            raise AuthProviderError(f"Lỗi kết nối tới auth endpoint {self.login_url}: {exc}") from exc

        if not resp.ok:
            raise AuthProviderError(f"Xác thực thất bại ({resp.status_code}): {resp.text[:300]}")

        try:
            data = resp.json()
        except Exception:
            raise AuthProviderError(f"Phản hồi auth không phải JSON: {resp.text[:300]}")

        if self.token_extractor:
            token = self.token_extractor(data)
        else:
            token = (
                data.get("token")
                or data.get("access_token")
                or data.get("jwt")
                or data.get("data", {}).get("token")
            )

        if not token:
            raise AuthProviderError(f"Không trích xuất được token từ phản hồi auth: {data}")

        self._current_token = str(token)
        self._expires_at = time.time() + self.ttl_seconds
        return self._current_token

    def get_token(self, session: requests.Session | None = None) -> str:
        """Lấy token hiện tại, tự động refresh nếu hết hạn hoặc chưa có."""
        if not self._current_token or self.is_expired:
            return self.refresh(session=session)
        return self._current_token

    def get_headers(self, session: requests.Session | None = None) -> dict[str, str]:
        """Trả về header xác thực hoàn chỉnh sẵn sàng gửi đi."""
        token = self.get_token(session=session)
        if not token:
            return {}
        return {self.header_name: f"{self.token_prefix}{token}".strip()}

    def handle_response(self, response: requests.Response, session: requests.Session | None = None) -> bool:
        """Nếu gặp mã 401 Unauthorized, gọi refresh token.

        Trả về True nếu đã refresh thành công và caller nên thử lại request.
        """
        if response.status_code == 401 and self.auth_type != "static":
            try:
                self.refresh(session=session)
                return True
            except AuthProviderError:
                return False
        return False


__all__ = ["AuthProviderError", "TokenManager"]
