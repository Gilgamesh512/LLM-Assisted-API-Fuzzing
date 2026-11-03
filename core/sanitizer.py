"""
core/sanitizer.py — Data Masking & PII Redaction cho môi trường Doanh nghiệp.

Loại bỏ/che giấu thông tin nhạy cảm (Private IP, Internal Domain, Real Email, Auth Tokens)
khỏi OpenAPI context trước khi gửi cho LLM nhằm tuân thủ quy chuẩn bảo mật (Data Privacy & Compliance).
"""

from __future__ import annotations

import re
from typing import Any

# Regex nhận diện email
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b")

# Regex nhận diện IP nội bộ (RFC 1918)
_INTERNAL_IP_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"
)

# Regex nhận diện internal hostnames
_INTERNAL_HOST_RE = re.compile(
    r"\b[a-zA-Z0-9.-]+\.(?:internal|corp|local|lan|private|dev|intranet)\b",
    re.IGNORECASE,
)

# Regex nhận diện token/secret trong ví dụ
_SECRET_VALUE_RE = re.compile(
    r'(?:bearer\s+[A-Za-z0-9\-_\.]+|ghp_[A-Za-z0-9]{30,}|ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*)',
    re.IGNORECASE,
)


class DataMasker:
    """Mã hoá một chiều/hai chiều các giá trị nhạy cảm trước khi đưa vào LLM."""

    def __init__(self) -> None:
        self.mapping: dict[str, str] = {}
        self.reverse_mapping: dict[str, str] = {}
        self._email_counter = 0
        self._ip_counter = 0
        self._host_counter = 0
        self._token_counter = 0

    def mask_string(self, text: str) -> str:
        if not text or not isinstance(text, str):
            return text

        def _sub_email(match: re.Match[str]) -> str:
            val = match.group(0)
            if val not in self.mapping:
                self._email_counter += 1
                masked = f"user_{self._email_counter}@example.mock"
                self.mapping[val] = masked
                self.reverse_mapping[masked] = val
            return self.mapping[val]

        def _sub_ip(match: re.Match[str]) -> str:
            val = match.group(0)
            if val not in self.mapping:
                self._ip_counter += 1
                masked = f"192.0.2.{self._ip_counter}"  # RFC 5737 TEST-NET-1
                self.mapping[val] = masked
                self.reverse_mapping[masked] = val
            return self.mapping[val]

        def _sub_host(match: re.Match[str]) -> str:
            val = match.group(0)
            if val not in self.mapping:
                self._host_counter += 1
                masked = f"api-service-{self._host_counter}.example.com"
                self.mapping[val] = masked
                self.reverse_mapping[masked] = val
            return self.mapping[val]

        def _sub_secret(match: re.Match[str]) -> str:
            val = match.group(0)
            if val not in self.mapping:
                self._token_counter += 1
                masked = f"REDACTED_SECRET_{self._token_counter}"
                self.mapping[val] = masked
                self.reverse_mapping[masked] = val
            return self.mapping[val]

        text = _SECRET_VALUE_RE.sub(_sub_secret, text)
        text = _INTERNAL_IP_RE.sub(_sub_ip, text)
        text = _INTERNAL_HOST_RE.sub(_sub_host, text)
        text = _EMAIL_RE.sub(_sub_email, text)
        return text

    def mask_object(self, obj: Any) -> Any:
        if isinstance(obj, str):
            return self.mask_string(obj)
        if isinstance(obj, dict):
            return {self.mask_string(str(k)): self.mask_object(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.mask_object(item) for item in obj]
        return obj

    def unmask_string(self, text: str) -> str:
        if not text or not isinstance(text, str):
            return text
        result = text
        for masked, original in self.reverse_mapping.items():
            result = result.replace(masked, original)
        return result


def mask_spec_data(data: Any) -> tuple[Any, dict[str, str]]:
    """Mask OpenAPI / spec data structure, trả về (masked_data, mapping)."""
    masker = DataMasker()
    masked = masker.mask_object(data)
    return masked, masker.reverse_mapping


def unmask_text(text: str, reverse_mapping: dict[str, str]) -> str:
    """Khôi phục text đã bị mask về nguyên trạng."""
    result = text
    for masked, original in reverse_mapping.items():
        result = result.replace(masked, original)
    return result


def unmask_object(obj: Any, reverse_mapping: dict[str, str]) -> Any:
    """Khôi phục object (dict, list, str) đã bị mask về nguyên trạng."""
    if not reverse_mapping:
        return obj
    if isinstance(obj, str):
        return unmask_text(obj, reverse_mapping)
    if isinstance(obj, dict):
        return {
            unmask_text(str(k), reverse_mapping): unmask_object(v, reverse_mapping)
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [unmask_object(item, reverse_mapping) for item in obj]
    return obj


__all__ = ["DataMasker", "mask_spec_data", "unmask_text", "unmask_object"]
