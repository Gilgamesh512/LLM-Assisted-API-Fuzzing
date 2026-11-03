"""
core/stateful_chain.py — Stateful Context Chaining & Multi-step Workflow Execution.

Phục vụ phát hiện các lỗ hổng logic nghiệp vụ phức tạp (BOLA, BFLA, Multi-step Flows):
- Trích xuất dữ liệu động (Dynamic Data Extraction) từ phản hồi HTTP bước trước (ví dụ: created ID, token).
- Tiêm (Inject) giá trị trích xuất vào các tham số (path, query, body, header) của bước sau.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

_TEMPLATE_VAR_RE = re.compile(r"\{\{([a-zA-Z0-9_]+)\}\}|\{([a-zA-Z0-9_]+)\}")


class StatefulContext:
    """Quản lý trạng thái chia sẻ giữa các bước trong một workflow tấn công."""

    def __init__(self, initial_vars: dict[str, Any] | None = None) -> None:
        self.variables: dict[str, Any] = dict(initial_vars or {})

    def set(self, key: str, value: Any) -> None:
        self.variables[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        return self.variables.get(key, default)

    def resolve_template(self, text: str) -> str:
        """Thay thế các placeholder như {{id}} hoặc {id} bằng giá trị trong context."""
        if not text or not isinstance(text, str):
            return text

        def _replace(match: re.Match[str]) -> str:
            var_name = match.group(1) or match.group(2)
            if var_name in self.variables:
                return str(self.variables[var_name])
            return match.group(0)

        return _TEMPLATE_VAR_RE.sub(_replace, text)

    def resolve_object(self, obj: Any) -> Any:
        """Đệ quy thay thế placeholder trong chuỗi, dict hoặc list."""
        if isinstance(obj, str):
            return self.resolve_template(obj)
        if isinstance(obj, dict):
            return {self.resolve_template(str(k)): self.resolve_object(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.resolve_object(item) for item in obj]
        return obj

    def extract(self, response_data: Any, extraction_rules: dict[str, str]) -> dict[str, Any]:
        """Trích xuất giá trị từ response_data (JSON dict) theo đường dẫn dot-notation.

        Ví dụ rules: {"order_id": "data.id", "auth_token": "token"}
        """
        extracted = {}
        for var_name, path in extraction_rules.items():
            val = self._query_path(response_data, path)
            if val is not None:
                self.set(var_name, val)
                extracted[var_name] = val
        return extracted

    @staticmethod
    def _query_path(data: Any, path: str) -> Any:
        """Truy vấn giá trị theo chuỗi đường dẫn a.b.c."""
        if not path or not isinstance(data, (dict, list)):
            return None
        parts = path.strip().split(".")
        current = data
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            elif isinstance(current, list) and part.isdigit():
                idx = int(part)
                current = current[idx] if 0 <= idx < len(current) else None
            else:
                return None
            if current is None:
                return None
        return current


@dataclass
class ChainStep:
    name: str
    method: str
    path: str
    headers: dict[str, str] = field(default_factory=dict)
    body: Any = None
    params: dict[str, Any] = field(default_factory=dict)
    extractors: dict[str, str] = field(default_factory=dict)
    expected_status: tuple[int, ...] = (200, 201, 204)
    expect_security_failure: bool = False  # Dùng khi test BOLA: kỳ vọng 403, nếu ra 200 là dính lỗ hổng


@dataclass
class StepResult:
    step_name: str
    status_code: int
    executed_path: str
    executed_body: Any
    extracted: dict[str, Any]
    security_flag: bool
    evidence: str


def execute_chain(
    steps: list[ChainStep],
    base_url: str,
    *,
    context: StatefulContext | None = None,
    requester: Callable[[str, str, dict[str, str], Any, dict[str, Any]], tuple[int, Any]] | None = None,
) -> list[StepResult]:
    """Thực thi tuần tự một chuỗi các request có liên kết trạng thái (Stateful Chaining)."""
    ctx = context or StatefulContext()
    results: list[StepResult] = []
    base_url = base_url.rstrip("/")

    for step in steps:
        resolved_path = ctx.resolve_template(step.path)
        resolved_headers = {k: ctx.resolve_template(v) for k, v in step.headers.items()}
        resolved_body = ctx.resolve_object(step.body)
        resolved_params = ctx.resolve_object(step.params)
        full_url = f"{base_url}/{resolved_path.lstrip('/')}"

        if requester:
            status_code, resp_data = requester(
                step.method.upper(), full_url, resolved_headers, resolved_body, resolved_params
            )
        else:
            import requests
            try:
                resp = requests.request(
                    step.method.upper(),
                    full_url,
                    headers=resolved_headers,
                    json=resolved_body if isinstance(resolved_body, (dict, list)) else None,
                    data=resolved_body if isinstance(resolved_body, str) else None,
                    params=resolved_params,
                    timeout=10,
                )
                status_code = resp.status_code
                try:
                    resp_data = resp.json()
                except Exception:
                    resp_data = resp.text
            except Exception as exc:
                status_code = 0
                resp_data = str(exc)

        extracted = ctx.extract(resp_data, step.extractors)
        security_flag = False
        evidence = f"HTTP {status_code}"

        # Kiểm tra điều kiện BOLA: nếu mong muốn bị chặn (401/403) nhưng lại thành công (200) -> lỗ hổng!
        if step.expect_security_failure:
            if 200 <= status_code < 300:
                security_flag = True
                evidence = f"BOLA / BFLA CONFIRMED: Kỳ vọng bị chặn nhưng endpoint trả về HTTP {status_code} thành công!"
        else:
            if status_code not in step.expected_status:
                evidence = f"HTTP {status_code} khác với mã kỳ vọng {step.expected_status}"

        results.append(
            StepResult(
                step_name=step.name,
                status_code=status_code,
                executed_path=resolved_path,
                executed_body=resolved_body,
                extracted=extracted,
                security_flag=security_flag,
                evidence=evidence,
            )
        )

    return results


__all__ = ["StatefulContext", "ChainStep", "StepResult", "execute_chain"]
