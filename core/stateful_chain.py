"""
core/stateful_chain.py — Stateful Context Chaining & Multi-step Workflow Execution.

Phục vụ phát hiện các lỗ hổng logic nghiệp vụ phức tạp (BOLA, BFLA, Multi-step Flows):
- Trích xuất dữ liệu động (Dynamic Data Extraction) từ phản hồi HTTP bước trước (ví dụ: created ID, token).
- Tiêm (Inject) giá trị trích xuất vào các tham số (path, query, body, header) của bước sau.
"""

from __future__ import annotations

import re
import time
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


def discover_crud_chains(endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Tự động phát hiện các cặp endpoint CRUD có liên kết trạng thái (Stateful Chains).

    Tìm các cặp: (POST /resource) -> (GET/PUT/DELETE /resource/{id}) để kiểm thử BOLA/IDOR.
    """
    chains: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    post_eps = [ep for ep in endpoints if str(ep.get("method", "")).upper() == "POST"]
    item_eps = [
        ep for ep in endpoints
        if str(ep.get("method", "")).upper() in ("GET", "PUT", "DELETE", "PATCH") and "{" in str(ep.get("path", ""))
    ]

    for c_ep in post_eps:
        c_path = str(c_ep.get("path", "")).rstrip("/")
        if not c_path:
            continue
        c_parts = [p for p in c_path.split("/") if p]

        for a_ep in item_eps:
            a_path = str(a_ep.get("path", ""))
            a_method = str(a_ep.get("method", "")).upper()
            a_parts = [p for p in a_path.split("/") if p]
            if not a_parts:
                continue

            var_name = ""
            matched = False

            # Kiểu 1: a_path bắt đầu trực tiếp bằng c_path + /{var} (vd: /orders -> /orders/{id})
            if a_path.startswith(c_path + "/{"):
                m = re.match(r"^" + re.escape(c_path) + r"/\{([a-zA-Z0-9_]+)\}", a_path)
                if m:
                    var_name = m.group(1)
                    matched = True

            # Kiểu 2: Cùng thư mục cha (vd: /users/v1/register và /users/v1/{username})
            if not matched and len(c_parts) > 1 and len(a_parts) == len(c_parts):
                if c_parts[:-1] == a_parts[:-1] and a_parts[-1].startswith("{") and a_parts[-1].endswith("}"):
                    var_name = a_parts[-1].strip("{}")
                    matched = True

            if matched and var_name:
                key = (c_path, a_method, a_path)
                if key not in seen:
                    seen.add(key)
                    chains.append({
                        "create_endpoint": c_ep,
                        "access_endpoint": a_ep,
                        "target_var": var_name,
                        "create_path": c_path,
                        "create_method": "POST",
                        "access_path": a_path,
                        "access_method": a_method,
                    })

    return chains


def _build_sample_body(c_ep: dict[str, Any], default_var_val: str = "bola_target_user") -> dict[str, Any]:
    """Tạo request body mẫu dựa trên tham số đặc tả của endpoint tạo mới."""
    body: dict[str, Any] = {}
    params = c_ep.get("parameters", []) or []
    req_body = c_ep.get("request_body", []) or []

    # Gom các thuộc tính
    all_props = []
    if isinstance(params, list):
        for p in params:
            if isinstance(p, dict) and p.get("in") == "body":
                all_props.append(p.get("name", ""))
    if isinstance(req_body, list):
        for p in req_body:
            if isinstance(p, dict):
                all_props.append(p.get("name", ""))
            elif isinstance(p, str):
                all_props.append(p)

    if not all_props:
        return {
            "username": default_var_val,
            "email": f"{default_var_val}@example.com",
            "password": "Password123!@#",
            "name": "Stateful BOLA Test Item",
        }

    for prop in all_props:
        p_lower = str(prop).lower()
        if "user" in p_lower:
            body[prop] = default_var_val
        elif "pass" in p_lower:
            body[prop] = "Password123!@#"
        elif "mail" in p_lower:
            body[prop] = f"{default_var_val}@example.com"
        elif any(k in p_lower for k in ("id", "code", "num", "amount", "price")):
            body[prop] = 100
        else:
            body[prop] = "test_value"

    return body


def execute_stateful_bola_scan(
    endpoints: list[dict[str, Any]],
    base_url: str,
    *,
    session: Any = None,
    primary_token: str | None = None,
    secondary_token: str | None = None,
    auth_header: str = "Authorization",
    auth_prefix: str = "Bearer ",
    timeout: float = 8.0,
    scope_guard: Any = None,
    rate_limiter: Any = None,
    target_name: str = "api_target",
    abort_event: Any = None,
    max_chains: int = 5,
) -> list[dict[str, Any]]:
    """Tự động phát hiện và thực thi chuỗi tấn công BOLA/IDOR (Stateful Context Chaining)."""
    chains = discover_crud_chains(endpoints)
    findings: list[dict[str, Any]] = []

    if not chains:
        return findings

    user_a_headers: dict[str, str] = {}
    if primary_token:
        user_a_headers[auth_header] = f"{auth_prefix}{primary_token}"

    user_b_headers: dict[str, str] = {}
    if secondary_token:
        user_b_headers[auth_header] = f"{auth_prefix}{secondary_token}"
    else:
        user_b_headers[auth_header] = f"{auth_prefix}attacker-invalid-token"

    test_chains = chains[:max_chains]

    for idx, chain in enumerate(test_chains, start=1):
        if abort_event and abort_event.is_set():
            break

        c_path = chain["create_path"]
        a_path = chain["access_path"]
        a_method = chain["access_method"]
        var_name = chain["target_var"]

        default_val = f"bola_user_{idx}_{int(time.time())}"
        sample_body = _build_sample_body(chain["create_endpoint"], default_var_val=default_val)

        ctx = StatefulContext({var_name: default_val, "id": default_val, "username": default_val})

        step1 = ChainStep(
            name=f"Bước 1: User A tạo tài nguyên ({c_path})",
            method="POST",
            path=c_path,
            headers=user_a_headers,
            body=sample_body,
            extractors={
                var_name: var_name,
                "id": "id",
                "data.id": "id",
                "uuid": "uuid",
                "user_id": "user_id",
                "username": "username",
            },
            expected_status=(200, 201, 204),
        )

        step2 = ChainStep(
            name=f"Bước 2: User B truy cập tài nguyên của User A ({a_method} {a_path})",
            method=a_method,
            path=a_path,
            headers=user_b_headers,
            expect_security_failure=True,  # Kỳ vọng phải bị chặn (401/403/404); nếu 200/204 là BOLA!
        )

        def _requester(method: str, url: str, headers: dict[str, str], body: Any, params: dict[str, Any]) -> tuple[int, Any]:
            if scope_guard and not scope_guard.is_in_scope(url):
                return 0, "Out of scope"
            if rate_limiter:
                rate_limiter.wait()

            import requests
            req_session = session or requests.Session()
            try:
                resp = req_session.request(
                    method,
                    url,
                    headers=headers,
                    json=body if isinstance(body, (dict, list)) else None,
                    params=params,
                    timeout=timeout,
                )
                try:
                    data = resp.json()
                except Exception:
                    data = resp.text
                return resp.status_code, data
            except Exception as exc:
                return 0, str(exc)

        chain_results = execute_chain([step1, step2], base_url, context=ctx, requester=_requester)
        if len(chain_results) >= 2:
            r1, r2 = chain_results[0], chain_results[1]
            if r2.security_flag:
                findings.append({
                    "tool": "stateful_fuzzer",
                    "target_app": target_name,
                    "endpoint": a_path,
                    "method": a_method,
                    "vuln_type": "BOLA",
                    "severity": "critical",
                    "http_status": r2.status_code,
                    "confirmed": True,
                    "bola_detected": True,
                    "confidence": 98,
                    "evidence": (
                        f"[STATEFUL BOLA CONFIRMED] Tài nguyên tạo bởi User A tại '{c_path}' "
                        f"(ID: {ctx.get(var_name)}) bị User B truy cập thành công trái phép "
                        f"tại '{r2.executed_path}' với HTTP {r2.status_code}."
                    ),
                    "reproduction": {
                        "step1": {"method": "POST", "url": r1.executed_path, "status": r1.status_code},
                        "step2": {"method": a_method, "url": r2.executed_path, "status": r2.status_code},
                        "extracted_id": ctx.get(var_name),
                    },
                })

    return findings


__all__ = [
    "StatefulContext",
    "ChainStep",
    "StepResult",
    "execute_chain",
    "discover_crud_chains",
    "execute_stateful_bola_scan",
]
