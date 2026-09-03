"""
core/analyzer.py — Task B1: Module phân tích OpenAPI/Swagger.

Đọc file đặc tả API (OpenAPI 3.x hoặc Swagger 2.0, JSON hoặc YAML) và
kết xuất một JSON gọn (endpoint, method, parameter, kiểu dữ liệu,
authentication, JWT, file upload) để nạp cho LLM ở bước B2/B3, tránh
đưa nguyên văn file Swagger hàng nghìn dòng vào ngữ cảnh của model.

Chỉ trích xuất sự thật kỹ thuật (structural facts) lấy từ đặc tả —
KHÔNG suy đoán lỗ hổng. Việc gán "Potential Issue" thuộc phạm vi
api_inventory.csv của Thành viên A / phần sinh payload của B3.

Sử dụng:
    python core/analyzer.py path/to/swagger.yaml -o compact_context.json
    python core/analyzer.py path/to/openapi.json --pretty
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml

HTTP_METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}

# Các security scheme được coi là "JWT-like" khi tên/scheme gợi ý bearer/JWT.
_JWT_HINT_NAMES = {"authorization", "bearer", "jwt", "token", "x-access-token"}


class SpecLoadError(RuntimeError):
    """Lỗi khi không đọc/parse được file đặc tả API."""


def load_spec(path: str | Path) -> dict[str, Any]:
    """Đọc file OpenAPI/Swagger JSON hoặc YAML thành dict.

    Không tự "sửa" spec lỗi — nếu spec không hợp lệ về mặt cú pháp,
    ném SpecLoadError kèm lý do rõ ràng (đúng tinh thần "nếu lỗi thì
    ghi rõ, không tự sửa âm thầm" trong kế hoạch của Thành viên A).
    """
    p = Path(path)
    if not p.is_file():
        raise SpecLoadError(f"Không tìm thấy file: {p}")

    raw = p.read_text(encoding="utf-8")
    try:
        if p.suffix.lower() in {".yaml", ".yml"}:
            spec = yaml.safe_load(raw)
        else:
            try:
                spec = json.loads(raw)
            except json.JSONDecodeError:
                # một số Swagger export vẫn là YAML dù đuôi .json
                spec = yaml.safe_load(raw)
    except (yaml.YAMLError, json.JSONDecodeError) as exc:
        raise SpecLoadError(f"File đặc tả không hợp lệ ({p.name}): {exc}") from exc

    if not isinstance(spec, dict):
        raise SpecLoadError(f"File đặc tả không đúng cấu trúc object gốc: {p.name}")
    if "paths" not in spec:
        raise SpecLoadError(f"File đặc tả thiếu khoá 'paths' (có phải OpenAPI/Swagger không?): {p.name}")
    return spec


def _resolve_ref(spec: dict[str, Any], ref: str) -> Any:
    """Resolve một local $ref dạng '#/components/schemas/User'."""
    if not ref.startswith("#/"):
        return {}
    node: Any = spec
    for part in ref.lstrip("#/").split("/"):
        if not isinstance(node, dict) or part not in node:
            return {}
        node = node[part]
    return node


def _deep_resolve(node: Any, spec: dict[str, Any], depth: int = 0) -> Any:
    """Resolve $ref đệ quy (giới hạn độ sâu để tránh vòng lặp vô hạn)."""
    if depth > 10 or not isinstance(node, dict):
        return node
    if "$ref" in node:
        resolved = _resolve_ref(spec, node["$ref"])
        return _deep_resolve(resolved, spec, depth + 1)
    return {
        k: (
            _deep_resolve(v, spec, depth + 1)
            if isinstance(v, dict)
            else [_deep_resolve(i, spec, depth + 1) for i in v]
            if isinstance(v, list)
            else v
        )
        for k, v in node.items()
    }


def _get_security_schemes(spec: dict[str, Any]) -> dict[str, Any]:
    """Lấy security schemes, hỗ trợ cả OpenAPI 3.x và Swagger 2.0."""
    if "components" in spec:  # OpenAPI 3.x
        return spec.get("components", {}).get("securitySchemes", {}) or {}
    return spec.get("securityDefinitions", {}) or {}  # Swagger 2.0


def _scheme_is_jwt_like(name: str, scheme: dict[str, Any]) -> bool:
    scheme_type = str(scheme.get("type", "")).lower()
    http_scheme = str(scheme.get("scheme", "")).lower()
    bearer_format = str(scheme.get("bearerFormat", "")).lower()
    if scheme_type == "http" and http_scheme == "bearer":
        return True
    if "jwt" in bearer_format:
        return True
    if scheme_type == "apikey" and name.lower() in _JWT_HINT_NAMES:
        return True
    if scheme_type == "oauth2":
        return True
    return name.lower() in _JWT_HINT_NAMES


def _security_requirement_names(security: list[dict[str, list[str]]]) -> set[str]:
    names: set[str] = set()
    for requirement in security or []:
        names.update(requirement.keys())
    return names


def _extract_parameters(raw_params: list[Any], spec: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    for raw in raw_params:
        param = _deep_resolve(raw, spec)
        schema = _deep_resolve(param.get("schema", {}), spec) if "schema" in param else {}
        param_type = schema.get("type") or param.get("type") or "unknown"
        result.append(
            {
                "name": param.get("name", "unknown"),
                "type": param_type,
                "location": param.get("in", "unknown"),
                "required": bool(param.get("required", False)),
            }
        )
    return result


def _merge_path_and_operation_params(
    path_params: list[dict[str, Any]], operation_params: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Gộp parameter khai báo ở path-item với parameter khai báo ở operation.

    Theo spec OpenAPI/Swagger, một parameter được định danh duy nhất bởi cặp
    (name, location) — nếu operation khai báo lại cùng (name, location) với
    path-item thì bản khai báo ở operation THẮNG (ghi đè), không được nhân đôi
    trong output. Trước đây hai danh sách chỉ được nối thô (concat) nên cùng
    một parameter có thể xuất hiện 2 lần trong JSON gọn đưa cho LLM.
    """
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for p in path_params:
        merged[(p["name"], p["location"])] = p
    for p in operation_params:
        merged[(p["name"], p["location"])] = p
    return list(merged.values())


def _flatten_body_schema(schema: dict[str, Any], spec: dict[str, Any], prefix: str = "") -> list[dict[str, Any]]:
    """Chuyển schema JSON của request body thành danh sách tham số phẳng
    (chỉ 1 cấp, đủ để LLM hiểu ngữ cảnh mà không tràn token với schema lồng sâu).
    """
    schema = _deep_resolve(schema, spec)
    props = schema.get("properties", {})
    required = set(schema.get("required", []) or [])
    out = []
    for name, prop_schema in props.items():
        prop_schema = _deep_resolve(prop_schema, spec)
        full_name = f"{prefix}{name}"
        out.append(
            {
                "name": full_name,
                "type": prop_schema.get("type", "unknown"),
                "location": "body",
                "required": name in required,
            }
        )
    return out


def _extract_request_body(operation: dict[str, Any], spec: dict[str, Any]) -> tuple[list[dict[str, Any]], bool]:
    """Trả về (parameters từ body, file_upload flag) cho OpenAPI 3.x."""
    request_body = _deep_resolve(operation.get("requestBody", {}), spec)
    content = request_body.get("content", {})
    file_upload = False
    params: list[dict[str, Any]] = []

    for content_type, media in content.items():
        media_schema = _deep_resolve(media.get("schema", {}), spec)
        if content_type == "multipart/form-data" or "form-data" in content_type:
            file_upload = True
        # Phát hiện field kiểu file (type: string, format: binary)
        for prop_name, prop_schema in media_schema.get("properties", {}).items():
            prop_schema = _deep_resolve(prop_schema, spec)
            if prop_schema.get("format") == "binary" or prop_schema.get("type") == "file":
                file_upload = True
        params.extend(_flatten_body_schema(media_schema, spec))
    return params, file_upload


def _extract_swagger2_body_and_form(raw_params: list[Any], spec: dict[str, Any]) -> tuple[list[dict[str, Any]], bool]:
    """Swagger 2.0: body nằm trong parameters với in=body/formData."""
    params: list[dict[str, Any]] = []
    file_upload = False
    for raw in raw_params:
        p = _deep_resolve(raw, spec)
        location = p.get("in")
        if location == "body":
            body_schema = _deep_resolve(p.get("schema", {}), spec)
            params.extend(_flatten_body_schema(body_schema, spec))
        elif location == "formData":
            p_type = p.get("type", "unknown")
            if p_type == "file":
                file_upload = True
            params.append(
                {
                    "name": p.get("name", "unknown"),
                    "type": p_type,
                    "location": "form-data",
                    "required": bool(p.get("required", False)),
                }
            )
    return params, file_upload


def analyze(spec: dict[str, Any]) -> list[dict[str, Any]]:
    """Trích xuất danh sách endpoint gọn từ spec đã load."""
    security_schemes = _get_security_schemes(spec)
    jwt_scheme_names = {name for name, s in security_schemes.items() if _scheme_is_jwt_like(name, s)}
    global_security = spec.get("security", [])

    endpoints: list[dict[str, Any]] = []
    for path, path_item in (spec.get("paths") or {}).items():
        if not isinstance(path_item, dict):
            continue
        path_item_resolved = _deep_resolve(path_item, spec)
        path_level_params = path_item_resolved.get("parameters", []) or []

        for method, operation in path_item_resolved.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue

            operation_params_raw = operation.get("parameters", []) or []
            parameters = _merge_path_and_operation_params(
                _extract_parameters(path_level_params, spec),
                _extract_parameters(operation_params_raw, spec),
            )

            if "components" in spec:  # OpenAPI 3.x
                body_params, file_upload = _extract_request_body(operation, spec)
            else:  # Swagger 2.0
                body_params, file_upload = _extract_swagger2_body_and_form(
                    path_level_params + operation_params_raw, spec
                )
            parameters.extend(body_params)

            security = operation.get("security", global_security)
            required_scheme_names = _security_requirement_names(security)
            authentication = bool(required_scheme_names)
            jwt = bool(required_scheme_names & jwt_scheme_names) or (
                authentication and not security_schemes  # spec không khai báo scheme rõ ràng nhưng có auth -> để LLM tự xét
            )

            endpoints.append(
                {
                    "method": method.upper(),
                    "path": path,
                    "operation_id": operation.get("operationId"),
                    "tags": operation.get("tags", []),
                    "parameters": parameters,
                    "authentication": authentication,
                    "jwt": jwt,
                    "file_upload": file_upload,
                }
            )

    endpoints.sort(key=lambda e: (e["path"], e["method"]))
    return endpoints


def analyze_file(path: str | Path) -> list[dict[str, Any]]:
    spec = load_spec(path)
    return analyze(spec)


def _ensure_utf8_console() -> None:
    """Ép stdout/stderr sang UTF-8 — console Windows mặc định (cp1252/cp437)
    sẽ ném UnicodeEncodeError khi in tiếng Việt có dấu nếu không làm việc này.
    """
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (AttributeError, ValueError, OSError):
                pass


def main(argv: list[str] | None = None) -> int:
    _ensure_utf8_console()
    parser = argparse.ArgumentParser(description="Task B1 — Parse OpenAPI/Swagger thành JSON gọn cho LLM.")
    parser.add_argument("spec_path", help="Đường dẫn file OpenAPI/Swagger (json/yaml)")
    parser.add_argument("-o", "--output", help="File JSON output (mặc định: in ra stdout)")
    parser.add_argument("--pretty", action="store_true", help="In JSON có thụt lề, dễ đọc")
    args = parser.parse_args(argv)

    try:
        endpoints = analyze_file(args.spec_path)
    except SpecLoadError as exc:
        print(f"[analyzer] Lỗi: {exc}", file=sys.stderr)
        return 1

    indent = 2 if args.pretty else None
    output_json = json.dumps(endpoints, ensure_ascii=False, indent=indent)

    if args.output:
        Path(args.output).write_text(output_json, encoding="utf-8")
        print(f"[analyzer] Đã ghi {len(endpoints)} endpoint vào {args.output}", file=sys.stderr)
    else:
        print(output_json)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
