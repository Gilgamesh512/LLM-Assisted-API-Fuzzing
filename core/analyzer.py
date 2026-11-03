"""
core/analyzer.py — Module phân tích OpenAPI/Swagger cho hệ thống LLM-Assisted API Fuzzing.

Đọc file đặc tả API (OpenAPI 3.x hoặc Swagger 2.0, JSON hoặc YAML) và
kết xuất một JSON gọn (endpoint, method, parameter, kiểu dữ liệu lồng sâu,
authentication, JWT, file upload) để nạp cho LLM làm ngữ cảnh.

Hỗ trợ:
- Local & Relative file $ref resolution.
- Multi-level JSON schema flattening (nested objects & array of objects).
- allOf, anyOf, oneOf composition.
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
    """Đọc file OpenAPI/Swagger JSON hoặc YAML thành dict."""
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


def _resolve_ref(spec: dict[str, Any], ref: str, base_dir: Path | None = None) -> Any:
    """Resolve một $ref dạng local ('#/components/...') hoặc file tương đối ('models.yaml#/User')."""
    if not ref or not isinstance(ref, str):
        return {}

    target_spec = spec
    target_ref = ref

    if not ref.startswith("#/"):
        if "#" in ref:
            file_part, _, pointer_part = ref.partition("#")
            pointer_part = pointer_part.lstrip("/")
        else:
            file_part = ref
            pointer_part = ""

        if base_dir:
            ext_path = (base_dir / file_part).resolve()
            if ext_path.is_file():
                try:
                    raw = ext_path.read_text(encoding="utf-8")
                    if ext_path.suffix.lower() in {".yaml", ".yml"}:
                        target_spec = yaml.safe_load(raw)
                    else:
                        target_spec = json.loads(raw)
                except Exception:
                    return {}
                target_ref = f"#/{pointer_part}" if pointer_part else ""
            else:
                return {}
        else:
            return {}

    if not target_ref or target_ref == "#/":
        return target_spec

    node: Any = target_spec
    for part in target_ref.lstrip("#/").split("/"):
        if not isinstance(node, dict) or part not in node:
            return {}
        node = node[part]
    return node


def _deep_resolve(node: Any, spec: dict[str, Any], depth: int = 0, base_dir: Path | None = None) -> Any:
    """Resolve $ref đệ quy (giới hạn độ sâu để tránh vòng lặp vô hạn)."""
    if depth > 10 or not isinstance(node, dict):
        return node
    if "$ref" in node:
        resolved = _resolve_ref(spec, node["$ref"], base_dir=base_dir)
        return _deep_resolve(resolved, spec, depth + 1, base_dir=base_dir)
    return {
        k: (
            _deep_resolve(v, spec, depth + 1, base_dir=base_dir)
            if isinstance(v, dict)
            else [_deep_resolve(i, spec, depth + 1, base_dir=base_dir) for i in v]
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


def _extract_parameters(raw_params: list[Any], spec: dict[str, Any], base_dir: Path | None = None) -> list[dict[str, Any]]:
    result = []
    for raw in raw_params:
        param = _deep_resolve(raw, spec, base_dir=base_dir)
        schema = _deep_resolve(param.get("schema", {}), spec, base_dir=base_dir) if "schema" in param else {}
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
    """Gộp parameter khai báo ở path-item với parameter khai báo ở operation."""
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for p in path_params:
        merged[(p["name"], p["location"])] = p
    for p in operation_params:
        merged[(p["name"], p["location"])] = p
    return list(merged.values())


def _flatten_body_schema(
    schema: dict[str, Any],
    spec: dict[str, Any],
    prefix: str = "",
    max_depth: int = 3,
    base_dir: Path | None = None,
) -> list[dict[str, Any]]:
    """Chuyển schema JSON của request body thành danh sách tham số phẳng,
    hỗ trợ object lồng sâu (nested), mảng object (array of objects), và allOf/anyOf/oneOf.
    """
    if max_depth <= 0 or not isinstance(schema, dict):
        return []

    schema = _deep_resolve(schema, spec, base_dir=base_dir)

    props: dict[str, Any] = {}
    required_set: set[str] = set()

    for combo_key in ("allOf", "anyOf", "oneOf"):
        if combo_key in schema and isinstance(schema[combo_key], list):
            for sub in schema[combo_key]:
                sub_resolved = _deep_resolve(sub, spec, base_dir=base_dir)
                if isinstance(sub_resolved, dict):
                    props.update(sub_resolved.get("properties", {}))
                    required_set.update(sub_resolved.get("required", []) or [])

    props.update(schema.get("properties", {}))
    required_set.update(schema.get("required", []) or [])

    out: list[dict[str, Any]] = []
    for name, raw_prop in props.items():
        prop_schema = _deep_resolve(raw_prop, spec, base_dir=base_dir)
        full_name = f"{prefix}{name}"
        prop_type = prop_schema.get("type", "unknown")

        if (prop_type == "object" or "properties" in prop_schema) and "properties" in prop_schema:
            out.extend(
                _flatten_body_schema(
                    prop_schema,
                    spec,
                    prefix=f"{full_name}.",
                    max_depth=max_depth - 1,
                    base_dir=base_dir,
                )
            )
        elif prop_type == "array" and "items" in prop_schema:
            items_schema = _deep_resolve(prop_schema["items"], spec, base_dir=base_dir)
            if isinstance(items_schema, dict) and ("properties" in items_schema or items_schema.get("type") == "object"):
                out.extend(
                    _flatten_body_schema(
                        items_schema,
                        spec,
                        prefix=f"{full_name}[].",
                        max_depth=max_depth - 1,
                        base_dir=base_dir,
                    )
                )
            else:
                out.append(
                    {
                        "name": full_name,
                        "type": f"array[{items_schema.get('type', 'unknown')}]",
                        "location": "body",
                        "required": name in required_set,
                    }
                )
        else:
            out.append(
                {
                    "name": full_name,
                    "type": prop_type,
                    "location": "body",
                    "required": name in required_set,
                }
            )
    return out


def _extract_request_body(
    operation: dict[str, Any],
    spec: dict[str, Any],
    base_dir: Path | None = None,
) -> tuple[list[dict[str, Any]], bool]:
    """Trả về (parameters từ body, file_upload flag) cho OpenAPI 3.x."""
    request_body = _deep_resolve(operation.get("requestBody", {}), spec, base_dir=base_dir)
    content = request_body.get("content", {})
    file_upload = False
    params: list[dict[str, Any]] = []

    for content_type, media in content.items():
        media_schema = _deep_resolve(media.get("schema", {}), spec, base_dir=base_dir)
        if content_type == "multipart/form-data" or "form-data" in content_type:
            file_upload = True
        # Phát hiện field kiểu file (type: string, format: binary)
        for prop_name, prop_schema in media_schema.get("properties", {}).items():
            prop_schema = _deep_resolve(prop_schema, spec, base_dir=base_dir)
            if prop_schema.get("format") == "binary" or prop_schema.get("type") == "file":
                file_upload = True
        params.extend(_flatten_body_schema(media_schema, spec, base_dir=base_dir))
    return params, file_upload


def _extract_swagger2_body_and_form(
    raw_params: list[Any],
    spec: dict[str, Any],
    base_dir: Path | None = None,
) -> tuple[list[dict[str, Any]], bool]:
    """Swagger 2.0: body nằm trong parameters với in=body/formData."""
    params: list[dict[str, Any]] = []
    file_upload = False
    for raw in raw_params:
        p = _deep_resolve(raw, spec, base_dir=base_dir)
        location = p.get("in")
        if location == "body":
            body_schema = _deep_resolve(p.get("schema", {}), spec, base_dir=base_dir)
            params.extend(_flatten_body_schema(body_schema, spec, base_dir=base_dir))
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


def analyze(spec: dict[str, Any], base_dir: Path | None = None) -> list[dict[str, Any]]:
    """Trích xuất danh sách endpoint gọn từ spec đã load."""
    security_schemes = _get_security_schemes(spec)
    jwt_scheme_names = {name for name, s in security_schemes.items() if _scheme_is_jwt_like(name, s)}
    global_security = spec.get("security", [])

    endpoints: list[dict[str, Any]] = []
    for path, path_item in (spec.get("paths") or {}).items():
        if not isinstance(path_item, dict):
            continue
        path_item_resolved = _deep_resolve(path_item, spec, base_dir=base_dir)
        path_level_params = path_item_resolved.get("parameters", []) or []

        for method, operation in path_item_resolved.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue

            operation_params_raw = operation.get("parameters", []) or []
            parameters = _merge_path_and_operation_params(
                _extract_parameters(path_level_params, spec, base_dir=base_dir),
                _extract_parameters(operation_params_raw, spec, base_dir=base_dir),
            )

            if "components" in spec:  # OpenAPI 3.x
                body_params, file_upload = _extract_request_body(operation, spec, base_dir=base_dir)
            else:  # Swagger 2.0
                body_params, file_upload = _extract_swagger2_body_and_form(
                    path_level_params + operation_params_raw, spec, base_dir=base_dir
                )
            parameters.extend(body_params)

            security = operation.get("security", global_security)
            required_scheme_names = _security_requirement_names(security)
            authentication = bool(required_scheme_names)
            jwt = bool(required_scheme_names & jwt_scheme_names) or (
                authentication and not security_schemes
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
    p = Path(path)
    spec = load_spec(p)
    return analyze(spec, base_dir=p.parent)


def _ensure_utf8_console() -> None:
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (AttributeError, ValueError, OSError):
                pass


def main(argv: list[str] | None = None) -> int:
    _ensure_utf8_console()
    parser = argparse.ArgumentParser(description="Parse OpenAPI/Swagger thành cấu trúc context cho LLM.")
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
