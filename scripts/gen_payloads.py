from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "Nuclei" / "executor"))

from core.analyzer import analyze_file, SpecLoadError  # noqa: E402
from core.gemini_client import call_gemini, GeminiAPIError  # noqa: E402
from core.validator import _extract_json_text  # noqa: E402
from core import target_config as tc  # noqa: E402
from schemas import Suite  # type: ignore  # noqa: E402


ATTACK_TYPES = "SQL_INJECTION, XSS, BOLA, SSRF, COMMAND_INJECTION, AUTH_BYPASS, MASS_ASSIGNMENT, PATH_TRAVERSAL"


class RestPayload(BaseModel):
    model_config = {"extra": "ignore"}

    endpoint: str
    method: str
    target_param: str
    param_location: str = "query"
    attack_type: str
    payload_value: Any
    owasp_category: str | None = None
    context: str | None = None
    expected_signal: list[str] = Field(default_factory=list)
    target_app: str | None = None


class GqlPayload(BaseModel):
    model_config = {"extra": "ignore"}

    query: str
    variables: dict[str, Any] = Field(default_factory=dict)
    operation_name: str | None = None
    operation: str | None = None
    attack_type: str
    payload_value: Any = None
    owasp_category: str | None = None
    context: str | None = None
    expected_signal: list[str] = Field(default_factory=list)
    target_app: str | None = "dvga"


def _ensure_utf8_console() -> None:
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name, None)
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (AttributeError, ValueError, OSError):
                pass


def _gemini_json(system_prompt: str, user_prompt: str) -> Any:
    result = call_gemini(user_prompt, system_prompt=system_prompt)
    raw = result["reply"]
    text = _extract_json_text(raw)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"LLM không trả JSON hợp lệ: {exc}\n--- raw ---\n{raw[:800]}") from exc
    if isinstance(data, dict) and "payloads" in data:
        data = data["payloads"]
    if isinstance(data, dict) and "test_cases" in data:
        return data
    if not isinstance(data, list):
        data = [data]
    return data


def _compact_endpoints(spec_path: str, max_endpoints: int) -> list[dict[str, Any]]:
    endpoints = analyze_file(spec_path)
    with_params = [e for e in endpoints if e["parameters"]]
    without = [e for e in endpoints if not e["parameters"]]
    ordered = with_params + without
    return ordered[:max_endpoints]


def _endpoints_for_prompt(endpoints: list[dict[str, Any]]) -> str:
    lines = []
    for e in endpoints:
        params = ", ".join(
            f"{p['name']}({p['location']}:{p['type']})" for p in e["parameters"]
        ) or "(không tham số)"
        flags = []
        if e.get("authentication"):
            flags.append("auth")
        if e.get("jwt"):
            flags.append("jwt")
        if e.get("file_upload"):
            flags.append("upload")
        tail = f" [{','.join(flags)}]" if flags else ""
        lines.append(f"- {e['method']} {e['path']} | params: {params}{tail}")
    return "\n".join(lines)


_REST_SYSTEM = (
    "Bạn là chuyên gia kiểm thử bảo mật API REST (OWASP API Security Top 10). "
    "Nhiệm vụ: với mỗi endpoint được cho, sinh payload tấn công context-aware bám sát "
    "kiểu dữ liệu & vai trò của tham số. Chỉ nhắm các app lab cố ý có lỗ hổng (vampi/crapi). "
    "TRẢ VỀ DUY NHẤT một JSON array, KHÔNG markdown, KHÔNG giải thích ngoài JSON."
)


def _rest_prompt(target_app: str, endpoints_text: str) -> str:
    return (
        f"App mục tiêu: {target_app}\n\n"
        f"Danh sách endpoint:\n{endpoints_text}\n\n"
        "Sinh 1-2 payload cho mỗi endpoint đáng nghi nhất. Mỗi phần tử JSON có ĐÚNG các field:\n"
        '  "endpoint" (string, y hệt path ở trên),\n'
        '  "method" (GET/POST/PUT/DELETE/PATCH),\n'
        '  "target_param" (tên tham số bị nhắm),\n'
        '  "param_location" (một trong: query|path|body|header),\n'
        f'  "attack_type" (một trong: {ATTACK_TYPES}),\n'
        '  "payload_value" (giá trị payload cụ thể),\n'
        '  "owasp_category" (vd "API1:2023 BOLA"),\n'
        '  "context" (1 câu vì sao payload này hợp ngữ cảnh),\n'
        '  "expected_signal" (mảng từ khoá kỳ vọng thấy trong response, vd ["sql syntax","syntax error"]),\n'
        f'  "target_app" ("{target_app}").\n'
        "Ưu tiên: BOLA cho tham số id/reference, SQLi/XSS cho string tự do, SSRF cho field url, "
        "AUTH_BYPASS/JWT cho endpoint có auth."
    )


def _validate_rest(items: list[Any], target_app: str) -> list[dict[str, Any]]:
    valid: list[dict[str, Any]] = []
    allowed_loc = {"query", "path", "body", "header"}
    for it in items:
        if not isinstance(it, dict):
            continue
        try:
            p = RestPayload.model_validate(it)
        except ValidationError:
            continue
        ep = p.endpoint.strip()
        if not ep.startswith("/") and "/" in ep:
            ep = ep[ep.index("/"):]
        p.endpoint = ep
        if p.param_location not in allowed_loc:
            p.param_location = "query"
        if not p.target_app:
            p.target_app = target_app
        valid.append(p.model_dump())
    return valid


def gen_rest(target_app: str, spec_path: str, out_path: str, max_endpoints: int) -> int:
    print(f"[gen] REST '{target_app}' <- {Path(spec_path).name}")
    endpoints = _compact_endpoints(spec_path, max_endpoints)
    print(f"[gen]   {len(endpoints)} endpoint đưa vào prompt")
    items = _gemini_json(_REST_SYSTEM, _rest_prompt(target_app, _endpoints_for_prompt(endpoints)))
    valid = _validate_rest(items, target_app)
    if not valid:
        print("[gen]   LLM trả 0 payload hợp lệ, thử lại lần 2...")
        items = _gemini_json(_REST_SYSTEM, _rest_prompt(target_app, _endpoints_for_prompt(endpoints)))
        valid = _validate_rest(items, target_app)
    if not valid:
        raise RuntimeError(f"Không sinh được payload REST hợp lệ cho {target_app}")
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text(
        json.dumps({"payloads": valid}, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"[gen]   OK -> {out_path} ({len(valid)} payload)")
    return len(valid)


_GQL_SYSTEM = (
    "Bạn là chuyên gia kiểm thử bảo mật GraphQL API. Mục tiêu là DVGA (Damn Vulnerable "
    "GraphQL Application) — app lab cố ý có lỗ hổng. Sinh các truy vấn GraphQL tấn công "
    "bám sát các field/argument trong schema. TRẢ VỀ DUY NHẤT một JSON array, không markdown."
)


def _gql_fields(schema_path: str) -> str:
    data = json.loads(Path(schema_path).read_text(encoding="utf-8"))
    schema = data.get("data", {}).get("__schema", data.get("__schema", {}))
    names: list[str] = []
    for t in schema.get("types", []):
        if t.get("name") in ("Query", "Mutations", "Mutation") and t.get("fields"):
            for f in t["fields"]:
                names.append(f"{t['name']}.{f['name']}")
    return ", ".join(names) or "(không đọc được field)"


def _gql_prompt(fields: str) -> str:
    return (
        f"Các field khả dụng trong schema DVGA: {fields}\n\n"
        "Sinh 4-8 truy vấn tấn công. Mỗi phần tử JSON có ĐÚNG các field:\n"
        '  "query" (chuỗi GraphQL đầy đủ, vd query { systemDebug(arg: "PAYLOAD") }),\n'
        '  "variables" ({} nếu không dùng),\n'
        '  "operation_name" (null nếu không có),\n'
        '  "operation" ("query" hoặc "mutation"),\n'
        f'  "attack_type" (một trong: {ATTACK_TYPES}),\n'
        '  "payload_value" (chuỗi payload nhồi vào argument),\n'
        '  "owasp_category", "context" (1 câu),\n'
        '  "expected_signal" (mảng từ khoá kỳ vọng trong response),\n'
        '  "target_app" ("dvga").\n'
        "Ưu tiên field có argument nhận string/cmd (vd systemDebug.arg, systemDiagnostics.cmd) "
        "để thử SQL_INJECTION và COMMAND_INJECTION; dùng marker duy nhất (vd DVGA_MARKER) để "
        "dễ nhận diện command injection qua expected_signal."
    )


def _validate_gql(items: list[Any]) -> list[dict[str, Any]]:
    valid: list[dict[str, Any]] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        try:
            p = GqlPayload.model_validate(it)
        except ValidationError:
            continue
        if not p.operation:
            p.operation = "mutation" if p.query.strip().lower().startswith("mutation") else "query"
        valid.append(p.model_dump())
    return valid


def gen_graphql(max_endpoints: int, schema: str, out: str) -> int:
    print(f"[gen] GraphQL <- {Path(schema).name}")
    fields = _gql_fields(schema)
    items = _gemini_json(_GQL_SYSTEM, _gql_prompt(fields))
    valid = _validate_gql(items)
    if not valid:
        print("[gen]   LLM trả 0 payload hợp lệ, thử lại lần 2...")
        items = _gemini_json(_GQL_SYSTEM, _gql_prompt(fields))
        valid = _validate_gql(items)
    if not valid:
        raise RuntimeError("Không sinh được payload GraphQL hợp lệ")
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(
        json.dumps({"payloads": valid}, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"[gen]   OK -> {out} ({len(valid)} payload)")
    return len(valid)


_NUCLEI_SYSTEM = (
    "Bạn là chuyên gia viết test case cho Nuclei để kiểm thử bảo mật API. "
    "Sinh test case bám sát endpoint & tham số của target lab (cố ý có lỗ hổng). "
    "Mỗi test case PHẢI có ít nhất một matcher (status/words/regex) nếu không sẽ bị bỏ qua. "
    "TRẢ VỀ DUY NHẤT một JSON object, không markdown."
)


def _nuclei_prompt(target_app: str, base_url: str, endpoints_text: str) -> str:
    return (
        f"Target app: {target_app}. Base URL: {base_url}\n\n"
        f"Danh sách endpoint:\n{endpoints_text}\n\n"
        "Trả về JSON object ĐÚNG cấu trúc:\n"
        "{\n"
        f'  "target": "{base_url}",\n'
        '  "variables": {},\n'
        '  "test_cases": [\n'
        "    {\n"
        '      "id": "chuoi-duy-nhat",\n'
        '      "endpoint": "/path/bat/dau/bang/slash",\n'
        '      "method": "GET|POST|PUT|DELETE|PATCH",\n'
        '      "vuln_type": "SQLI|XSS|BOLA|SSRF|CMDI|AUTH|...",\n'
        '      "headers": {}, "path_params": {}, "query_params": {}, "body": null,\n'
        '      "payload": "gia tri payload (tuy chon)",\n'
        '      "matchers": {"status": [500], "words": ["SQL syntax","error"], "regex": [], "dsl": [], "condition": "or"},\n'
        '      "severity": "info|low|medium|high|critical"\n'
        "    }\n"
        "  ]\n"
        "}\n"
        "Sinh 6-12 test case. endpoint phải bắt đầu bằng '/'. Mỗi case có ít nhất 1 matcher. "
        'Endpoint cần xác thực: đặt header {"Authorization": "Bearer {{jwt}}"} — dùng ĐÚNG placeholder '
        "{{jwt}}, TUYỆT ĐỐI KHÔNG bịa token thật (token thật được inject lúc chạy qua biến môi trường JWT)."
    )


def build_nuclei_suite(
    app: str, spec: str, base_url: str, max_endpoints: int, feedback: str | None = None
) -> "Suite":
    endpoints = _compact_endpoints(spec, max_endpoints)
    prompt = _nuclei_prompt(app, base_url, _endpoints_for_prompt(endpoints))
    if feedback:
        prompt += "\n\n=== PHẢN HỒI RUNTIME (dựa vào đây để cải thiện thế hệ này) ===\n" + feedback
    data = _gemini_json(_NUCLEI_SYSTEM, prompt)
    if isinstance(data, list):
        data = {"target": base_url, "variables": {}, "test_cases": data}
    data.setdefault("target", base_url)
    data.setdefault("variables", {})
    cleaned_cases: list[dict[str, Any]] = []
    from schemas import Case  # type: ignore

    for tc in data.get("test_cases", []):
        if not isinstance(tc, dict):
            continue
        headers = tc.get("headers")
        if isinstance(headers, dict):
            for hk, hv in list(headers.items()):
                if hk.lower() == "authorization" and isinstance(hv, str) and "{{jwt}}" not in hv:
                    headers[hk] = "Bearer {{jwt}}"
        try:
            case = Case.model_validate(tc)
        except ValidationError:
            continue
        if case.matchers.is_empty():
            continue
        cleaned_cases.append(case.model_dump())
    data["test_cases"] = cleaned_cases
    try:
        return Suite.model_validate(data)
    except ValidationError as exc:
        raise RuntimeError(f"Suite nuclei không hợp lệ: {exc}") from exc


def gen_nuclei(max_endpoints: int, app: str, spec: str, base_url: str, out: str) -> int:
    print(f"[gen] Nuclei suite '{app}' <- {Path(spec).name}")
    suite = build_nuclei_suite(app, spec, base_url, max_endpoints)
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(
        json.dumps(suite.model_dump(), ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"[gen]   OK -> {out} ({len(suite.test_cases)} test case)")
    return len(suite.test_cases)


def main(argv: list[str] | None = None) -> int:
    _ensure_utf8_console()
    parser = argparse.ArgumentParser(description="B sinh payload đúng định dạng cho C (4 file).")
    parser.add_argument(
        "--only",
        choices=["rest", "graphql", "nuclei", "all"],
        default="all",
        help="Chỉ sinh một nhóm (mặc định: all = cả 4 file).",
    )
    parser.add_argument("--max-endpoints", type=int, default=25, help="Số endpoint tối đa đưa vào prompt.")
    parser.add_argument("--config", help="File config target (mặc định config/targets.yaml).")
    parser.add_argument("--target", help="Chỉ sinh cho 1 target trong config (mặc định: tất cả).")
    parser.add_argument("--spec", help="[ad-hoc] File spec của target, bỏ qua config (OpenAPI/Swagger, hoặc GraphQL introspection cho --kind graphql).")
    parser.add_argument("--kind", choices=["rest", "graphql", "nuclei"], help="[ad-hoc] Loại payload sinh cho --spec.")
    parser.add_argument("--target-app", default="custom", help="[ad-hoc] Tên định danh target.")
    parser.add_argument("--base-url", help="[ad-hoc] URL target, bắt buộc khi --kind nuclei.")
    parser.add_argument("--out", help="[ad-hoc] File payload xuất ra.")
    args = parser.parse_args(argv)

    total = 0
    try:
        if args.spec:
            if not args.kind:
                print("[gen] LỖI: dùng --spec phải kèm --kind rest|graphql|nuclei.", file=sys.stderr)
                return 1
            if args.kind == "rest":
                out = args.out or f"Schemathesis/payload_{args.target_app}.json"
                total += gen_rest(args.target_app, args.spec, out, args.max_endpoints)
            elif args.kind == "graphql":
                out = args.out or f"Schemathesis/payload_{args.target_app}_graphql.json"
                total += gen_graphql(args.max_endpoints, schema=args.spec, out=out)
            elif args.kind == "nuclei":
                if not args.base_url:
                    print("[gen] LỖI: --kind nuclei cần --base-url http://target.", file=sys.stderr)
                    return 1
                out = args.out or f"Nuclei/executor/benchmark/suite_{args.target_app}.json"
                total += gen_nuclei(args.max_endpoints, app=args.target_app, spec=args.spec, base_url=args.base_url, out=out)
            print(f"\n[gen] XONG (ad-hoc) — {total} payload/test case. Output: {out}")
            return 0

        cfg_path = args.config or str(tc.DEFAULT_CONFIG_PATH)
        names = [args.target] if args.target else tc.list_targets(cfg_path)
        for name in names:
            t = tc.get_target(name, cfg_path)
            spec = t.resolve_spec_path()
            if t.kind == "rest" and args.only in ("rest", "all"):
                total += gen_rest(name, spec, t.resolved_payload_out(), args.max_endpoints)
            if t.kind == "graphql" and args.only in ("graphql", "all"):
                total += gen_graphql(args.max_endpoints, schema=spec, out=t.resolved_payload_out())
            if t.kind == "rest" and t.nuclei_out and args.only in ("nuclei", "all"):
                total += gen_nuclei(args.max_endpoints, app=name, spec=spec, base_url=t.base_url, out=t.nuclei_out)
    except (SpecLoadError, GeminiAPIError, RuntimeError, ValueError) as exc:
        print(f"[gen] LỖI: {exc}", file=sys.stderr)
        return 1

    print(f"\n[gen] XONG — tổng {total} payload/test case đã sinh & validate.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
