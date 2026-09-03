"""Sinh suite.json tự động từ tài liệu OpenAPI/Swagger (bản rule-based).

Đây là bản THAY TẠM cho module B (LLM Generator) để module C test độc lập:
đọc spec -> với mỗi endpoint/tham số, gắn payload mặc định theo loại lỗ hổng
-> xuất ra suite.json đúng "hợp đồng dữ liệu" mà run_nuclei nhận.

Trong hệ thống thật, B dùng LLM để sinh payload context-aware; file này chỉ dùng
vài payload cố định theo heuristic tên/loại tham số.

Chạy:
    python -m executor.tools.suite_from_openapi --spec openapi.json -o suite.json
    python -m executor.tools.suite_from_openapi --spec openapi.json --target http://host -o suite.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

PAYLOADS = {
    "sqli": "1' OR '1'='1",
    "xss": "<script>alert(9)</script>",
    "ssrf": "http://169.254.169.254/latest/meta-data/",
    "traversal": "../../../../etc/passwd",
}

MATCHERS = {
    "sqli": {"status": [500], "words": ["SQL", "syntax", "SQLException", "ORA-", "mysql_"]},
    "xss": {"status": [200], "words": [PAYLOADS["xss"]]},
    "ssrf": {"status": [200], "words": ["metadata", "INTERNAL", "root:x:", "ami-id"]},
    "traversal": {"status": [200], "words": ["root:x:", "/bin/bash"]},
}

SEVERITY = {"sqli": "high", "xss": "medium", "ssrf": "critical", "traversal": "high"}

SSRF_HINTS = ("url", "uri", "link", "dest", "redirect", "target", "callback", "next", "path")


def _categories_for_param(name: str) -> list[str]:
    """Chọn loại lỗ hổng cần thử cho 1 tham số theo tên."""
    low = name.lower()
    if any(h in low for h in SSRF_HINTS):
        return ["ssrf", "sqli", "xss"]
    return ["sqli", "xss"]


def _server_target(spec: dict[str, Any]) -> str | None:
    servers = spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        return servers[0].get("url")
    host = spec.get("host")
    if host:
        scheme = (spec.get("schemes") or ["http"])[0]
        base = spec.get("basePath", "")
        return f"{scheme}://{host}{base}"
    return None


def _iter_params(op: dict[str, Any], path_item: dict[str, Any]) -> list[dict[str, Any]]:
    params = list(path_item.get("parameters", [])) + list(op.get("parameters", []))
    return [p for p in params if p.get("in") in ("path", "query")]


def build_suite(spec: dict[str, Any], target: str | None) -> dict[str, Any]:
    target = target or _server_target(spec) or "http://localhost"
    target = target.rstrip("/")
    cases: list[dict[str, Any]] = []
    counter = 0

    for path, path_item in (spec.get("paths") or {}).items():
        if not isinstance(path_item, dict):
            continue
        for method, op in path_item.items():
            if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                continue
            if not isinstance(op, dict):
                continue
            params = _iter_params(op, path_item)
            for p in params:
                pname = p.get("name")
                if not pname:
                    continue
                for cat in _categories_for_param(pname):
                    counter += 1
                    tc: dict[str, Any] = {
                        "id": f"tc_{counter:03d}_{cat}",
                        "endpoint": path,
                        "method": method.upper(),
                        "vuln_type": cat,
                        "path_params": {},
                        "query_params": {},
                        "payload": PAYLOADS[cat],
                        "matchers": MATCHERS[cat],
                        "severity": SEVERITY[cat],
                    }
                    if p.get("in") == "path":
                        tc["path_params"][pname] = PAYLOADS[cat]
                    else:
                        tc["query_params"][pname] = PAYLOADS[cat]
                    cases.append(tc)

    return {"target": target, "test_cases": cases}


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="python -m executor.tools.suite_from_openapi",
        description="Sinh suite.json từ OpenAPI/Swagger (thay tạm module B).",
    )
    p.add_argument("--spec", "-s", required=True, help="File OpenAPI/Swagger (JSON).")
    p.add_argument("--target", "-u", default=None, help="Ghi đè target (mặc định lấy từ spec).")
    p.add_argument("--output", "-o", default=None, help="File suite.json xuất ra (mặc định: stdout).")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    spec_path = Path(args.spec)
    if not spec_path.exists():
        print(f"Không thấy file spec: {spec_path}", file=sys.stderr)
        return 2
    try:
        spec = json.loads(spec_path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        print(f"Spec không phải JSON hợp lệ: {exc}", file=sys.stderr)
        return 2

    suite = build_suite(spec, args.target)
    text = json.dumps(suite, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(
            f"Đã sinh {len(suite['test_cases'])} test case -> {args.output} "
            f"(target: {suite['target']})",
            file=sys.stderr,
        )
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
