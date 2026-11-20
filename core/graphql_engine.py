"""core/graphql_engine.py — GraphQL Schema Introspection & Security Fuzzing Adapter.

Hỗ trợ LLM hiểu và tấn công ứng dụng GraphQL:
- Truy vấn Introspection Schema từ endpoint /graphql.
- Tóm tắt Query, Mutation, và Types thành ngữ cảnh cô đọng (Context-Aware) cho LLM.
- Sinh các mẫu truy vấn tấn công logic đặc thù: Đệ quy lồng sâu (Query Depth DoS), Batching/Aliasing, và BOLA trên Mutations.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Optional

import requests

from core.curl_builder import build_curl_command

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          name
          description
          type {
            name
            kind
            ofType {
              name
              kind
            }
          }
        }
        type {
          name
          kind
          ofType {
            name
            kind
          }
        }
      }
    }
  }
}
"""


@dataclass
class GraphQLField:
    name: str
    args: list[dict[str, str]] = field(default_factory=list)
    return_type: str = "Unknown"


@dataclass
class GraphQLSchemaSummary:
    queries: list[GraphQLField] = field(default_factory=list)
    mutations: list[GraphQLField] = field(default_factory=list)
    types: list[str] = field(default_factory=list)

    def to_llm_context(self, max_items: int = 25) -> str:
        """Tạo chuỗi mô tả cấu trúc GraphQL ngắn gọn để đưa vào prompt cho LLM."""
        lines = ["[GRAPHQL SCHEMA CONTEXT]"]
        if self.queries:
            lines.append("Queries:")
            for q in self.queries[:max_items]:
                arg_str = ", ".join(f"{a['name']}: {a['type']}" for a in q.args)
                lines.append(f"  - {q.name}({arg_str}) -> {q.return_type}")

        if self.mutations:
            lines.append("Mutations:")
            for m in self.mutations[:max_items]:
                arg_str = ", ".join(f"{a['name']}: {a['type']}" for a in m.args)
                lines.append(f"  - {m.name}({arg_str}) -> {m.return_type}")

        return "\n".join(lines)


def fetch_graphql_introspection(
    url: str,
    headers: dict[str, str] | None = None,
    timeout: float = 6.0,
    insecure: bool = False,
) -> Optional[dict[str, Any]]:
    """Gửi Introspection Query đến endpoint GraphQL để lấy toàn bộ schema."""
    req_headers = dict(headers or {})
    if "content-type" not in [k.lower() for k in req_headers]:
        req_headers["Content-Type"] = "application/json"

    try:
        resp = requests.post(
            url,
            json={"query": INTROSPECTION_QUERY},
            headers=req_headers,
            timeout=timeout,
            verify=not insecure,
        )
        if resp.status_code == 200:
            data = resp.json()
            if "data" in data and "__schema" in data["data"]:
                return data["data"]["__schema"]
    except Exception:
        pass
    return None


def parse_graphql_schema(schema_data: dict[str, Any]) -> GraphQLSchemaSummary:
    """Chuyển đổi dữ liệu Introspection thô thành GraphQLSchemaSummary gọn nhẹ."""
    summary = GraphQLSchemaSummary()
    types_list = schema_data.get("types", [])

    query_type_name = (schema_data.get("queryType") or {}).get("name", "Query")
    mutation_type_name = (schema_data.get("mutationType") or {}).get("name", "Mutation")

    for t in types_list:
        t_name = t.get("name", "")
        # Bỏ qua internal introspection types (__Directive, __Field, ...)
        if t_name.startswith("__"):
            continue

        if t_name == query_type_name:
            for f in t.get("fields") or []:
                args = [
                    {"name": a.get("name", ""), "type": (a.get("type", {}) or {}).get("name") or "Any"}
                    for a in (f.get("args") or [])
                ]
                ret = (f.get("type") or {}).get("name") or "Any"
                summary.queries.append(GraphQLField(name=f.get("name", ""), args=args, return_type=ret))

        elif t_name == mutation_type_name:
            for f in t.get("fields") or []:
                args = [
                    {"name": a.get("name", ""), "type": (a.get("type", {}) or {}).get("name") or "Any"}
                    for a in (f.get("args") or [])
                ]
                ret = (f.get("type") or {}).get("name") or "Any"
                summary.mutations.append(GraphQLField(name=f.get("name", ""), args=args, return_type=ret))
        else:
            summary.types.append(t_name)

    return summary


def build_nested_query_probe(query_name: str, field_name: str, depth: int = 15) -> str:
    """Tạo mẫu truy vấn lồng sâu (Recursive Nested Query) để kiểm tra DoS / Resource Exhaustion."""
    inner = field_name
    for _ in range(depth):
        inner = f"{field_name} {{ {inner} }}"
    return f"query DeepProbe {{ {query_name} {{ {inner} }} }}"


def audit_graphql_endpoint(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: float = 6.0,
    insecure: bool = False,
    target_name: str = "api_target",
) -> tuple[list[dict[str, Any]], Optional[GraphQLSchemaSummary]]:
    """Kiểm thử bảo mật toàn diện cho endpoint GraphQL (Introspection leak & Query Depth DoS)."""
    findings: list[dict[str, Any]] = []
    schema_data = fetch_graphql_introspection(url, headers=headers, timeout=timeout, insecure=insecure)
    if not schema_data:
        return findings, None

    # Finding 1: Introspection Schema Enabled in Production
    curl_intro = build_curl_command(
        "POST",
        url,
        headers=headers,
        json_data={"query": "query { __schema { types { name } } }"},
        insecure=insecure,
    )
    findings.append({
        "tool": "graphql_engine",
        "target_app": target_name,
        "vulnerability": "GraphQL Introspection Exposed",
        "vuln_type": "GraphQL Introspection Exposed",
        "endpoint": "/graphql",
        "method": "POST",
        "severity": "medium",
        "confidence": 100,
        "confirmed": True,
        "cwe": "CWE-200",
        "owasp_category": "API8:2023",
        "evidence": "GraphQL endpoint responds to Introspection queries, fully exposing all types, queries, and mutations.",
        "reproduction_curl": curl_intro,
        "reproduction": {
            "method": "POST",
            "url": url,
            "query": "IntrospectionQuery",
            "curl": curl_intro,
        },
        "recommendation": "Vô hiệu hóa Introspection trong môi trường Production để ngăn chặn rà quét cấu trúc CSDL và logic nghiệp vụ.",
    })

    summary = parse_graphql_schema(schema_data)

    # Finding 2: Recursive Query Depth DoS Probe
    if summary.queries:
        sample_q = summary.queries[0].name
        deep_probe = build_nested_query_probe(sample_q, sample_q, depth=12)
        try:
            req_headers = dict(headers or {})
            if "content-type" not in [k.lower() for k in req_headers]:
                req_headers["Content-Type"] = "application/json"

            resp = requests.post(
                url,
                json={"query": deep_probe},
                headers=req_headers,
                timeout=timeout,
                verify=not insecure,
            )
            # Nếu server không chặn với lỗi Max Depth mà xử lý trả về (200 hoặc thực thi đệ quy)
            if resp.status_code == 200 and "Max query depth" not in resp.text and "depth limit" not in resp.text.lower():
                curl_deep = build_curl_command(
                    "POST",
                    url,
                    headers=req_headers,
                    json_data={"query": deep_probe},
                    insecure=insecure,
                )
                findings.append({
                    "tool": "graphql_engine",
                    "target_app": target_name,
                    "vulnerability": "GraphQL Query Depth Limit Missing",
                    "vuln_type": "GraphQL Query Depth Limit Missing",
                    "endpoint": "/graphql",
                    "method": "POST",
                    "severity": "high",
                    "confidence": 90,
                    "confirmed": True,
                    "cwe": "CWE-400",
                    "owasp_category": "API4:2023",
                    "evidence": f"Server processed 12-level nested recursive query without query depth limit rejection (HTTP {resp.status_code}).",
                    "reproduction_curl": curl_deep,
                    "reproduction": {
                        "method": "POST",
                        "url": url,
                        "query": deep_probe,
                        "curl": curl_deep,
                    },
                    "recommendation": "Cài đặt middleware giới hạn độ sâu truy vấn (Query Depth Limiting / Cost Analysis) để ngăn chặn DoS cạn kiệt tài nguyên máy chủ.",
                })
        except Exception:
            pass

    return findings, summary


def build_graphql_fuzz_prompt(summary: GraphQLSchemaSummary) -> str:
    """Tạo prompt chi tiết đưa Schema vào LLM để sinh truy vấn GraphQL tấn công."""
    context = summary.to_llm_context(max_items=30)
    return (
        "Bạn là chuyên gia kiểm thử bảo mật thâm nhập GraphQL API (OWASP API Security Top 10).\n"
        "Dưới đây là cấu trúc Schema GraphQL đã trích xuất qua Introspection:\n"
        f"{context}\n\n"
        "Hãy phân tích và sinh danh sách JSON các truy vấn GraphQL kiểm thử bảo mật (Query/Mutation):\n"
        "1. BOLA / IDOR trên Mutations (thay thế ID đối tượng sang ID khác).\n"
        "2. Injection (SQLi, Command Injection) trong các tham số chuỗi của Query và Mutation.\n"
        "3. GraphQL Batching / Query Alias DoS.\n\n"
        "Định dạng JSON trả về:\n"
        "[\n"
        '  {"name": "test_name", "query": "query/mutation string", "vuln_type": "BOLA", "severity": "high"}\n'
        "]\n"
        "Chỉ trả về JSON thuần trong khối ```json."
    )


def execute_graphql_fuzz_probes(
    url: str,
    payloads: list[dict[str, Any]],
    headers: dict[str, str] | None = None,
    timeout: float = 6.0,
    insecure: bool = False,
    target_name: str = "api_target",
) -> list[dict[str, Any]]:
    """Gửi các truy vấn GraphQL do LLM sinh ra để phát hiện lỗi runtime."""
    findings = []
    req_headers = dict(headers or {})
    if "content-type" not in [k.lower() for k in req_headers]:
        req_headers["Content-Type"] = "application/json"

    for p in payloads:
        q_str = p.get("query")
        if not q_str:
            continue
        try:
            resp = requests.post(
                url,
                json={"query": q_str},
                headers=req_headers,
                timeout=timeout,
                verify=not insecure,
            )
            is_vuln = False
            evidence = ""
            if resp.status_code == 200:
                body = resp.text
                if any(sig in body.lower() for sig in ["sql syntax", "sqlite3.operationalerror", "uid=", "root:", "syntax error", "traceback"]):
                    is_vuln = True
                    evidence = f"GraphQL returned sensitive execution signal in response: {body[:150]}"

            if is_vuln:
                curl_cmd = build_curl_command("POST", url, headers=req_headers, json_data={"query": q_str}, insecure=insecure)
                findings.append({
                    "tool": "graphql_engine",
                    "target_app": target_name,
                    "vulnerability": p.get("vuln_type", "GraphQL Security Finding"),
                    "vuln_type": p.get("vuln_type", "GraphQL Security Finding"),
                    "endpoint": "/graphql",
                    "method": "POST",
                    "severity": p.get("severity", "high"),
                    "confidence": 90,
                    "confirmed": True,
                    "cwe": "CWE-89",
                    "owasp_category": "API10:2023",
                    "evidence": evidence,
                    "reproduction_curl": curl_cmd,
                    "reproduction": {"method": "POST", "url": url, "query": q_str, "curl": curl_cmd},
                })
        except Exception:
            continue

    return findings

