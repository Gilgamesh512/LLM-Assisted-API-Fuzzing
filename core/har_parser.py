"""
core/har_parser.py — Traffic-Driven HAR Ingestion & Live Seed Corpus Harvester.

Phục vụ giải quyết điểm mù đặc tả tĩnh (Spec-Only Blindness) và hàng rào DTO validation:
- Nạp các file .har (HTTP Archive) xuất từ Chrome DevTools, Burp Suite, Charles Proxy, Postman, hoặc API Gateway.
- Trích xuất tự động các giá trị tham số thực tế (Live Seeds: ID thật, CCCD, Token, Header x-*, Payload DTO hợp lệ).
- Hợp nhất hạt giống sống vào đặc tả OpenAPI hoặc tự động sinh danh sách endpoints trực tiếp từ file HAR.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Các header trình duyệt thông thường không cần coi là custom header của ứng dụng
BROWSER_IGNORE_HEADERS = {
    "host",
    "connection",
    "accept-encoding",
    "accept-language",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-user",
    "upgrade-insecure-requests",
    "user-agent",
    "priority",
}


@dataclass
class HARSeed:
    method: str
    url: str
    path: str
    query_params: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    body: Any = None
    body_json: dict[str, Any] | None = None
    status_code: int | None = None


class SeedCorpus:
    """Kho lưu trữ hạt giống dữ liệu sống (Live Seed Corpus) được trích xuất từ lưu lượng thực tế."""

    def __init__(self) -> None:
        self.param_seeds: dict[str, list[Any]] = {}
        self.request_seeds: dict[tuple[str, str], list[HARSeed]] = {}
        self.auth_headers: dict[str, str] = {}
        self.common_headers: dict[str, str] = {}
        self.discovered_hosts: set[str] = set()

    def add_param_seed(self, param_name: str, value: Any) -> None:
        clean_name = str(param_name).strip()
        if not clean_name or value is None:
            return
        if clean_name not in self.param_seeds:
            self.param_seeds[clean_name] = []
        if value not in self.param_seeds[clean_name]:
            self.param_seeds[clean_name].append(value)

    def get_seed_for_param(self, param_name: str) -> Any | None:
        """Lấy giá trị hạt giống thực tế cho một tham số (tìm theo tên chính xác hoặc không phân biệt hoa thường)."""
        if param_name in self.param_seeds and self.param_seeds[param_name]:
            return self.param_seeds[param_name][0]
        p_lower = param_name.lower()
        for k, vals in self.param_seeds.items():
            if k.lower() == p_lower and vals:
                return vals[0]
        return None

    def get_body_seed(self, method: str, path: str) -> dict[str, Any] | None:
        """Lấy JSON request body thực tế đã được ghi nhận cho cặp method và path."""
        key = (method.upper(), path)
        if key in self.request_seeds:
            for seed in self.request_seeds[key]:
                if seed.body_json:
                    return dict(seed.body_json)
        # Tìm path tương đương (bỏ qua trailing slash)
        for (m, p), seeds in self.request_seeds.items():
            if m == method.upper() and (p.rstrip("/") == path.rstrip("/") or path.startswith(p)):
                for seed in seeds:
                    if seed.body_json:
                        return dict(seed.body_json)
        return None

    def get_template_for_endpoint(self, method: str, path: str) -> HARSeed | None:
        key = (method.upper(), path)
        seeds = self.request_seeds.get(key)
        return seeds[0] if seeds else None

    def suggest_auth_token(self) -> str | None:
        """Tự động phát hiện Bearer token hoặc Auth token từ lưu lượng đã bắt được."""
        for name, val in self.auth_headers.items():
            if "authorization" in name.lower():
                clean_val = val.strip()
                if clean_val.lower().startswith("bearer "):
                    return clean_val[7:].strip()
                return clean_val
            if any(k in name.lower() for k in ("token", "jwt", "api-key")):
                return val.strip()
        return None

    def summary(self) -> dict[str, Any]:
        return {
            "total_params_seeded": len(self.param_seeds),
            "unique_endpoints_observed": len(self.request_seeds),
            "discovered_hosts": list(self.discovered_hosts),
            "has_auth": bool(self.auth_headers),
        }


def _collect_nested_keys(obj: Any, prefix: str = "", out_dict: dict[str, Any] | None = None) -> dict[str, Any]:
    if out_dict is None:
        out_dict = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            full_key = f"{prefix}.{k}" if prefix else str(k)
            out_dict[full_key] = v
            out_dict[str(k)] = v  # Cả tên ngắn lẫn dot-notation
            if isinstance(v, (dict, list)):
                _collect_nested_keys(v, full_key, out_dict)
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            full_key = f"{prefix}[{idx}]"
            out_dict[full_key] = item
            if isinstance(item, (dict, list)):
                _collect_nested_keys(item, full_key, out_dict)
    return out_dict


def parse_har_file(har_source: str | Path | dict[str, Any]) -> SeedCorpus:
    """Đọc và bóc tách file .har thành một SeedCorpus chứa các hạt giống dữ liệu thực tế."""
    if isinstance(har_source, (str, Path)):
        p = Path(har_source)
        if not p.is_file():
            raise FileNotFoundError(f"Không tìm thấy file HAR tại '{har_source}'")
        raw_text = p.read_text(encoding="utf-8-sig")
        har_data = json.loads(raw_text)
    elif isinstance(har_source, dict):
        har_data = har_source
    else:
        raise ValueError(f"Dữ liệu HAR không hợp lệ: {type(har_source)}")

    corpus = SeedCorpus()
    log = har_data.get("log", {})
    entries = log.get("entries", [])

    for entry in entries:
        req = entry.get("request", {})
        if not req:
            continue

        raw_url = str(req.get("url", "")).strip()
        if not raw_url or raw_url.startswith(("data:", "blob:", "javascript:")):
            continue

        parsed = urllib.parse.urlparse(raw_url)
        path = parsed.path or "/"
        method = str(req.get("method", "GET")).upper()

        if parsed.netloc:
            corpus.discovered_hosts.add(parsed.netloc)

        # 1. Trích xuất Headers & Cookies
        headers_dict: dict[str, str] = {}
        for h in req.get("headers", []):
            name = str(h.get("name", "")).strip()
            val = str(h.get("value", "")).strip()
            if not name:
                continue
            name_lower = name.lower()
            if name_lower in BROWSER_IGNORE_HEADERS:
                continue
            headers_dict[name] = val

            # Lưu auth headers riêng
            if any(auth_hint in name_lower for auth_hint in ("authorization", "token", "x-auth", "api-key", "secret")):
                corpus.auth_headers[name] = val
            elif name_lower.startswith("x-") or name_lower in ("content-type", "accept"):
                corpus.common_headers[name] = val

        cookies_dict: dict[str, str] = {}
        for c in req.get("cookies", []):
            c_name = str(c.get("name", "")).strip()
            c_val = str(c.get("value", "")).strip()
            if c_name:
                cookies_dict[c_name] = c_val
                corpus.add_param_seed(c_name, c_val)

        # 2. Trích xuất Query Parameters
        query_dict: dict[str, Any] = {}
        # Từ queryString trong HAR
        for q in req.get("queryString", []):
            q_name = str(q.get("name", "")).strip()
            q_val = str(q.get("value", "")).strip()
            if q_name:
                query_dict[q_name] = q_val
                corpus.add_param_seed(q_name, q_val)

        # Từ URL parse nếu queryString rỗng
        if not query_dict and parsed.query:
            qs = urllib.parse.parse_qs(parsed.query)
            for k, vs in qs.items():
                if vs:
                    query_dict[k] = vs[0]
                    corpus.add_param_seed(k, vs[0])

        # 3. Trích xuất Request Body
        body_val: Any = None
        body_json: dict[str, Any] | None = None
        post_data = req.get("postData")

        if isinstance(post_data, dict):
            mime = str(post_data.get("mimeType", "")).lower()
            raw_text = post_data.get("text", "")
            params = post_data.get("params", [])

            if "json" in mime or (isinstance(raw_text, str) and raw_text.strip().startswith(("{", "["))):
                try:
                    parsed_json = json.loads(raw_text)
                    if isinstance(parsed_json, dict):
                        body_json = parsed_json
                        body_val = parsed_json
                        nested = _collect_nested_keys(parsed_json)
                        for k, v in nested.items():
                            corpus.add_param_seed(k, v)
                    else:
                        body_val = parsed_json
                except Exception:
                    body_val = raw_text
            elif params:
                form_body = {}
                for p in params:
                    p_name = str(p.get("name", "")).strip()
                    p_val = str(p.get("value", "")).strip()
                    if p_name:
                        form_body[p_name] = p_val
                        corpus.add_param_seed(p_name, p_val)
                body_val = form_body
                body_json = form_body
            else:
                body_val = raw_text

        # 4. Trích xuất path variables nếu có số hoặc UUID trong path
        path_parts = [part for part in path.split("/") if part]
        for part in path_parts:
            # Nhận diện UUID hoặc numeric ID
            if part.isdigit():
                corpus.add_param_seed("id", int(part))
            elif re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", part, re.IGNORECASE):
                corpus.add_param_seed("id", part)
                corpus.add_param_seed("uuid", part)

        status_code = entry.get("response", {}).get("status")

        har_seed = HARSeed(
            method=method,
            url=raw_url,
            path=path,
            query_params=query_dict,
            headers=headers_dict,
            cookies=cookies_dict,
            body=body_val,
            body_json=body_json,
            status_code=status_code,
        )

        key = (method, path)
        if key not in corpus.request_seeds:
            corpus.request_seeds[key] = []
        corpus.request_seeds[key].append(har_seed)

    return corpus


def har_to_endpoints(har_source: str | Path | dict[str, Any]) -> list[dict[str, Any]]:
    """Chuyển đổi một file .har thành danh sách các endpoints chuẩn hóa phục vụ Fuzzing trực tiếp."""
    corpus = parse_har_file(har_source)
    endpoints: list[dict[str, Any]] = []

    for (method, path), seeds in corpus.request_seeds.items():
        primary_seed = seeds[0]
        params_list: list[dict[str, Any]] = []

        # Query params
        for q_name, q_val in primary_seed.query_params.items():
            params_list.append({
                "name": q_name,
                "location": "query",
                "type": type(q_val).__name__,
                "required": False,
                "sample_value": q_val,
                "has_live_seed": True,
            })

        # Body params
        if primary_seed.body_json:
            for b_name, b_val in primary_seed.body_json.items():
                params_list.append({
                    "name": b_name,
                    "location": "body",
                    "type": type(b_val).__name__,
                    "required": True,
                    "sample_value": b_val,
                    "has_live_seed": True,
                })

        has_auth = bool(primary_seed.headers.get("Authorization") or primary_seed.headers.get("authorization") or corpus.auth_headers)
        jwt = False
        for auth_v in [primary_seed.headers.get("Authorization"), primary_seed.headers.get("authorization")] + list(corpus.auth_headers.values()):
            if auth_v and "bearer" in str(auth_v).lower():
                jwt = True
                break

        endpoints.append({
            "method": method,
            "path": path,
            "operation_id": f"har_{method.lower()}_{path.replace('/', '_').strip('_')}",
            "tags": ["har_harvested"],
            "parameters": params_list,
            "authentication": has_auth,
            "jwt": jwt,
            "file_upload": False,
            "seed_body": primary_seed.body_json,
            "seed_headers": primary_seed.headers,
        })

    endpoints.sort(key=lambda e: (e["path"], e["method"]))
    return endpoints


def enrich_endpoints_with_har(
    endpoints: list[dict[str, Any]],
    corpus: SeedCorpus,
) -> tuple[list[dict[str, Any]], int]:
    """Bổ sung các hạt giống sống (Live Seeds) từ SeedCorpus vào danh sách endpoints của OpenAPI spec.
    
    Trả về (enriched_endpoints, enriched_count).
    """
    enriched_count = 0

    for ep in endpoints:
        method = str(ep.get("method", "GET")).upper()
        path = str(ep.get("path", ""))

        # 1. Tìm seed body cho endpoint
        body_seed = corpus.get_body_seed(method, path)
        if body_seed:
            ep["seed_body"] = body_seed
            enriched_count += 1

        # 2. Tìm template seed cho headers
        template = corpus.get_template_for_endpoint(method, path)
        if template and template.headers:
            ep["seed_headers"] = template.headers

        # 3. Làm giàu từng tham số với sample_value thực tế
        params = ep.get("parameters", [])
        if isinstance(params, list):
            for param in params:
                if isinstance(param, dict):
                    p_name = param.get("name", "")
                    live_val = corpus.get_seed_for_param(p_name)
                    if live_val is not None:
                        param["sample_value"] = live_val
                        param["has_live_seed"] = True
                        enriched_count += 1

    return endpoints, enriched_count
