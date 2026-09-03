

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode

import yaml

from .schemas import Matchers, Case

_PLACEHOLDER_RE = re.compile(r"\{(\w+)\}")


def template_id(tc: Case) -> str:
    """ID template dùng để map ngược finding <-> test case."""
    return f"{tc.id}-{tc.vuln_type}"


def _fill_path_params(endpoint: str, path_params: dict[str, Any]) -> str:
    """Thay ``{name}`` trong endpoint bằng giá trị đã URL-encode.

    Placeholder không có giá trị tương ứng được giữ nguyên (vd ``{{BaseURL}}``
    của Nuclei sẽ không bị đụng vì ta chỉ match ``{name}`` đơn).
    """

    def _sub(match: re.Match[str]) -> str:
        key = match.group(1)
        if key in path_params:
            return quote(str(path_params[key]), safe="")
        return match.group(0)

    return _PLACEHOLDER_RE.sub(_sub, endpoint)


def build_path(tc: Case) -> str:
    """Ghép path đầy đủ cho Nuclei: ``{{BaseURL}}`` + endpoint + query string."""
    path = _fill_path_params(tc.endpoint, tc.path_params)
    if tc.query_params:
        query = urlencode({k: str(v) for k, v in tc.query_params.items()})
        sep = "&" if "?" in path else "?"
        path = f"{path}{sep}{query}"
    return f"{{{{BaseURL}}}}{path}"


def _build_matchers(m: Matchers) -> list[dict[str, Any]]:
    """Chuyển ``Matchers`` (schema B) thành list matcher của Nuclei."""
    out: list[dict[str, Any]] = []
    if m.status:
        out.append({"type": "status", "status": list(m.status)})
    if m.words:
        out.append(
            {
                "type": "word",
                "part": "body",
                "words": list(m.words),
                "condition": "or",
            }
        )
    if m.regex:
        out.append({"type": "regex", "part": "body", "regex": list(m.regex)})
    if m.dsl:
        out.append({"type": "dsl", "dsl": list(m.dsl)})
    return out


def build_template(tc: Case, variables: dict[str, str] | None = None) -> dict[str, Any]:
    """Tạo dict template Nuclei cho 1 test case.

    Trả về dict (dễ test/serialize); ghi ra file bằng ``dump_template``.
    """
    matcher_list = _build_matchers(tc.matchers)

    http_block: dict[str, Any] = {
        "method": tc.method,
        "path": [build_path(tc)],
    }
    if tc.headers:
        http_block["headers"] = dict(tc.headers)
    if tc.body is not None:
        http_block["body"] = tc.body if isinstance(tc.body, str) else yaml.safe_dump(
            tc.body, default_flow_style=True
        ).strip()

    if matcher_list:
        http_block["matchers-condition"] = tc.matchers.condition
        http_block["matchers"] = matcher_list

    template: dict[str, Any] = {
        "id": template_id(tc),
        "info": {
            "name": f"LLM-generated {tc.vuln_type} test ({tc.id})",
            "author": "research-team",
            "severity": tc.severity,
            "tags": f"llm,api,{tc.vuln_type}",
        },
        "http": [http_block],
    }

    if variables:
        template["variables"] = dict(variables)

    return template


def dump_template(tc: Case, variables: dict[str, str] | None = None) -> str:
    """Serialize template ra YAML string bằng safe_dump."""
    return yaml.safe_dump(
        build_template(tc, variables),
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
    )


def write_templates(
    test_cases: list[Case],
    out_dir: str | Path,
    variables: dict[str, str] | None = None,
) -> list[Path]:
    """Ghi từng test case ra 1 file ``.yaml`` trong ``out_dir``.

    Trả về danh sách đường dẫn file đã ghi. Test case không có matcher nào sẽ bị
    bỏ qua (không thể xác định match) — caller tự quyết cách log.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for tc in test_cases:
        if tc.matchers.is_empty():
            continue
        path = out_dir / f"{template_id(tc)}.yaml"
        path.write_text(dump_template(tc, variables), encoding="utf-8")
        written.append(path)
    return written
