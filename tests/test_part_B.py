"""tests/test_part_B.py — Test cho Task B1 (analyzer) & Task B4 (validator)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.analyzer import SpecLoadError, analyze_file  # noqa: E402
from core.validator import (  # noqa: E402
    MAX_REPAIR_ATTEMPTS,
    validate_llm_output,
)

FIXTURE = Path(__file__).parent / "fixtures" / "sample_openapi.json"


# ---------------------------------------------------------------------------
# Task B1 — analyzer.py
# ---------------------------------------------------------------------------


def test_analyze_file_extracts_all_endpoints():
    endpoints = analyze_file(FIXTURE)
    paths = {(e["method"], e["path"]) for e in endpoints}
    assert ("GET", "/api/users/{id}") in paths
    assert ("POST", "/api/login") in paths
    assert ("POST", "/api/users/avatar") in paths


def test_analyze_path_param_detected():
    endpoints = analyze_file(FIXTURE)
    get_user = next(e for e in endpoints if e["path"] == "/api/users/{id}")
    assert get_user["parameters"] == [
        {"name": "id", "type": "integer", "location": "path", "required": True}
    ]
    assert get_user["authentication"] is True
    assert get_user["jwt"] is True
    assert get_user["file_upload"] is False


def test_analyze_body_params_flattened():
    endpoints = analyze_file(FIXTURE)
    login = next(e for e in endpoints if e["path"] == "/api/login")
    names = {p["name"] for p in login["parameters"]}
    assert names == {"username", "password"}
    assert all(p["location"] == "body" for p in login["parameters"])
    assert login["authentication"] is False


def test_analyze_operation_param_overrides_path_level_param():
    """Operation-level parameter phải THẮNG path-level cùng (name, location),
    không được nhân đôi trong output (bug đã sửa trong _merge_path_and_operation_params).
    """
    endpoints = analyze_file(FIXTURE)
    product = next(e for e in endpoints if e["path"] == "/api/products/{id}")
    by_name = {p["name"]: p for p in product["parameters"]}

    # "id" khai báo ở cả path-item (string, optional) và operation (integer,
    # required) -> chỉ 1 bản ghi, và phải là bản operation-level.
    assert len([p for p in product["parameters"] if p["name"] == "id"]) == 1
    assert by_name["id"]["type"] == "integer"
    assert by_name["id"]["required"] is True

    # "verbose" chỉ khai báo ở path-item -> vẫn được kế thừa, đúng 1 bản ghi.
    assert by_name["verbose"]["type"] == "boolean"
    assert by_name["verbose"]["location"] == "query"


def test_analyze_file_upload_detected():
    endpoints = analyze_file(FIXTURE)
    upload = next(e for e in endpoints if e["path"] == "/api/users/avatar")
    assert upload["file_upload"] is True
    assert upload["authentication"] is True


def test_analyze_file_missing_raises():
    with pytest.raises(SpecLoadError):
        analyze_file("does_not_exist.yaml")


def test_analyze_invalid_spec_raises(tmp_path: Path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(SpecLoadError):
        analyze_file(bad)


# ---------------------------------------------------------------------------
# Task B4 — validator.py
# ---------------------------------------------------------------------------

VALID_PAYLOAD = [
    {
        "method": "GET",
        "path": "/api/users/{id}",
        "target_parameter": "id",
        "location": "path",
        "vulnerability_type": "BOLA",
        "payload_value": "2",
        "rationale": "id la so nguyen, doi user khac de kiem tra IDOR.",
        "expected_indicator": "Response tra ve du lieu cua user id=2.",
    }
]


def test_validate_llm_output_valid_json():
    result = validate_llm_output(json.dumps(VALID_PAYLOAD))
    assert result.ok is True
    assert len(result.payloads) == 1
    assert result.payloads[0].vulnerability_type.value == "BOLA"


def test_validate_llm_output_strips_markdown_fence():
    wrapped = f"Đây là kết quả:\n```json\n{json.dumps(VALID_PAYLOAD)}\n```\nHết."
    result = validate_llm_output(wrapped)
    assert result.ok is True
    assert len(result.payloads) == 1


def test_validate_llm_output_accepts_payloads_wrapper():
    result = validate_llm_output(json.dumps({"payloads": VALID_PAYLOAD}))
    assert result.ok is True


def test_validate_llm_output_invalid_json_returns_repair_prompt():
    result = validate_llm_output("khong phai json")
    assert result.ok is False
    assert result.payloads is None
    assert "repair" not in result.error_message.lower()  # error mô tả bằng tiếng Việt/kỹ thuật
    assert result.repair_prompt is not None
    assert "lần thử 1" in result.repair_prompt.lower() or "lan thu 1" in result.repair_prompt.lower()


def test_validate_llm_output_invalid_enum_rejected():
    bad = [dict(VALID_PAYLOAD[0], vulnerability_type="RCE")]  # RCE không nằm trong enum
    result = validate_llm_output(json.dumps(bad))
    assert result.ok is False
    assert "vulnerability_type" in result.error_message


def test_validate_llm_output_missing_field_rejected():
    bad = [{k: v for k, v in VALID_PAYLOAD[0].items() if k != "rationale"}]
    result = validate_llm_output(json.dumps(bad))
    assert result.ok is False
    assert "rationale" in result.error_message


def test_max_repair_attempts_is_reasonable():
    assert MAX_REPAIR_ATTEMPTS == 3  # khớp điều kiện dừng feedback loop của Thành viên C
