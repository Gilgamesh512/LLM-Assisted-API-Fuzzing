"""tests/test_run_pipeline.py — Test cho scripts/run_pipeline.py.

Mock hoàn toàn run_deepcode() (không gọi mạng/deepcode thật, không phụ thuộc
rate limit của provider nào) để kiểm tra logic: happy path, repair-loop khi
LLM trả sai định dạng, và dừng đúng sau MAX_REPAIR_ATTEMPTS lần thử.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import scripts.run_pipeline as pipeline  # noqa: E402

FIXTURE = Path(__file__).parent / "fixtures" / "sample_openapi.json"

VALID_PAYLOAD_JSON = json.dumps(
    [
        {
            "method": "GET",
            "path": "/api/users/{id}",
            "target_parameter": "id",
            "location": "path",
            "vulnerability_type": "BOLA",
            "payload_value": "2",
            "rationale": "test",
            "expected_indicator": "test",
        }
    ]
)


def test_run_pipeline_happy_path(tmp_path: Path):
    output_path = tmp_path / "out.json"
    with patch.object(pipeline, "run_deepcode", return_value=VALID_PAYLOAD_JSON) as mock_call:
        code = pipeline.run_pipeline(FIXTURE, output_path, cwd=tmp_path)

    assert code == 0
    assert mock_call.call_count == 1  # không cần repair
    written = json.loads(output_path.read_text(encoding="utf-8"))
    assert len(written) == 1
    assert written[0]["vulnerability_type"] == "BOLA"
    assert (tmp_path / "context.json").is_file()  # B1 output cũng được ghi lại


def test_run_pipeline_retries_on_invalid_output_then_succeeds(tmp_path: Path):
    output_path = tmp_path / "out.json"
    manifest_path = tmp_path / "run_manifest.json"
    responses = ["khong phai json hop le", VALID_PAYLOAD_JSON]
    with patch.object(pipeline, "run_deepcode", side_effect=responses) as mock_call:
        code = pipeline.run_pipeline(FIXTURE, output_path, cwd=tmp_path, manifest_path=manifest_path)

    assert code == 0
    assert mock_call.call_count == 2  # 1 lần đầu + 1 lần repair
    assert output_path.is_file()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["generation"]["repair_count"] == 1
    assert manifest["repair"] == {
        "attempts": 1, "initial_valid": False, "final_valid": True, "successful": True
    }


def test_run_pipeline_gives_up_after_max_repair_attempts(tmp_path: Path):
    output_path = tmp_path / "out.json"
    with patch.object(pipeline, "run_deepcode", return_value="khong bao gio hop le"):
        with pytest.raises(pipeline.PipelineError, match="Hết"):
            pipeline.run_pipeline(FIXTURE, output_path, cwd=tmp_path)

    assert not output_path.is_file()  # không ghi output khi thất bại


def test_run_pipeline_propagates_deepcode_process_error(tmp_path: Path):
    output_path = tmp_path / "out.json"
    with patch.object(pipeline, "run_deepcode", side_effect=pipeline.PipelineError("deepcode thoát mã lỗi 1")):
        with pytest.raises(pipeline.PipelineError, match="thoát mã lỗi"):
            pipeline.run_pipeline(FIXTURE, output_path, cwd=tmp_path)
