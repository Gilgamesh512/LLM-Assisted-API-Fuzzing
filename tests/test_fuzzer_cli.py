from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock, patch

import fuzzer

FIXTURE = Path(__file__).parent / "fixtures" / "sample_openapi.json"

SAMPLE_PAYLOADS = json.dumps([
    {
        "method": "GET",
        "path": "/api/users/{id}",
        "target_parameter": "id",
        "location": "path",
        "vulnerability_type": "BOLA",
        "payload_value": "999",
        "rationale": "IDOR check",
        "expected_indicator": "HTTP 200",
    }
])


class FakeProvider:
    name = "gemini"
    model = "test-model"

    def generate(self, prompt, *, system_prompt=None, context=None):
        return {"reply": SAMPLE_PAYLOADS}

    def repair(self, prompt, *, system_prompt=None, context=None):
        return {"reply": SAMPLE_PAYLOADS}


def test_fuzzer_scan_dry_run(tmp_path: Path):
    with patch("fuzzer.get_provider", return_value=FakeProvider()):
        code = fuzzer.run_full_scan(
            FIXTURE,
            provider="gemini",
            out_dir=tmp_path / "out",
            dry_run=True,
            safe_mode=True,
            mask_data=True,
        )

    assert code == 0
    assert (tmp_path / "out" / "payloads_validated.json").is_file()
    assert (tmp_path / "out" / "payloads_fuzz.json").is_file()
    assert (tmp_path / "out" / "findings_summary.sarif").is_file()
    assert (tmp_path / "out" / "manifest.json").is_file()

    sarif_data = json.loads((tmp_path / "out" / "findings_summary.sarif").read_text(encoding="utf-8"))
    assert sarif_data["version"] == "2.1.0"
