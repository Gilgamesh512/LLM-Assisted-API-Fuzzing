"""
tests/test_safety_cleanup.py — Unit tests cho audit headers và cleanup manifest trong core/safety.py.
"""

import json
from pathlib import Path

from core.safety import (
    FUZZER_AUDIT_HEADER,
    FUZZER_RUN_ID_HEADER,
    CleanupTracker,
    get_audit_headers,
)


def test_get_audit_headers():
    headers = get_audit_headers("test-run-456")
    assert headers[FUZZER_AUDIT_HEADER] == "true"
    assert headers[FUZZER_RUN_ID_HEADER] == "test-run-456"


def test_cleanup_tracker_record_and_export(tmp_path: Path):
    tracker = CleanupTracker("run-xyz-789")
    tracker.record_mutation(
        method="POST",
        url="http://test.local/api/v1/users",
        path="/api/v1/users",
        status_code=201,
        identifier="user_999",
        payload={"username": "fuzz_user", "role": "admin"},
    )
    tracker.record_mutation(
        method="PUT",
        url="http://test.local/api/v1/profiles/1",
        path="/api/v1/profiles/1",
        status_code=200,
        identifier="1",
    )

    # 404 should not be recorded
    tracker.record_mutation(
        method="POST",
        url="http://test.local/api/v1/fail",
        path="/api/v1/fail",
        status_code=404,
    )

    manifest_file = tmp_path / "cleanup_manifest.json"
    exported_path = tracker.export_cleanup_manifest(manifest_file)
    assert exported_path is not None
    assert manifest_file.exists()

    data = json.loads(manifest_file.read_text(encoding="utf-8"))
    assert data["run_id"] == "run-xyz-789"
    assert data["total_mutations_recorded"] == 2
    assert len(data["mutations"]) == 2
    assert data["mutations"][0]["method"] == "POST"
    assert data["mutations"][0]["identifier"] == "user_999"
    assert "DELETE /api/v1/users/user_999" in data["mutations"][0]["suggested_cleanup"]
