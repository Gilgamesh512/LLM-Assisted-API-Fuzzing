import json

from core.evaluation import ExperimentProtocol, Treatment, evaluate_run, schema_hash
from scripts.evaluate_experiment import evaluate_manifest


def test_evaluate_run_separates_valid_executable_unique_and_confirmed():
    payloads = [
        {"method": "GET", "path": "/users/{id}", "target_parameter": "id", "payload_value": "1", "valid": True, "executable": True},
        {"method": "GET", "path": "/users/{id}", "target_parameter": "id", "payload_value": "1", "valid": True, "executable": True},
        {"valid": True, "executable": False},
        {"valid": False, "executable": False},
    ]
    findings = [
        {"target_app": "vampi", "method": "GET", "endpoint": "/users/{id}", "vuln_type": "BOLA", "confirmed": True, "tool": "nuclei", "payload_source": "llm"},
        {"target_app": "vampi", "method": "GET", "endpoint": "/login", "vuln_type": "SQLi", "confirmation_status": "rejected", "tool": "nuclei"},
    ]
    result = evaluate_run(payloads, findings, runtime_seconds=12.5, llm_cost_usd=0.08, llm_tokens=100, known_vulnerabilities=2)
    assert result["valid_payload_rate"] == 0.75
    assert result["executability_rate"] == 0.5
    assert result["unique_payload_rate"] == 0.5
    assert result["confirmed_findings"] == 1
    assert result["false_positive_rate"] == 0.5
    assert result["detection_rate"] == 0.5
    assert result["attribution"]["confirmed_by_payload_source"] == ["llm"]


def test_protocol_is_serializable_and_schema_hash_is_stable():
    protocol = ExperimentProtocol(
        benchmark="research-v1", targets=("vampi", "crapi"), endpoint_set="fixed", timeout_seconds=300,
        runs_per_treatment=3, seed=7, treatments=(Treatment("B0", "schemathesis"),),
    )
    assert protocol.to_dict()["treatments"][0]["name"] == "B0"
    assert schema_hash({"b": 1, "a": [2]}) == schema_hash({"a": [2], "b": 1})


def test_evaluate_manifest_reads_run_artifacts(tmp_path):
    (tmp_path / "payloads.json").write_text(json.dumps([{"valid": True, "executable": True}]), encoding="utf-8")
    (tmp_path / "findings.ndjson").write_text(
        json.dumps({"vuln_type": "BOLA", "confirmed": True, "tool": "schemathesis"}) + "\n",
        encoding="utf-8",
    )
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"known_vulnerabilities": 1, "runs": [{
        "treatment": "B0", "target": "vampi", "payloads": "payloads.json", "findings": "findings.ndjson",
    }]}), encoding="utf-8")

    rows = evaluate_manifest(manifest)

    assert rows[0]["treatment"] == "B0"
    assert rows[0]["confirmed_findings"] == 1
    assert rows[0]["detection_rate"] == 1.0


def test_evaluate_manifest_reads_single_pipeline_manifest(tmp_path):
    payloads = tmp_path / "payloads.json"
    findings = tmp_path / "findings.ndjson"
    payloads.write_text(json.dumps([{"valid": True, "executable": True}]), encoding="utf-8")
    findings.write_text("", encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({
        "run_id": "run-1", "target": {"name": "vampi"},
        "runtime_ms": {"total": 2500}, "generation": {"total_tokens": 12},
        "artifacts": {"payloads": str(payloads), "findings": str(findings)},
    }), encoding="utf-8")

    rows = evaluate_manifest(manifest)

    assert rows[0]["run_id"] == "run-1"
    assert rows[0]["runtime_seconds"] == 2.5
    assert rows[0]["llm_tokens"] == 12