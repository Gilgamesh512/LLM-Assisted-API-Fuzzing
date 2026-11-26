from __future__ import annotations

import json
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import requests

import fuzzer
import web_ui
from core.analyzer import analyze, _convert_postman_to_openapi
from core.notifier import send_webhook_notification
from core.remediation import export_remediations_markdown, generate_remediation
from core.validator import extract_json_from_text


def test_analyzer_openapi3_without_components_preserves_request_body():
    postman_data = {
        "info": {"name": "Orders API"},
        "item": [
            {
                "name": "Create Order",
                "request": {
                    "method": "POST",
                    "url": "https://api.example.com/v1/orders",
                    "body": {"mode": "raw", "raw": '{"amount": 100, "currency": "VND"}'},
                },
            }
        ],
    }
    spec = _convert_postman_to_openapi(postman_data)
    assert "components" not in spec
    endpoints = analyze(spec)
    assert len(endpoints) == 1
    param_names = {p["name"] for p in endpoints[0]["parameters"]}
    assert {"amount", "currency"}.issubset(param_names)


def test_extract_json_from_text_handles_markdown_and_raw():
    fenced = 'Here you go:\n```json\n[{"name": "probe", "query": "{ users { id } }"}]\n```'
    parsed = extract_json_from_text(fenced)
    assert isinstance(parsed, list)
    assert parsed[0]["name"] == "probe"
    assert extract_json_from_text("not json at all") is None


def test_graphql_llm_probes_executed_with_dict_provider_reply(tmp_path: Path):
    spec_file = tmp_path / "spec.json"
    spec_file.write_text(
        json.dumps({
            "openapi": "3.0.0",
            "info": {"title": "GQL", "version": "1.0"},
            "paths": {"/graphql": {"post": {"parameters": [{"name": "query", "in": "query", "schema": {"type": "string"}}]}}},
        }),
        encoding="utf-8",
    )

    rest_reply = json.dumps([{
        "method": "POST",
        "path": "/graphql",
        "target_parameter": "query",
        "location": "query",
        "vulnerability_type": "SQLi",
        "payload_value": "' OR 1=1--",
        "rationale": "sqli probe",
        "expected_indicator": "HTTP 500",
    }])
    gql_reply = json.dumps([{
        "name": "gql_sqli",
        "query": "query { user(id: \"1'\") { name } }",
        "vuln_type": "SQLi",
        "severity": "high",
    }])

    mock_provider = MagicMock()
    mock_provider.name = "gemini"
    mock_provider.model = "gemini-test"
    mock_provider.generate.side_effect = [
        {"reply": rest_reply, "usage": {}},
        {"reply": gql_reply, "usage": {}},
    ]

    introspection_resp = MagicMock()
    introspection_resp.status_code = 200
    introspection_resp.text = '{"data": {"__schema": {"queryType": {"name": "Query"}, "mutationType": null, "types": [{"name": "Query", "fields": [{"name": "user", "args": [{"name": "id", "type": {"name": "String"}}], "type": {"name": "User"}}]}]}}}'
    introspection_resp.json.return_value = json.loads(introspection_resp.text)

    depth_resp = MagicMock()
    depth_resp.status_code = 400
    depth_resp.text = "Max query depth exceeded"

    sqli_gql_resp = MagicMock()
    sqli_gql_resp.status_code = 200
    sqli_gql_resp.text = "sqlite3.operationalerror: unrecognized token"

    rest_resp = MagicMock()
    rest_resp.status_code = 200
    rest_resp.text = '{"ok": true}'
    rest_resp.headers = {}

    fake_session = MagicMock()
    fake_session.request.return_value = rest_resp

    with patch("fuzzer.get_provider", return_value=mock_provider), \
         patch("requests.Session", return_value=fake_session), \
         patch("core.graphql_engine.requests.post", side_effect=[introspection_resp, depth_resp, sqli_gql_resp]):
        fuzzer.run_full_scan(
            spec_file,
            target_url="http://gql.local/graphql",
            provider="local",
            out_dir=tmp_path / "out",
            graphql=True,
            concurrency=1,
            remediation=True,
            pr_comment=True,
        )

    ndjson_lines = (tmp_path / "out" / "findings_summary.ndjson").read_text(encoding="utf-8").splitlines()
    findings = [json.loads(line) for line in ndjson_lines if line.strip()]
    assert any(f.get("tool") == "graphql_engine" and "sqlite3" in f.get("evidence", "").lower() for f in findings)


def test_auto_cleanup_extracts_id_and_passes_auth_headers(tmp_path: Path):
    spec_file = tmp_path / "spec.json"
    spec_file.write_text(
        json.dumps({
            "openapi": "3.0.0",
            "info": {"title": "Users", "version": "1.0"},
            "paths": {"/users": {"post": {"requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {"name": {"type": "string"}}}}}}}}},
        }),
        encoding="utf-8",
    )

    mock_provider = MagicMock()
    mock_provider.name = "local"
    mock_provider.model = "local-test"
    mock_provider.generate.return_value = {
        "reply": json.dumps([{
            "method": "POST",
            "path": "/users",
            "target_parameter": "name",
            "location": "body",
            "vulnerability_type": "Other",
            "payload_value": "alice",
            "rationale": "create resource",
            "expected_indicator": "HTTP 201",
        }])
    }

    post_resp = MagicMock()
    post_resp.status_code = 201
    post_resp.text = '{"id": "usr-42", "name": "alice"}'
    post_resp.json.return_value = {"id": "usr-42", "name": "alice"}
    post_resp.headers = {}

    real_session = requests.Session()
    with patch("fuzzer.get_provider", return_value=mock_provider), \
         patch.object(real_session, "request", return_value=post_resp), \
         patch("requests.Session", return_value=real_session), \
         patch("requests.delete") as mock_delete:
        del_resp = MagicMock()
        del_resp.status_code = 204
        mock_delete.return_value = del_resp

        fuzzer.run_full_scan(
            spec_file,
            target_url="http://users.local",
            provider="local",
            auth_token="secret-jwt-token",
            out_dir=tmp_path / "out",
            auto_cleanup=True,
            concurrency=1,
            remediation=True,
            pr_comment=True,
        )

    manifest = json.loads((tmp_path / "out" / "cleanup_manifest.json").read_text(encoding="utf-8"))
    assert manifest["mutations"][0]["identifier"] == "usr-42"
    mock_delete.assert_called_once()
    call_args, call_kwargs = mock_delete.call_args
    assert call_args[0] == "http://users.local/users/usr-42"
    assert call_kwargs["headers"]["Authorization"] == "Bearer secret-jwt-token"

    # Checksums and HTML report include post-generated files
    checksum_text = (tmp_path / "out" / "checksums.sha256").read_text(encoding="utf-8")
    assert "poc_collection.json" in checksum_text
    assert "pr_comment.md" in checksum_text
    html_text = (tmp_path / "out" / "report.html").read_text(encoding="utf-8")
    assert "poc_collection.json" in html_text
    assert "pr_comment.md" in html_text


def test_remediation_mass_assignment_classification_and_language_fence():
    rem = generate_remediation(
        {"endpoint": "/api/profile", "method": "PUT", "target_param": "role", "vuln_type": "Mass Assignment", "severity": "critical"},
        framework="express",
    )
    assert rem["category"] == "mass_assignment"
    md = export_remediations_markdown([rem], target_name="ShopAPI")
    assert "```javascript" in md
    assert "```python" not in md


def test_notifier_supports_target_name_fallback():
    captured = {}

    def fake_urlopen(req, timeout=10.0):
        captured["body"] = json.loads(req.data.decode("utf-8"))
        resp = MagicMock()
        resp.status = 200
        resp.__enter__ = lambda s: s
        resp.__exit__ = lambda s, *a: None
        return resp

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        ok = send_webhook_notification("https://hooks.example.com/test", {"target_name": "CoreBankingSvc", "total_findings": 1})
    assert ok is True
    assert captured["body"]["target_app"] == "CoreBankingSvc"


def test_web_ui_summary_counts_critical_from_ndjson_and_form_input_class(tmp_path: Path):
    out_dir = tmp_path / "res"
    out_dir.mkdir()
    (out_dir / "findings_summary.ndjson").write_text(
        json.dumps({"severity": "critical", "vuln_type": "BOLA"}) + "\n"
        + json.dumps({"severity": "high", "vuln_type": "SQLi"}) + "\n",
        encoding="utf-8",
    )
    (out_dir / "report.html").write_text("<html></html>", encoding="utf-8")

    with patch("web_ui.run_full_scan", return_value=1):
        web_ui.scan_abort_event.clear()
        web_ui._background_scan_worker({"spec_path": "x.json", "out_dir": str(out_dir)})

    assert web_ui.scan_state["summary"]["critical"] == 1
    assert web_ui.scan_state["summary"]["high"] == 1

    client = web_ui.app.test_client()
    html = client.get("/").data.decode("utf-8")
    assert 'id="fallbackModel" class="form-input"' in html


def test_fuzzer_auto_fallback_works_without_explicit_fallback_flag(tmp_path: Path):
    spec_file = tmp_path / "spec.json"
    spec_file.write_text(
        json.dumps({
            "openapi": "3.0.0",
            "info": {"title": "Test", "version": "1.0"},
            "paths": {"/items": {"get": {"parameters": [{"name": "q", "in": "query", "schema": {"type": "string"}}]}}},
        }),
        encoding="utf-8",
    )

    broken_gemini = MagicMock()
    broken_gemini.name = "gemini"
    broken_gemini.model = "gemini-3.7-flash"
    broken_gemini.generate.side_effect = RuntimeError("Quota 429 exceeded")

    with patch("fuzzer.get_provider", return_value=broken_gemini), \
         patch("core.providers.LocalProvider.generate", side_effect=RuntimeError("no ollama")):
        code = fuzzer.run_full_scan(
            spec_file,
            provider="gemini",
            out_dir=tmp_path / "out_fb",
            dry_run=True,
        )

    assert code == 0
    assert (tmp_path / "out_fb" / "payloads_validated.json").is_file()


def test_concurrent_fuzzing_uses_distinct_thread_local_sessions(tmp_path: Path):
    spec_file = tmp_path / "spec.json"
    spec_file.write_text(
        json.dumps({
            "openapi": "3.0.0",
            "info": {"title": "Test", "version": "1.0"},
            "paths": {"/items": {"get": {"parameters": [{"name": "q", "in": "query", "schema": {"type": "string"}}]}}},
        }),
        encoding="utf-8",
    )

    payloads = [
        {
            "method": "GET",
            "path": "/items",
            "target_parameter": "q",
            "location": "query",
            "vulnerability_type": "SQLi",
            "payload_value": f"p{i}",
            "rationale": "test",
            "expected_indicator": "HTTP 500",
        }
        for i in range(6)
    ]
    mock_provider = MagicMock()
    mock_provider.name = "local"
    mock_provider.model = "local-test"
    mock_provider.generate.return_value = {"reply": json.dumps(payloads)}

    barrier = threading.Barrier(2)
    entered = 0
    seen_by_thread: dict[int, set[int]] = {}
    all_session_ids: set[int] = set()
    lock = threading.Lock()

    def fake_request(self, method, url, **kwargs):
        nonlocal entered
        with lock:
            entered += 1
            my_idx = entered
            tid = threading.get_ident()
            seen_by_thread.setdefault(tid, set()).add(id(self))
            all_session_ids.add(id(self))
        if my_idx <= 2:
            barrier.wait(timeout=3.0)
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "ok"
        resp.headers = {}
        return resp

    with patch("fuzzer.get_provider", return_value=mock_provider), \
         patch.object(requests.Session, "request", fake_request):
        code = fuzzer.run_full_scan(
            spec_file,
            target_url="http://items.local",
            provider="local",
            out_dir=tmp_path / "out_threads",
            concurrency=3,
        )

    assert code == 0
    assert len(seen_by_thread) >= 2
    assert len(all_session_ids) == len(seen_by_thread)
