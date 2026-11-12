"""
tests/test_har_parser.py — Unit & Integration tests for HAR Ingestion & Live Seed Corpus.
"""

from __future__ import annotations

import json
from pathlib import Path

from core.analyzer import analyze_file
from core.har_parser import (
    SeedCorpus,
    enrich_endpoints_with_har,
    har_to_endpoints,
    parse_har_file,
)

FIXTURE_HAR = Path(__file__).resolve().parent / "fixtures" / "sample_traffic.har"


def test_parse_har_file() -> None:
    corpus = parse_har_file(FIXTURE_HAR)

    assert isinstance(corpus, SeedCorpus)
    summary = corpus.summary()
    assert summary["unique_endpoints_observed"] >= 3
    assert summary["has_auth"] is True

    # 1. Kiểm tra tham số hạt giống (Seeds)
    assert corpus.get_seed_for_param("citizen_id") == "079201004567"
    assert corpus.get_seed_for_param("username") == "john_doe"
    assert corpus.get_seed_for_param("include_transactions") == "true"
    assert corpus.get_seed_for_param("session_id") == "sess_9988776655"

    # 2. Kiểm tra Body Seed
    body_seed = corpus.get_body_seed("POST", "/api/v1/users/register")
    assert body_seed is not None
    assert body_seed["citizen_id"] == "079201004567"
    assert body_seed["phone"] == "0901234567"

    # 3. Kiểm tra tự động phát hiện Auth Token
    token = corpus.suggest_auth_token()
    assert token == "test-har-jwt-token-xyz"


def test_har_to_endpoints() -> None:
    endpoints = har_to_endpoints(FIXTURE_HAR)
    assert len(endpoints) >= 3

    # Tìm POST endpoint
    post_ep = next((e for e in endpoints if e["method"] == "POST" and "register" in e["path"]), None)
    assert post_ep is not None
    assert post_ep["authentication"] is True
    assert post_ep["jwt"] is True
    assert post_ep["seed_body"] is not None
    assert post_ep["seed_body"]["username"] == "john_doe"

    # Tìm GET endpoint
    get_ep = next((e for e in endpoints if e["method"] == "GET" and "accounts" in e["path"]), None)
    assert get_ep is not None
    param_names = [p["name"] for p in get_ep["parameters"]]
    assert "include_transactions" in param_names


def test_enrich_endpoints_with_har() -> None:
    corpus = parse_har_file(FIXTURE_HAR)

    openapi_mock_endpoints = [
        {
            "method": "POST",
            "path": "/api/v1/users/register",
            "parameters": [
                {"name": "username", "location": "body", "type": "string"},
                {"name": "citizen_id", "location": "body", "type": "string"},
            ],
        },
        {
            "method": "GET",
            "path": "/api/v1/accounts/{id}",
            "parameters": [
                {"name": "id", "location": "path", "type": "string"},
            ],
        },
    ]

    enriched, count = enrich_endpoints_with_har(openapi_mock_endpoints, corpus)
    assert count >= 2
    assert enriched[0].get("seed_body") is not None
    assert enriched[0]["seed_body"]["citizen_id"] == "079201004567"

    # Tham số citizen_id phải được làm giàu sample_value
    citizen_param = next(p for p in enriched[0]["parameters"] if p["name"] == "citizen_id")
    assert citizen_param.get("sample_value") == "079201004567"
    assert citizen_param.get("has_live_seed") is True


def test_analyze_file_auto_har_support() -> None:
    # analyze_file phải tự động nhận diện file .har và chuyển đổi sang endpoints
    endpoints = analyze_file(FIXTURE_HAR)
    assert len(endpoints) >= 3
    methods = {e["method"] for e in endpoints}
    assert "POST" in methods
    assert "GET" in methods
    assert "PUT" in methods
