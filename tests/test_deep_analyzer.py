from __future__ import annotations

import json
from pathlib import Path

from core.analyzer import _flatten_body_schema, _resolve_ref, analyze


def test_flatten_nested_body_schema():
    nested_schema = {
        "type": "object",
        "properties": {
            "user": {
                "type": "object",
                "properties": {
                    "username": {"type": "string"},
                    "address": {
                        "type": "object",
                        "properties": {
                            "city": {"type": "string"},
                            "zip": {"type": "integer"},
                        },
                    },
                },
                "required": ["username"],
            },
            "tags": {"type": "array", "items": {"type": "string"}},
        },
    }
    params = _flatten_body_schema(nested_schema, {})
    names = [p["name"] for p in params]
    assert "user.username" in names
    assert "user.address.city" in names
    assert "user.address.zip" in names
    assert "tags" in names


def test_flatten_polymorphic_allof_schema():
    schema = {
        "allOf": [
            {
                "type": "object",
                "properties": {"base_id": {"type": "integer"}},
                "required": ["base_id"],
            },
            {
                "type": "object",
                "properties": {"extended_info": {"type": "string"}},
            },
        ]
    }
    params = _flatten_body_schema(schema, {})
    names = [p["name"] for p in params]
    assert "base_id" in names
    assert "extended_info" in names


def test_relative_file_ref_resolution(tmp_path: Path):
    model_file = tmp_path / "models.json"
    model_file.write_text(
        json.dumps({
            "User": {
                "type": "object",
                "properties": {"email": {"type": "string"}},
            }
        }),
        encoding="utf-8",
    )

    spec = {}
    resolved = _resolve_ref(spec, "models.json#/User", base_dir=tmp_path)
    assert resolved.get("type") == "object"
    assert "email" in resolved.get("properties", {})
