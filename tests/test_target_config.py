from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from core import target_config as tc


def _write_cfg(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "targets.yaml"
    p.write_text(textwrap.dedent(body), encoding="utf-8")
    return p


def test_load_default_config_has_three_lab_targets():
    cfg = tc.load_targets()
    assert {"vampi", "crapi", "dvga"} <= set(cfg.targets)
    assert cfg.targets["vampi"].base_url == "http://localhost:5002"
    assert cfg.targets["dvga"].kind == "graphql"


def test_allowlist_rejects_unknown_target(tmp_path):
    cfg_path = _write_cfg(
        tmp_path,
        """
        allowed_targets: [vampi]
        targets:
          vampi: {kind: rest, base_url: http://localhost:5002, spec: dataset/vampi_openapi.json}
          evil:  {kind: rest, base_url: http://evil.example, spec: dataset/vampi_openapi.json}
        """,
    )
    assert tc.list_targets(cfg_path) == ["vampi"]
    with pytest.raises(tc.TargetConfigError):
        tc.get_target("evil", cfg_path)


def test_token_read_from_env(tmp_path, monkeypatch):
    cfg_path = _write_cfg(
        tmp_path,
        """
        allowed_targets: [prod]
        targets:
          prod:
            kind: rest
            base_url: https://api.example.com
            spec: dataset/vampi_openapi.json
            auth: {type: static, token_env: PROD_TOKEN}
        """,
    )
    monkeypatch.setenv("PROD_TOKEN", "secret-123")
    assert tc.get_target("prod", cfg_path).token() == "secret-123"


def test_resolve_spec_path_missing_raises(tmp_path):
    cfg_path = _write_cfg(
        tmp_path,
        """
        targets:
          x: {kind: rest, base_url: http://x, spec: does/not/exist.json}
        """,
    )
    with pytest.raises(tc.TargetConfigError):
        tc.get_target("x", cfg_path).resolve_spec_path()


def test_resolved_payload_out_defaults_by_kind(tmp_path):
    cfg_path = _write_cfg(
        tmp_path,
        """
        targets:
          a: {kind: rest, base_url: http://a, spec: dataset/vampi_openapi.json}
          b: {kind: graphql, base_url: http://b, spec: dataset/dvga_schema.json}
        """,
    )
    assert tc.get_target("a", cfg_path).resolved_payload_out().endswith("payload_a.json")
    assert tc.get_target("b", cfg_path).resolved_payload_out().endswith("payload_b_graphql.json")
