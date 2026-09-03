from __future__ import annotations

import os
from pathlib import Path

import requests
import yaml
from pydantic import BaseModel, Field

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = REPO_ROOT / "config" / "targets.yaml"
SPEC_CACHE_DIR = REPO_ROOT / ".spec_cache"


class TargetConfigError(RuntimeError):
    pass


class AuthConfig(BaseModel):
    type: str = "none"
    login_url: str | None = None
    register_url: str | None = None
    username: str | None = None
    password: str | None = None
    token_env: str | None = None


class TargetConfig(BaseModel):
    name: str
    kind: str
    base_url: str
    spec: str | None = None
    spec_url: str | None = None
    graphql_path: str = "/graphql"
    payload_out: str | None = None
    nuclei_out: str | None = None
    auth: AuthConfig = Field(default_factory=AuthConfig)

    def token(self) -> str | None:
        if self.auth.token_env:
            return os.environ.get(self.auth.token_env)
        return None

    def resolve_spec_path(self) -> str:
        if self.spec:
            p = Path(self.spec)
            if not p.is_absolute():
                p = REPO_ROOT / p
            if not p.is_file():
                raise TargetConfigError(f"Target '{self.name}': không thấy spec {p}")
            return str(p)
        if self.spec_url:
            SPEC_CACHE_DIR.mkdir(parents=True, exist_ok=True)
            cached = SPEC_CACHE_DIR / f"{self.name}_spec.json"
            try:
                resp = requests.get(self.spec_url, timeout=30)
                resp.raise_for_status()
            except requests.RequestException as exc:
                raise TargetConfigError(
                    f"Target '{self.name}': tải spec_url thất bại ({self.spec_url}): {exc}"
                ) from exc
            cached.write_text(resp.text, encoding="utf-8")
            return str(cached)
        raise TargetConfigError(f"Target '{self.name}': phải có 'spec' hoặc 'spec_url'.")

    def resolved_payload_out(self) -> str:
        if self.payload_out:
            return self.payload_out
        if self.kind == "graphql":
            return f"Schemathesis/payload_{self.name}_graphql.json"
        return f"Schemathesis/payload_{self.name}.json"


class TargetsFile(BaseModel):
    targets: dict[str, TargetConfig] = Field(default_factory=dict)
    allowed_targets: list[str] = Field(default_factory=list)


def load_targets(path: str | Path = DEFAULT_CONFIG_PATH) -> TargetsFile:
    p = Path(path)
    if not p.is_file():
        raise TargetConfigError(f"Không thấy file config target: {p}")
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    targets_raw = raw.get("targets", {}) or {}
    for name, cfg in targets_raw.items():
        cfg.setdefault("name", name)
    parsed = {name: TargetConfig.model_validate(cfg) for name, cfg in targets_raw.items()}
    return TargetsFile(targets=parsed, allowed_targets=raw.get("allowed_targets", []) or [])


def get_target(name: str, path: str | Path = DEFAULT_CONFIG_PATH) -> TargetConfig:
    cfg = load_targets(path)
    if cfg.allowed_targets and name not in cfg.allowed_targets:
        raise TargetConfigError(
            f"Target '{name}' không nằm trong allowed_targets {cfg.allowed_targets} — từ chối."
        )
    if name not in cfg.targets:
        raise TargetConfigError(f"Không có target '{name}' trong config. Có: {list(cfg.targets)}")
    return cfg.targets[name]


def list_targets(path: str | Path = DEFAULT_CONFIG_PATH) -> list[str]:
    cfg = load_targets(path)
    if cfg.allowed_targets:
        return [n for n in cfg.targets if n in cfg.allowed_targets]
    return list(cfg.targets)
