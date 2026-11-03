from __future__ import annotations

import os
from abc import ABC, abstractmethod
from typing import Any, Protocol

from core.deepseek_client import call_deepseek
from core.gemini_client import call_gemini
from core.local_client import call_local


class LLMProvider(Protocol):
    name: str
    default_model: str
    model: str

    def generate(self, prompt: str, *, system_prompt: str | None = None, context: dict[str, Any] | None = None) -> dict[str, Any]:
        ...

    def repair(self, prompt: str, *, system_prompt: str | None = None, context: dict[str, Any] | None = None) -> dict[str, Any]:
        ...

    def metadata(self) -> dict[str, str]:
        ...


class BaseProvider(ABC):
    name = "base"
    default_model = "unknown"
    api_key_env: str | None = None

    def __init__(self, model: str | None = None):
        self.model = model or self.default_model

    def resolve_api_key(self) -> str:
        if self.api_key_env is None:
            return ""
        api_key = os.environ.get(self.api_key_env, "").strip()
        if api_key:
            return api_key
        title = self.name.title()
        raise RuntimeError(f"{title} provider selected but {self.api_key_env} is not configured.")

    @abstractmethod
    def generate(self, prompt: str, *, system_prompt: str | None = None, context: dict[str, Any] | None = None) -> dict[str, Any]:
        raise NotImplementedError

    def repair(self, prompt: str, *, system_prompt: str | None = None, context: dict[str, Any] | None = None) -> dict[str, Any]:
        return self.generate(prompt, system_prompt=system_prompt, context=context)

    def metadata(self) -> dict[str, str]:
        return {"provider": self.name, "model": self.model}


class GeminiProvider(BaseProvider):
    name = "gemini"
    default_model = "gemini-3.7-flash"
    api_key_env = "GEMINI_API_KEY"

    def generate(self, prompt: str, *, system_prompt: str | None = None, context: dict[str, Any] | None = None) -> dict[str, Any]:
        self.resolve_api_key()
        return call_gemini(prompt, model=self.model, system_prompt=system_prompt, api_key=os.environ.get(self.api_key_env))


class DeepSeekProvider(BaseProvider):
    name = "deepseek"
    default_model = "deepseek-chat"
    api_key_env = "DEEPSEEK_API_KEY"

    def generate(self, prompt: str, *, system_prompt: str | None = None, context: dict[str, Any] | None = None) -> dict[str, Any]:
        self.resolve_api_key()
        return call_deepseek(prompt, model=self.model, system_prompt=system_prompt, api_key=os.environ.get(self.api_key_env))


class LocalProvider(BaseProvider):
    """Provider phục vụ chạy mô hình Offline/On-premise (Ollama, vLLM, Azure OpenAI Private)."""
    name = "local"
    default_model = "qwen2.5-coder"
    api_key_env = "LOCAL_LLM_API_KEY"

    def resolve_api_key(self) -> str:
        # Local LLM không bắt buộc key bí mật, dùng dummy key nếu không có
        return os.environ.get(self.api_key_env, "ollama").strip() or "ollama"

    def generate(self, prompt: str, *, system_prompt: str | None = None, context: dict[str, Any] | None = None) -> dict[str, Any]:
        base_url = os.environ.get("LOCAL_LLM_URL", "http://localhost:11434/v1")
        return call_local(
            prompt,
            model=self.model,
            base_url=base_url,
            system_prompt=system_prompt,
            api_key=self.resolve_api_key(),
        )


PROVIDERS: dict[str, type[BaseProvider]] = {
    "gemini": GeminiProvider,
    "deepseek": DeepSeekProvider,
    "local": LocalProvider,
    "ollama": LocalProvider,
    "vllm": LocalProvider,
}


def get_provider(provider_name: str, model: str | None = None) -> BaseProvider:
    normalized = (provider_name or "").strip().lower()
    if normalized not in PROVIDERS:
        supported = ", ".join(sorted(PROVIDERS))
        raise ValueError(f"Unsupported LLM provider '{provider_name}'. Supported providers: {supported}")
    provider_cls = PROVIDERS[normalized]
    return provider_cls(model=model)


__all__ = [
    "LLMProvider",
    "BaseProvider",
    "GeminiProvider",
    "DeepSeekProvider",
    "LocalProvider",
    "PROVIDERS",
    "get_provider",
]
