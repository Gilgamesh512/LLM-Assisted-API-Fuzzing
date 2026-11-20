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

    def __init__(self, model: str | None = None, base_url: str | None = None):
        super().__init__(model=model)
        self.base_url = base_url or os.environ.get("LOCAL_LLM_URL", "http://localhost:11434/v1")

    def resolve_api_key(self) -> str:
        # Local LLM không bắt buộc key bí mật, dùng dummy key nếu không có
        return os.environ.get(self.api_key_env, "ollama").strip() or "ollama"

    def generate(self, prompt: str, *, system_prompt: str | None = None, context: dict[str, Any] | None = None) -> dict[str, Any]:
        return call_local(
            prompt,
            model=self.model,
            base_url=self.base_url,
            system_prompt=system_prompt,
            api_key=self.resolve_api_key(),
        )


class ResilientProvider(BaseProvider):
    """Provider bao bọc thông minh hỗ trợ tự động chuyển nhượng (Failover / Handover Chain).
    
    Khi provider chính (vd: Gemini, DeepSeek) gặp lỗi hết token (Quota 429),
    thiếu API key hoặc rớt mạng, hệ thống sẽ tự động chuyển nhượng sang provider
    dự phòng (Ollama / Gemma / Qwen hoặc Offline) để phiên quét không bị dừng.
    """

    def __init__(
        self,
        primary: BaseProvider,
        fallbacks: list[BaseProvider] | None = None,
        auto_fallback: bool = True,
    ) -> None:
        super().__init__(model=primary.model)
        self.primary = primary
        self.fallbacks = fallbacks or []
        self.auto_fallback = auto_fallback
        self.active_provider: BaseProvider = primary
        self.name = primary.name

    def generate(self, prompt: str, *, system_prompt: str | None = None, context: dict[str, Any] | None = None) -> dict[str, Any]:
        providers_to_try = [self.active_provider]
        if self.auto_fallback:
            for fb in self.fallbacks:
                if fb != self.active_provider and fb not in providers_to_try:
                    providers_to_try.append(fb)

        last_exc: Exception | None = None
        for idx, prov in enumerate(providers_to_try):
            try:
                res = prov.generate(prompt, system_prompt=system_prompt, context=context)
                if prov != self.active_provider:
                    print(f"\n      [✓] [CHUYỂN NHƯỢNG THÀNH CÔNG] Đã bàn giao tác vụ sang: '{prov.name}' (Model: {prov.model})")
                    self.active_provider = prov
                    self.name = prov.name
                    self.model = prov.model
                return res
            except Exception as exc:
                last_exc = exc
                if idx < len(providers_to_try) - 1:
                    next_p = providers_to_try[idx + 1]
                    print(f"\n      [!] [CẢNH BÁO QUOTA/LỖI API] Provider '{prov.name}' gặp sự cố hoặc hết token: {exc}")
                    print(f"      [*] Đang tự động chuyển giao (Failover) sang AI dự phòng: '{next_p.name}' (Model: {next_p.model})...")
                else:
                    raise last_exc
        raise last_exc or RuntimeError("Tất cả providers trong chuỗi dự phòng đều thất bại.")

    def repair(self, prompt: str, *, system_prompt: str | None = None, context: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            return self.active_provider.repair(prompt, system_prompt=system_prompt, context=context)
        except Exception:
            # Nếu repair trên active_provider gặp lỗi, dùng generate của chuỗi failover
            return self.generate(prompt, system_prompt=system_prompt, context=context)

    def metadata(self) -> dict[str, str]:
        return {
            "provider": self.active_provider.name,
            "model": self.active_provider.model,
            "primary": self.primary.name,
            "failover_active": str(self.active_provider != self.primary),
        }


class OfflineProvider(BaseProvider):
    """Provider offline / CI-CD baseline phục vụ kiểm thử pipeline không cần API key hay mạng."""
    name = "offline"
    default_model = "rule-based-baseline"
    api_key_env = None

    def resolve_api_key(self) -> str:
        return "offline"

    def generate(self, prompt: str, *, system_prompt: str | None = None, context: dict[str, Any] | None = None) -> dict[str, Any]:
        import json
        sample_payloads = [
            {
                "method": "GET",
                "path": "/users",
                "target_parameter": "id",
                "location": "query",
                "vulnerability_type": "SQLi",
                "payload_value": "1' OR '1'='1",
                "rationale": "Offline baseline payload checking SQL injection on query parameter",
                "expected_indicator": "HTTP 500 or SQL syntax error",
            },
            {
                "method": "POST",
                "path": "/users",
                "target_parameter": "role",
                "location": "body",
                "vulnerability_type": "BOLA",
                "payload_value": "admin",
                "rationale": "Offline baseline payload checking privilege escalation",
                "expected_indicator": "HTTP 200 with admin role",
            },
        ]
        return {
            "reply": json.dumps(sample_payloads),
            "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
        }


PROVIDERS: dict[str, type[BaseProvider]] = {
    "gemini": GeminiProvider,
    "deepseek": DeepSeekProvider,
    "local": LocalProvider,
    "ollama": LocalProvider,
    "vllm": LocalProvider,
    "offline": OfflineProvider,
    "mock": OfflineProvider,
}


def get_provider(provider_name: str, model: str | None = None) -> BaseProvider:
    normalized = (provider_name or "").strip().lower()
    if normalized not in PROVIDERS:
        supported = ", ".join(sorted(PROVIDERS))
        raise ValueError(f"Unsupported LLM provider '{provider_name}'. Supported providers: {supported}")
    provider_cls = PROVIDERS[normalized]
    return provider_cls(model=model)


def get_resilient_provider(
    primary_name: str,
    primary_model: str | None = None,
    fallback_name: str | None = None,
    fallback_model: str | None = None,
    local_url: str | None = None,
    auto_fallback: bool = True,
) -> BaseProvider:
    """Tạo bộ Provider có khả năng tự phục hồi & tự động chuyển giao (Smart Resilient Provider)."""
    primary = get_provider(primary_name, model=primary_model)
    fallbacks: list[BaseProvider] = []

    if fallback_name:
        fn_low = fallback_name.lower().strip()
        if fn_low in ("local", "ollama", "vllm"):
            fallbacks.append(LocalProvider(model=fallback_model, base_url=local_url))
        else:
            fallbacks.append(get_provider(fallback_name, model=fallback_model))
    elif auto_fallback and primary_name.lower() in ("gemini", "deepseek"):
        # Mặc định: Nếu dùng Cloud API, chuẩn bị sẵn phương án dự phòng sang Local LLM (Ollama) và Offline
        fallbacks.append(LocalProvider(model=fallback_model or "qwen2.5-coder", base_url=local_url))
        fallbacks.append(OfflineProvider())

    if not fallbacks:
        return primary

    return ResilientProvider(primary, fallbacks=fallbacks, auto_fallback=True)


__all__ = [
    "LLMProvider",
    "BaseProvider",
    "GeminiProvider",
    "DeepSeekProvider",
    "LocalProvider",
    "OfflineProvider",
    "ResilientProvider",
    "PROVIDERS",
    "get_provider",
    "get_resilient_provider",
]
