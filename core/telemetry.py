"""Run-level timing and LLM usage telemetry."""

from __future__ import annotations

from dataclasses import dataclass, field
from time import perf_counter
from typing import Any


@dataclass
class LLMUsage:
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    available: bool = False
    source: str = "provider"

    @property
    def total_tokens(self) -> int | None:
        if self.prompt_tokens is None or self.completion_tokens is None:
            return None
        return self.prompt_tokens + self.completion_tokens

    @staticmethod
    def _normalize_usage(usage: dict[str, Any] | None) -> dict[str, int | None] | None:
        if not isinstance(usage, dict):
            return None

        prompt = (
            usage.get("prompt_tokens")
            if usage.get("prompt_tokens") is not None
            else usage.get("promptTokenCount")
            if usage.get("promptTokenCount") is not None
            else usage.get("input_tokens")
        )
        completion = (
            usage.get("completion_tokens")
            if usage.get("completion_tokens") is not None
            else usage.get("completionTokenCount")
            if usage.get("completionTokenCount") is not None
            else usage.get("output_tokens")
            if usage.get("output_tokens") is not None
            else usage.get("candidatesTokenCount")
        )
        total = usage.get("total_tokens")
        if total is None and prompt is not None and completion is not None:
            total = int(prompt) + int(completion)
        if prompt is None and total is not None and completion is not None:
            prompt = int(total) - int(completion)
        if completion is None and total is not None and prompt is not None:
            completion = int(total) - int(prompt)

        return {
            "prompt_tokens": int(prompt) if prompt is not None else None,
            "completion_tokens": int(completion) if completion is not None else None,
            "total_tokens": int(total) if total is not None else None,
        }

    def add(self, usage: dict[str, Any] | None, source: str = "provider") -> None:
        normalized = self._normalize_usage(usage)
        if normalized is None:
            return
        prompt = normalized["prompt_tokens"]
        completion = normalized["completion_tokens"]
        if prompt is None and completion is None and normalized["total_tokens"] is not None:
            return
        if prompt is None or completion is None:
            self.prompt_tokens = self.prompt_tokens if self.prompt_tokens is not None else prompt
            self.completion_tokens = self.completion_tokens if self.completion_tokens is not None else completion
            self.available = prompt is not None or completion is not None
            self.source = source
            return
        self.prompt_tokens = (self.prompt_tokens or 0) + int(prompt)
        self.completion_tokens = (self.completion_tokens or 0) + int(completion)
        self.available = True
        self.source = source


@dataclass
class RunTelemetry:
    """Accumulates stage timings and generation metadata without knowing evaluator format."""

    usage: LLMUsage = field(default_factory=LLMUsage)
    repair_count: int = 0
    initial_valid: bool | None = None
    final_valid: bool | None = None
    stages_ms: dict[str, float] = field(default_factory=dict)
    _started: dict[str, float] = field(default_factory=dict, repr=False)
    _run_started: float = field(default_factory=perf_counter, repr=False)

    def start(self, stage: str) -> None:
        self._started[stage] = perf_counter()

    def stop(self, stage: str) -> float:
        started = self._started.pop(stage, None)
        elapsed = 0.0 if started is None else round((perf_counter() - started) * 1000, 2)
        self.stages_ms[stage] = round(self.stages_ms.get(stage, 0.0) + elapsed, 2)
        return elapsed

    def add_usage(self, usage: dict[str, Any] | None, source: str = "provider") -> None:
        self.usage.add(usage, source)

    def add_repair(self) -> None:
        self.repair_count += 1

    def record_validation(self, valid: bool) -> None:
        if self.initial_valid is None:
            self.initial_valid = valid
        self.final_valid = valid

    @property
    def total_ms(self) -> float:
        return round((perf_counter() - self._run_started) * 1000, 2)
