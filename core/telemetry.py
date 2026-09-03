"""Run-level timing and LLM usage telemetry."""

from __future__ import annotations

from dataclasses import dataclass, field
from time import perf_counter
from typing import Any


@dataclass
class LLMUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    def add(self, usage: dict[str, Any] | None) -> None:
        if not usage:
            return
        self.prompt_tokens += int(usage.get("prompt_tokens", usage.get("promptTokenCount", 0)) or 0)
        self.completion_tokens += int(
            usage.get("completion_tokens", usage.get("candidatesTokenCount", 0)) or 0
        )


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

    def add_usage(self, usage: dict[str, Any] | None) -> None:
        self.usage.add(usage)

    def add_repair(self) -> None:
        self.repair_count += 1

    def record_validation(self, valid: bool) -> None:
        if self.initial_valid is None:
            self.initial_valid = valid
        self.final_valid = valid

    @property
    def total_ms(self) -> float:
        return round((perf_counter() - self._run_started) * 1000, 2)
