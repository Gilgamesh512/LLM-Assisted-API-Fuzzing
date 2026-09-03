from __future__ import annotations

import csv
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from core import oracle

REPO_ROOT = Path(__file__).resolve().parent.parent

GenFn = Callable[[Any, Optional[str], Optional[list[dict[str, Any]]], int], Any]
FireFn = Callable[[Any, Any], list[dict[str, Any]]]


@dataclass
class GenerationRecord:
    generation: int
    n_payloads: int
    n_success: int
    n_anomaly: int
    n_miss: int
    exploited: bool


@dataclass
class LoopResult:
    target: str
    status: str
    generations: list[GenerationRecord] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)

    @property
    def total_generations(self) -> int:
        return len(self.generations)


def _write_logs(results_dir: Path, target: str, records: list[GenerationRecord], findings: list[dict[str, Any]]) -> None:
    results_dir.mkdir(parents=True, exist_ok=True)
    runs = results_dir / "feedback_runs.csv"
    with open(runs, "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["target", "generation", "n_payloads", "n_success", "n_anomaly", "n_miss", "exploited"])
        for r in records:
            w.writerow([target, r.generation, r.n_payloads, r.n_success, r.n_anomaly, r.n_miss, r.exploited])
    (results_dir / "feedback_findings.ndjson").write_text(
        "\n".join(json.dumps(f, ensure_ascii=False) for f in findings) + ("\n" if findings else ""),
        encoding="utf-8",
    )


def run_feedback_loop(
    target: Any,
    gen_fn: GenFn,
    fire_fn: FireFn,
    *,
    max_generations: int = 3,
    max_no_progress: int = 3,
    results_dir: Path | str = REPO_ROOT / "results" / "feedback",
    on_generation: Optional[Callable[[GenerationRecord], None]] = None,
) -> LoopResult:
    """Vòng lặp feedback-guided: B sinh payload -> C bắn (Người 1) -> oracle phân tích (Người 2)
    -> phản hồi cho B sinh thế hệ mới. Dừng khi: khai thác thành công, hoặc `max_no_progress`
    thế hệ liên tiếp không có tín hiệu mới, hoặc hết `max_generations`.
    """
    target_name = getattr(target, "name", str(target))
    records: list[GenerationRecord] = []
    findings: list[dict[str, Any]] = []
    feedback: str | None = None
    seeds: list[dict[str, Any]] | None = None
    consecutive_fail = 0
    status = "budget_exhausted"

    for gen in range(max_generations):
        suite = gen_fn(target, feedback, seeds, gen)
        findings = fire_fn(suite, target)
        analysis = oracle.analyze(findings)

        rec = GenerationRecord(
            generation=gen,
            n_payloads=len(findings),
            n_success=len(analysis.successes),
            n_anomaly=len(analysis.anomalies),
            n_miss=len(analysis.misses),
            exploited=analysis.exploited,
        )
        records.append(rec)
        if on_generation:
            on_generation(rec)

        if analysis.exploited:
            status = "success"
            break

        if analysis.has_signal():
            consecutive_fail = 0
        else:
            consecutive_fail += 1
        if consecutive_fail >= max_no_progress:
            status = "no_progress"
            break

        feedback = oracle.summarize_for_llm(analysis)
        seeds = analysis.hits()

    _write_logs(Path(results_dir), target_name, records, findings)
    return LoopResult(target=target_name, status=status, generations=records, findings=findings)
