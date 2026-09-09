"""Main payload-generation pipeline with runtime provider selection.

This remains a single pipeline structure while allowing runtime provider changes
without mutating project config or branching on provider in the execution path.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from core.analyzer import SpecLoadError, analyze_file  # noqa: E402
from core.manifest import build_manifest, new_run_id, write_manifest  # noqa: E402
from core.prompt_builder import build_payload_generation_prompt, build_repair_prompt  # noqa: E402
from core.providers import get_provider  # noqa: E402
from core.telemetry import RunTelemetry  # noqa: E402
from core.validator import MAX_REPAIR_ATTEMPTS, payloads_to_jsonable, validate_llm_output  # noqa: E402

SKILL_NAME = "api-payload-generator"


def _ensure_utf8_console() -> None:
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (AttributeError, ValueError, OSError):
                pass


class PipelineError(RuntimeError):
    """Raised when the common pipeline fails at any stage."""


def _resolve_provider(provider_name: str | None, model: str | None = None):
    normalized = (provider_name or "").strip().lower()
    if not normalized:
        raise PipelineError(
            "Provider is required. Supported providers: gemini, deepseek."
        )
    try:
        provider_instance = get_provider(normalized, model=model)
    except ValueError as exc:
        raise PipelineError(str(exc)) from exc
    return normalized, provider_instance


def run_b1_analyze(spec_path: str | Path, context_path: Path) -> list[dict[str, Any]]:
    try:
        endpoints = analyze_file(spec_path)
    except SpecLoadError as exc:
        raise PipelineError(f"[B1] Lỗi đọc spec: {exc}") from exc

    context_path.write_text(json.dumps(endpoints, ensure_ascii=False, indent=2), encoding="utf-8")
    return endpoints


def _generate_reply(
    provider_instance,
    prompt: str,
    *,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result = provider_instance.generate(prompt, system_prompt=None, context=context)
    if not isinstance(result, dict):
        raise PipelineError(f"Provider '{provider_instance.name}' did not return a dict payload")
    if "reply" not in result:
        raise PipelineError(f"Provider '{provider_instance.name}' returned no 'reply' field")
    return result


def _repair_reply(
    provider_instance,
    prompt: str,
    *,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result = provider_instance.repair(prompt, system_prompt=None, context=context)
    if not isinstance(result, dict):
        raise PipelineError(f"Provider '{provider_instance.name}' repair result was not a dict")
    if "reply" not in result:
        raise PipelineError(f"Provider '{provider_instance.name}' repair output had no 'reply' field")
    return result


def run_b2_b3_generate_payloads(
    context_path: Path,
    *,
    provider_instance,
    cwd: Path | None = None,
) -> str:
    prompt = build_payload_generation_prompt(context_path)
    result = _generate_reply(
        provider_instance,
        prompt,
        context={"context_path": str(context_path), "cwd": str(cwd or REPO_ROOT)},
    )
    return str(result["reply"])


def run_b2_b3_repair(
    previous_raw: str,
    error_message: str,
    attempt: int,
    *,
    provider_instance,
    cwd: Path | None = None,
) -> str:
    repair_prompt = build_repair_prompt(previous_raw, error_message, attempt)
    result = _repair_reply(provider_instance, repair_prompt, context={"cwd": str(cwd or REPO_ROOT)})
    return str(result["reply"])


def run_pipeline(
    spec_path: str | Path,
    output_path: Path,
    cwd: Path,
    *,
    provider: str | None = None,
    model: str | None = None,
    manifest_path: Path | None = None,
) -> int:
    telemetry = RunTelemetry()
    run_id = new_run_id()
    context_path = cwd / "context.json"
    resolved_provider, provider_instance = _resolve_provider(provider, model)
    model_name = provider_instance.model

    print(f"[pipeline] B1 — Parse '{spec_path}' -> {context_path.name}")
    telemetry.start("analyzer")
    endpoints = run_b1_analyze(spec_path, context_path)
    telemetry.stop("analyzer")
    print(f"[pipeline]   {len(endpoints)} endpoint.")

    print(f"[pipeline] B2/B3 — Generate payloads via {resolved_provider} provider...")
    telemetry.start("llm_generation")
    raw = run_b2_b3_generate_payloads(context_path, provider_instance=provider_instance, cwd=cwd)
    telemetry.stop("llm_generation")

    print("[pipeline] B4 — Validate output...")
    telemetry.start("validation")
    result = validate_llm_output(raw)
    telemetry.record_validation(result.ok)
    telemetry.stop("validation")

    attempt = 1
    while not result.ok and attempt < MAX_REPAIR_ATTEMPTS:
        attempt += 1
        telemetry.add_repair()
        print(f"[pipeline]   Không hợp lệ (lần {attempt - 1}): {result.error_message}")
        print(f"[pipeline]   Thử sinh lại (lần {attempt}/{MAX_REPAIR_ATTEMPTS})...")
        telemetry.start("repair")
        raw = run_b2_b3_repair(
            raw,
            result.error_message or "",
            attempt,
            provider_instance=provider_instance,
            cwd=cwd,
        )
        telemetry.stop("repair")
        telemetry.start("validation")
        result = validate_llm_output(raw, attempt=attempt)
        telemetry.record_validation(result.ok)
        telemetry.stop("validation")

    if not result.ok:
        raise PipelineError(
            f"[B4] Hết {MAX_REPAIR_ATTEMPTS} lần thử, output vẫn không hợp lệ: {result.error_message}\n"
            f"Output cuối cùng:\n{raw}"
        )

    payloads = payloads_to_jsonable(result.payloads or [])
    output_path.write_text(json.dumps(payloads, ensure_ascii=False, indent=2), encoding="utf-8")
    manifest = build_manifest(
        run_id=run_id,
        target_name=Path(spec_path).stem,
        protocol="rest",
        provider=resolved_provider,
        model=model_name,
        telemetry=telemetry,
        payload_count=len(payloads),
        status="completed",
        output_path=output_path,
        context_path=context_path,
    )
    final_manifest_path = manifest_path or cwd / "results" / "runs" / run_id / "manifest.json"
    write_manifest(manifest, final_manifest_path)

    print(f"\n[pipeline] THÀNH CÔNG — {len(payloads)} payload hợp lệ, ghi vào {output_path}")
    print(f"[pipeline] Manifest: {final_manifest_path}")
    by_type: dict[str, int] = {}
    for p in payloads:
        by_type[p["vulnerability_type"]] = by_type.get(p["vulnerability_type"], 0) + 1
    for vuln_type, count in sorted(by_type.items()):
        print(f"[pipeline]   {vuln_type}: {count}")

    return 0


def main(argv: list[str] | None = None) -> int:
    _ensure_utf8_console()
    parser = argparse.ArgumentParser(description="Run the shared API payload generation pipeline with a selected provider.")
    parser.add_argument("spec_path", help="File OpenAPI/Swagger đầu vào (json/yaml)")
    parser.add_argument("-o", "--output", default="payloads_validated.json", help="File JSON output cho Thành viên C")
    parser.add_argument(
        "--provider",
        choices=["gemini", "deepseek"],
        required=True,
        help="LLM provider runtime used by the pipeline",
    )
    parser.add_argument("--model", help="Model name passed to the selected provider runtime")
    parser.add_argument("--manifest", type=Path, help="Đường dẫn manifest output")
    args = parser.parse_args(argv)

    try:
        return run_pipeline(
            args.spec_path,
            Path(args.output),
            cwd=REPO_ROOT,
            provider=args.provider,
            model=args.model,
            manifest_path=args.manifest,
        )
    except PipelineError as exc:
        print(f"[pipeline] Lỗi: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
