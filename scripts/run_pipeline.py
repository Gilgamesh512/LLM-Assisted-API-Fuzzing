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
DEEPCODE_TIMEOUT_SECONDS = 300
_DEEPCODE_CLI_JS_RELATIVE = Path("node_modules") / "@vegamo" / "deepcode-cli" / "dist" / "cli.js"


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


def _resolve_deepcode_entry() -> tuple[str, str]:
    node_path = shutil.which("node")
    if node_path is None:
        raise PipelineError("Không tìm thấy 'node' trên PATH — cần Node.js để gọi deepcode trực tiếp.")
    shim_path = shutil.which("deepcode.cmd") or shutil.which("deepcode")
    if shim_path is None:
        raise PipelineError("Không tìm thấy lệnh 'deepcode'.")
    cli_js = Path(shim_path).resolve().parent / _DEEPCODE_CLI_JS_RELATIVE
    if not cli_js.is_file():
        raise PipelineError(f"Tìm thấy shim 'deepcode' tại {shim_path} nhưng không thấy điểm vào thật ở {cli_js}.")
    return node_path, str(cli_js)


def run_deepcode(prompt: str, cwd: Path, timeout: int = DEEPCODE_TIMEOUT_SECONDS) -> str:
    """Compatibility adapter for older code paths/tests."""
    node_path, cli_js = _resolve_deepcode_entry()
    try:
        result = subprocess.run(
            [node_path, cli_js, "-x", "-p", prompt],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise PipelineError("Không tìm thấy lệnh 'deepcode'.") from exc
    except subprocess.TimeoutExpired as exc:
        raise PipelineError(f"deepcode chạy quá {timeout}s, đã huỷ.") from exc

    if result.returncode != 0:
        raise PipelineError(
            f"deepcode thoát với mã lỗi {result.returncode}.\nstderr: {result.stderr[:1000]}"
        )

    return result.stdout


def run_b1_analyze(spec_path: str | Path, context_path: Path) -> list[dict[str, Any]]:
    try:
        endpoints = analyze_file(spec_path)
    except SpecLoadError as exc:
        raise PipelineError(f"[B1] Lỗi đọc spec: {exc}") from exc

    context_path.write_text(json.dumps(endpoints, ensure_ascii=False, indent=2), encoding="utf-8")
    return endpoints


def _generate_reply(
    provider_name: str,
    prompt: str,
    *,
    model: str | None = None,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if provider_name in {"unknown", "deepcode"}:
        cwd = Path((context or {}).get("cwd", str(REPO_ROOT))) if isinstance(context, dict) and (context or {}).get("cwd") else REPO_ROOT
        raw = run_deepcode(prompt, cwd=cwd)
        return {"reply": raw}

    provider = get_provider(provider_name, model=model)
    result = provider.generate(prompt, system_prompt=None, context=context)
    if not isinstance(result, dict):
        raise PipelineError(f"Provider '{provider_name}' did not return a dict payload")
    if "reply" not in result:
        raise PipelineError(f"Provider '{provider_name}' returned no 'reply' field")
    return result


def _repair_reply(
    provider_name: str,
    prompt: str,
    *,
    model: str | None = None,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if provider_name in {"unknown", "deepcode"}:
        cwd = Path((context or {}).get("cwd", str(REPO_ROOT))) if isinstance(context, dict) and (context or {}).get("cwd") else REPO_ROOT
        raw = run_deepcode(prompt, cwd=cwd)
        return {"reply": raw}

    provider = get_provider(provider_name, model=model)
    result = provider.repair(prompt, system_prompt=None, context=context)
    if not isinstance(result, dict):
        raise PipelineError(f"Provider '{provider_name}' repair result was not a dict")
    if "reply" not in result:
        raise PipelineError(f"Provider '{provider_name}' repair output had no 'reply' field")
    return result


def run_b2_b3_generate_payloads(
    context_path: Path,
    *,
    provider: str = "unknown",
    model: str | None = None,
    cwd: Path | None = None,
) -> str:
    prompt = build_payload_generation_prompt(context_path)
    result = _generate_reply(
        provider,
        prompt,
        model=model,
        context={"context_path": str(context_path), "cwd": str(cwd or REPO_ROOT)},
    )
    return str(result["reply"])


def run_b2_b3_repair(
    previous_raw: str,
    error_message: str,
    attempt: int,
    *,
    provider: str = "unknown",
    model: str | None = None,
    cwd: Path | None = None,
) -> str:
    repair_prompt = build_repair_prompt(previous_raw, error_message, attempt)
    result = _repair_reply(provider, repair_prompt, model=model, context={"cwd": str(cwd or REPO_ROOT)})
    return str(result["reply"])


def run_pipeline(
    spec_path: str | Path,
    output_path: Path,
    cwd: Path,
    *,
    provider: str = "unknown",
    model: str | None = None,
    manifest_path: Path | None = None,
) -> int:
    telemetry = RunTelemetry()
    run_id = new_run_id()
    context_path = cwd / "context.json"
    resolved_provider = (provider or "unknown").strip().lower()
    provider_instance = get_provider(resolved_provider, model=model) if resolved_provider not in {"unknown", "deepcode"} else None
    model_name = model or os.environ.get("MODEL") or (provider_instance.model if provider_instance else "unknown")

    print(f"[pipeline] B1 — Parse '{spec_path}' -> {context_path.name}")
    telemetry.start("analyzer")
    endpoints = run_b1_analyze(spec_path, context_path)
    telemetry.stop("analyzer")
    print(f"[pipeline]   {len(endpoints)} endpoint.")

    print(f"[pipeline] B2/B3 — Generate payloads via {resolved_provider} provider...")
    telemetry.start("llm_generation")
    raw = run_b2_b3_generate_payloads(context_path, provider=resolved_provider, model=model_name, cwd=cwd)
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
        raw = run_b2_b3_repair(raw, result.error_message or "", attempt, provider=resolved_provider, model=model_name, cwd=cwd)
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
        choices=["gemini", "deepseek", "deepcode", "unknown"],
        default="unknown",
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
