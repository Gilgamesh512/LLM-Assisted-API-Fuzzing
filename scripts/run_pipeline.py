"""
scripts/run_pipeline.py — Nối liền toàn bộ Task B thành 1 lệnh duy nhất:

    OpenAPI/Swagger --[B1: analyzer.py]--> context.json
                    --[B2/B3: skill api-payload-generator qua deepcode]--> raw LLM output
                    --[B4: validator.py, tự động repair-loop]--> payload đã validate
                    --> ghi file JSON cuối cùng để bàn giao cho Thành viên C.

Trước đây 3 bước này phải chạy tay từng lệnh (đúng như ví dụ trong SKILL.md) — script
này gói lại thành 1 lệnh, có tự động retry khi LLM trả sai định dạng (dùng đúng
repair_prompt của B4, dừng sau MAX_REPAIR_ATTEMPTS lần theo đúng thiết kế).

Sử dụng:
    python scripts/run_pipeline.py path/to/swagger.yaml
    python scripts/run_pipeline.py path/to/swagger.yaml -o payloads_for_C.json
    python scripts/run_pipeline.py path/to/swagger.yaml --provider deepseek

`--provider` (tuỳ chọn) gọi `switch_ai.py <provider>` trước khi chạy, để chắc chắn
đang dùng đúng provider mong muốn (deepseek/gemini) — bỏ qua nếu đã tự đổi provider từ trước.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import os
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from core.analyzer import SpecLoadError, analyze_file  # noqa: E402
from core.validator import MAX_REPAIR_ATTEMPTS, validate_llm_output, payloads_to_jsonable  # noqa: E402
from core.manifest import build_manifest, new_run_id, write_manifest  # noqa: E402
from core.telemetry import RunTelemetry  # noqa: E402

SKILL_NAME = "api-payload-generator"
DEEPCODE_TIMEOUT_SECONDS = 300

# Đường dẫn cli.js thật bên trong package npm của deepcode, tương đối so với thư mục
# chứa shim `deepcode`/`deepcode.cmd` — đúng cấu trúc mà chính shim đó dùng
# (%dp0%\node_modules\@vegamo\deepcode-cli\dist\cli.js), không phụ thuộc máy nào.
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
    """Lỗi ở bất kỳ bước nào trong pipeline — luôn kèm bước nào gây lỗi."""


def _resolve_deepcode_entry() -> tuple[str, str]:
    """Tìm điểm vào THẬT của `deepcode` (node + cli.js) để gọi trực tiếp qua node.exe,
    không qua cmd.exe (không dùng shell=True) — tránh ký tự shell (&|<>^%...) trong prompt
    (kể cả prompt chứa nguyên văn payload tấn công do LLM tự sinh) bị cmd.exe diễn giải.

    `deepcode`/`deepcode.cmd` chỉ là shim npm trỏ tới
    <thư mục shim>/node_modules/@vegamo/deepcode-cli/dist/cli.js — tìm đúng file đó rồi
    gọi thẳng `node cli.js ...`, argv truyền qua CreateProcess nên không đi qua bất kỳ
    shell nào, ký tự đặc biệt trong prompt luôn được node nhận nguyên văn.
    """
    node_path = shutil.which("node")
    if node_path is None:
        raise PipelineError("Không tìm thấy 'node' trên PATH — cần Node.js để gọi deepcode trực tiếp.")

    shim_path = shutil.which("deepcode.cmd") or shutil.which("deepcode")
    if shim_path is None:
        raise PipelineError(
            "Không tìm thấy lệnh 'deepcode'. Cài đặt/npm link chưa đúng, hoặc PATH chưa có nó."
        )

    cli_js = Path(shim_path).resolve().parent / _DEEPCODE_CLI_JS_RELATIVE
    if not cli_js.is_file():
        raise PipelineError(
            f"Tìm thấy shim 'deepcode' tại {shim_path} nhưng không thấy điểm vào thật ở "
            f"{cli_js} — cấu trúc cài đặt khác chuẩn npm global/`npm link`, cần kiểm tra lại."
        )

    return node_path, str(cli_js)


def run_deepcode(prompt: str, cwd: Path, timeout: int = DEEPCODE_TIMEOUT_SECONDS) -> str:
    """Gọi `deepcode -x -p <prompt>` không tương tác, trả về stdout.

    Gọi thẳng `node <cli.js thật> -x -p <prompt>` với shell=False — KHÔNG qua cmd.exe,
    nên ký tự shell trong prompt (kể cả prompt nhúng nguyên văn payload tấn công do LLM
    tự sinh, ví dụ payload OS command injection chứa `&`/`|`/`` ` ``) không có cách nào
    được diễn giải như lệnh shell, dù prompt truyền qua argv dạng list hay không.
    """
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
        raise PipelineError(
            "Không tìm thấy lệnh 'deepcode'. Cài đặt/npm link chưa đúng, hoặc PATH chưa có nó."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise PipelineError(f"deepcode chạy quá {timeout}s, đã huỷ (có thể do prompt/model chậm).") from exc

    if result.returncode != 0:
        raise PipelineError(f"deepcode thoát với mã lỗi {result.returncode}.\nstderr: {result.stderr[:1000]}")

    return result.stdout


def run_b1_analyze(spec_path: str | Path, context_path: Path) -> list[dict[str, Any]]:
    try:
        endpoints = analyze_file(spec_path)
    except SpecLoadError as exc:
        raise PipelineError(f"[B1] Lỗi đọc spec: {exc}") from exc
    context_path.write_text(json.dumps(endpoints, ensure_ascii=False, indent=2), encoding="utf-8")
    return endpoints


def run_b2_b3_generate_payloads(context_path: Path, cwd: Path) -> str:
    prompt = (
        f"Gọi tool 'skill' với tên '{SKILL_NAME}' ngay bây giờ để nạp hướng dẫn của skill đó. "
        f"Sau đó đọc file {context_path.name} và làm đúng theo hướng dẫn skill vừa nạp để sinh "
        f"payload bảo mật cho các endpoint trong file, trả về JSON array theo đúng schema."
    )
    return run_deepcode(prompt, cwd=cwd)


def run_b2_b3_repair(previous_raw: str, error_message: str, attempt: int, cwd: Path) -> str:
    from core.validator import build_repair_prompt

    repair_prompt = build_repair_prompt(previous_raw, error_message, attempt)
    return run_deepcode(
        f"Gọi tool 'skill' với tên '{SKILL_NAME}' nếu skill đó chưa được nạp trong phiên này. " + repair_prompt,
        cwd=cwd,
    )


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
    model_name = model or os.environ.get("DEEPCODE_MODEL", "unknown")

    print(f"[pipeline] B1 — Parse '{spec_path}' -> {context_path.name}")
    telemetry.start("analyzer")
    endpoints = run_b1_analyze(spec_path, context_path)
    telemetry.stop("analyzer")
    print(f"[pipeline]   {len(endpoints)} endpoint.")

    print("[pipeline] B2/B3 — Gọi skill api-payload-generator qua deepcode...")
    telemetry.start("llm_generation")
    raw = run_b2_b3_generate_payloads(context_path, cwd=cwd)
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
        raw = run_b2_b3_repair(raw, result.error_message or "", attempt, cwd=cwd)
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
        provider=provider,
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
    parser = argparse.ArgumentParser(
        description="Chạy toàn bộ pipeline Task B: analyzer -> skill (deepcode) -> validator, 1 lệnh duy nhất."
    )
    parser.add_argument("spec_path", help="File OpenAPI/Swagger đầu vào (json/yaml)")
    parser.add_argument(
        "-o", "--output", default="payloads_validated.json", help="File JSON output cho Thành viên C"
    )
    parser.add_argument(
        "--provider", choices=["deepseek", "gemini"], help="Đổi provider trước khi chạy (gọi switch_ai.py)"
    )
    parser.add_argument("--model", help="Tên model để ghi vào manifest (không ảnh hưởng DeepCode runtime)")
    parser.add_argument("--manifest", type=Path, help="Đường dẫn manifest output (mặc định results/runs/<run_id>/manifest.json)")
    args = parser.parse_args(argv)

    cwd = REPO_ROOT
    if args.provider:
        import scripts.switch_ai as switch_ai

        try:
            print(switch_ai.switch_to(args.provider))
        except switch_ai.SwitchAIError as exc:
            print(f"[pipeline] Lỗi đổi provider: {exc}", file=sys.stderr)
            return 1

    try:
        return run_pipeline(
            args.spec_path,
            cwd / args.output,
            cwd=cwd,
            provider=args.provider or "unknown",
            model=args.model,
            manifest_path=args.manifest,
        )
    except PipelineError as exc:
        print(f"\n[pipeline] LỖI: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
