#!/usr/bin/env python3
"""
fuzzer.py — Điểm nhập duy nhất (Single-Command Entrypoint) cho toàn bộ hệ thống LLM-Assisted API Fuzzing.

Vận hành toàn bộ quy trình chỉ trong 1 lệnh duy nhất:
  Parse Spec -> Mask Data -> LLM Generation -> Guardrails Repair -> Safe Mode Filter ->
  Fuzzing Execution (Concurrent & Auth-aware) -> Enhanced Oracle -> OASIS SARIF / CSV Reporting -> Security Gate.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import json
import sys
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT))

from core.analyzer import analyze_file  # noqa: E402
from core.auth_manager import TokenManager  # noqa: E402
from core.baseline import security_gate  # noqa: E402
from core.manifest import build_manifest, new_run_id, write_manifest  # noqa: E402
from core.oracle import Signal, analyze as oracle_analyze  # noqa: E402
from core.prompt_builder import build_payload_generation_prompt, build_repair_prompt  # noqa: E402
from core.providers import get_provider  # noqa: E402
from core.safety import filter_safe_payloads  # noqa: E402
from core.sanitizer import mask_spec_data, unmask_object  # noqa: E402
from core.sarif import export_sarif_file  # noqa: E402
from core.telemetry import RunTelemetry  # noqa: E402
from core.validator import (  # noqa: E402
    MAX_REPAIR_ATTEMPTS,
    convert_attack_payload_to_fuzz,
    payloads_to_jsonable,
    validate_llm_output,
)


def _ensure_utf8() -> None:
    for s in ("stdout", "stderr"):
        stream = getattr(sys, s, None)
        if stream and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


def _build_body_payload(param: str, val: Any) -> dict[str, Any]:
    """Tạo payload cho body, hỗ trợ cả dot-notation nested object (vd: user.profile.name)."""
    if "." in param:
        root: dict[str, Any] = {}
        curr = root
        parts = param.split(".")
        for part in parts[:-1]:
            curr[part] = {}
            curr = curr[part]
        curr[parts[-1]] = val
        return root
    return {param: val}


def _send_fuzz_request(
    session: Any,
    base_url: str,
    item: dict[str, Any],
    timeout: float = 8.0,
    token_mgr: TokenManager | None = None,
) -> dict[str, Any]:
    """Gửi một request fuzzing và trả về dict kết quả chuẩn hóa."""
    method = item["method"]
    endpoint = item["endpoint"]
    param = item["target_param"]
    loc = str(item.get("param_location", "query")).lower()
    val = item["payload_value"]
    attack_type = item["attack_type"]
    target_app = item.get("target_app", "")

    url = f"{base_url}/{endpoint.lstrip('/')}"
    req_params: dict[str, Any] = {}
    req_headers: dict[str, str] = {}
    req_cookies: dict[str, str] = {}
    req_data: Any = None

    if loc == "path":
        url = url.replace(f"{{{param}}}", str(val))
    elif loc == "query":
        req_params[param] = str(val)
    elif loc == "header":
        req_headers[param] = str(val)
    elif loc == "cookie":
        req_cookies[param] = str(val)
    elif loc == "form-data":
        req_data = {param: str(val)}
    elif loc == "body":
        body_dict = _build_body_payload(param, val)
        req_data = json.dumps(body_dict)
        req_headers["Content-Type"] = "application/json"
    else:
        req_params[param] = str(val)

    start_t = time.perf_counter()
    status_code = 0
    resp_text = ""
    try:
        resp = session.request(
            method,
            url,
            params=req_params,
            data=req_data,
            headers=req_headers,
            cookies=req_cookies,
            timeout=timeout,
        )
        status_code = resp.status_code
        resp_text = resp.text[:1000]

        # Xử lý tự động refresh token nếu bị 401
        if status_code == 401 and token_mgr and token_mgr.auth_type != "static":
            if token_mgr.handle_response(resp, session=session):
                resp = session.request(
                    method,
                    url,
                    params=req_params,
                    data=req_data,
                    headers=req_headers,
                    cookies=req_cookies,
                    timeout=timeout,
                )
                status_code = resp.status_code
                resp_text = resp.text[:1000]
    except Exception as exc:
        status_code = 0
        resp_text = str(exc)
    latency_ms = round((time.perf_counter() - start_t) * 1000, 2)

    return {
        "tool": "fuzzer_engine",
        "target_app": target_app,
        "endpoint": endpoint,
        "method": method,
        "vuln_type": attack_type,
        "severity": "high" if status_code >= 500 else "medium" if "syntax" in resp_text.lower() else "info",
        "http_status": status_code,
        "response_time_ms": latency_ms,
        "confirmed": False,
        "evidence": f"HTTP {status_code}; Latency {latency_ms}ms; Response: {resp_text[:200]}",
        "reproduction": {
            "method": method,
            "url": url,
            "target_param": param,
            "location": loc,
            "payload_value": val,
        },
    }


def run_full_scan(
    spec_path: str | Path,
    *,
    target_url: str | None = None,
    provider: str = "gemini",
    model: str | None = None,
    out_dir: str | Path = "results",
    safe_mode: bool = True,
    mask_data: bool = True,
    dry_run: bool = False,
    fail_on: str = "high",
    auth_token: str | None = None,
    auth_header: str = "Authorization",
    auth_prefix: str = "Bearer ",
    concurrency: int = 5,
    timeout: float = 8.0,
) -> int:
    """Chạy toàn bộ vòng đời Fuzzing."""
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    run_id = new_run_id()
    telemetry = RunTelemetry()

    print("=" * 65)
    print(" LLM-ASSISTED API FUZZING — AUTOMATED SCAN PIPELINE")
    print("=" * 65)
    print(f"[*] Spec file   : {spec_path}")
    print(f"[*] Target URL  : {target_url or '(Dry run / Generation only)'}")
    print(f"[*] Provider    : {provider} (model: {model or 'default'})")
    print(f"[*] Safe Mode   : {'BẬT (Chặn DELETE & endpoint nguy hiểm)' if safe_mode else 'TẮT'}")
    print(f"[*] Data Masking: {'BẬT (Che giấu IP/Domain nội bộ)' if mask_data else 'TẮT'}")
    if target_url and not dry_run:
        print(f"[*] Auth Token  : {'(Đã cấu hình)' if auth_token else '(Không)'}")
        print(f"[*] Concurrency : {concurrency} workers (Timeout: {timeout}s)")
    print("-" * 65)

    # 1. Phân tích đặc tả API
    telemetry.start("analyzer")
    endpoints = analyze_file(spec_path)
    telemetry.stop("analyzer")
    print(f"[1/6] Phân tích đặc tả thành công: phát hiện {len(endpoints)} endpoints.")

    # 2. Data Masking (nếu bật)
    context_data = endpoints
    reverse_map: dict[str, str] = {}
    if mask_data:
        context_data, reverse_map = mask_spec_data(endpoints)
        print(f"[2/6] Đã ẩn danh (Data Masking) {len(reverse_map)} mục nhạy cảm.")
    else:
        print("[2/6] Bỏ qua Data Masking.")

    # 3. Sinh Payload qua LLM Provider
    print(f"[3/6] Gọi LLM Provider '{provider}' sinh attack payloads...")
    telemetry.start("llm_generation")
    try:
        provider_inst = get_provider(provider, model=model)
        prompt = build_payload_generation_prompt(context_data)
        gen_res = provider_inst.generate(prompt)
    except Exception as exc:
        telemetry.stop("llm_generation")
        print(f"[ERROR] Không thể kết nối tới LLM Provider '{provider}': {exc}", file=sys.stderr)
        print(f"        -> Vui lòng kiểm tra API Key (GEMINI_API_KEY/DEEPSEEK_API_KEY) hoặc URL Local LLM (LOCAL_LLM_URL).", file=sys.stderr)
        return 1
    telemetry.add_usage(gen_res.get("usage"), source=provider)
    telemetry.stop("llm_generation")
    raw_reply = str(gen_res.get("reply", ""))

    # 4. Xác thực & Vòng lặp tự sửa lỗi (Pydantic Guardrails)
    print("[4/6] Xác thực cấu trúc output & Guardrails...")
    telemetry.start("validation")
    val_res = validate_llm_output(raw_reply)
    telemetry.record_validation(val_res.ok)
    telemetry.stop("validation")

    attempt = 1
    while not val_res.ok and attempt < MAX_REPAIR_ATTEMPTS:
        attempt += 1
        telemetry.add_repair()
        print(f"      [!] Lỗi schema lần {attempt-1}: {val_res.error_message}. Đang yêu cầu sửa lại ({attempt}/{MAX_REPAIR_ATTEMPTS})...")
        telemetry.start("repair")
        repair_prompt = build_repair_prompt(raw_reply, val_res.error_message or "", attempt)
        try:
            rep_res = provider_inst.repair(repair_prompt)
        except Exception as exc:
            telemetry.stop("repair")
            print(f"[ERROR] Lỗi kết nối LLM khi yêu cầu tự sửa: {exc}", file=sys.stderr)
            return 1
        telemetry.add_usage(rep_res.get("usage"), source=provider)
        raw_reply = str(rep_res.get("reply", ""))
        telemetry.stop("repair")

        telemetry.start("validation")
        val_res = validate_llm_output(raw_reply, attempt=attempt)
        telemetry.record_validation(val_res.ok)
        telemetry.stop("validation")

    if not val_res.ok:
        print(f"[ERROR] Sau {MAX_REPAIR_ATTEMPTS} lần thử, LLM không trả JSON hợp lệ: {val_res.error_message}", file=sys.stderr)
        return 1

    payloads = payloads_to_jsonable(val_res.payloads or [])

    # Khôi phục (Unmask) dữ liệu sau khi LLM sinh
    if mask_data and reverse_map:
        payloads = unmask_object(payloads, reverse_map)
        print(f"      [Data Masking] Đã khôi phục (Unmask) {len(reverse_map)} mục nhạy cảm cho payloads.")

    print(f"      [OK] Đã xác thực thành công {len(payloads)} payloads.")

    # 5. Chế độ An toàn (Safe Mode)
    if safe_mode:
        payloads, blocked = filter_safe_payloads(payloads, safe_mode=True)
        if blocked:
            print(f"      [Safe Mode] Đã lọc bỏ {len(blocked)} payload có nguy cơ phá hủy.")

    # Lưu artifacts payload
    canonical_file = out_path / "payloads_validated.json"
    fuzz_file = out_path / "payloads_fuzz.json"
    canonical_file.write_text(json.dumps(payloads, ensure_ascii=False, indent=2), encoding="utf-8")

    fuzz_items = [convert_attack_payload_to_fuzz(p, target_app=Path(spec_path).stem) for p in payloads]
    fuzz_file.write_text(json.dumps({"payloads": fuzz_items}, ensure_ascii=False, indent=2), encoding="utf-8")

    # 6. Bắn Fuzzing thực tế (nếu có target_url và không bật dry_run)
    findings: list[dict[str, Any]] = []
    if target_url and not dry_run:
        print(f"[5/6] Thực thi Fuzzing vào target: {target_url}...")
        import requests
        base_url = target_url.rstrip("/")
        session = requests.Session()

        token_mgr = None
        if auth_token:
            token_mgr = TokenManager(
                auth_type="static",
                static_token=auth_token,
                header_name=auth_header,
                token_prefix=auth_prefix,
            )
            session.headers.update(token_mgr.get_headers(session=session))

        # Thực thi tuần tự hoặc đa luồng (Concurrent)
        if concurrency > 1 and len(fuzz_items) > 1:
            print(f"      [*] Chạy đồng thời ({concurrency} workers)...")
            with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
                future_map = {
                    executor.submit(_send_fuzz_request, session, base_url, item, timeout, token_mgr): item
                    for item in fuzz_items
                }
                for fut in concurrent.futures.as_completed(future_map):
                    findings.append(fut.result())
        else:
            for item in fuzz_items:
                res = _send_fuzz_request(session, base_url, item, timeout=timeout, token_mgr=token_mgr)
                findings.append(res)

        print(f"      [OK] Đã hoàn thành bắn {len(findings)} test cases.")

        # Phân tích Oracle & Đồng bộ kết quả vào findings
        print("[6/6] Phân tích bằng Enhanced Oracle (Regex, Timing, OAST, BOLA)...")
        analysis = oracle_analyze(findings)

        # Cập nhật ngược lại vào findings để phục vụ xuất báo cáo SARIF và Security Gate
        for c in analysis.classified:
            f = c.finding
            if c.signal == Signal.SUCCESS:
                f["confirmed"] = True
                vuln_upper = str(f.get("vuln_type", "")).upper()
                if any(k in vuln_upper for k in ("SQL", "BOLA", "AUTH", "SSRF", "COMMAND", "TRAVERSAL")):
                    f["severity"] = "critical"
                else:
                    f["severity"] = "high"
                f["confidence"] = 95
                f["evidence"] = f"[ORACLE CONFIRMED: {c.reason}] {f.get('evidence', '')}".strip()
            elif c.signal == Signal.ANOMALY:
                if str(f.get("severity", "")).lower() in ("info", "low", ""):
                    f["severity"] = "medium"
                f["confidence"] = 80
                f["evidence"] = f"[ORACLE ANOMALY: {c.reason}] {f.get('evidence', '')}".strip()
            else:
                f["confidence"] = 40

        print(f"      - Khai thác thành công (Success) : {len(analysis.successes)}")
        print(f"      - Bất thường phát hiện (Anomaly)  : {len(analysis.anomalies)}")
        print(f"      - Không phản hồi lỗi (Miss)       : {len(analysis.misses)}")
    else:
        print("[5/6] Bỏ qua Fuzzing runtime (chế độ Dry Run hoặc chưa cấu hình URL).")
        # Giả định finding từ danh sách payload để phục vụ xuất báo cáo
        for p in payloads:
            findings.append({
                "tool": "static_analyzer",
                "target_app": Path(spec_path).stem,
                "endpoint": p["path"],
                "method": p["method"],
                "vuln_type": p["vulnerability_type"],
                "severity": "medium",
                "http_status": None,
                "confirmed": False,
                "evidence": f"Generated candidate payload: {p['payload_value']}. Rationale: {p['rationale']}",
            })

    # Xuất báo cáo SARIF, CSV, NDJSON
    sarif_file = out_path / "findings_summary.sarif"
    csv_file = out_path / "findings_summary.csv"
    ndjson_file = out_path / "findings_summary.ndjson"

    export_sarif_file(findings, str(sarif_file))

    # Xuất CSV summary
    with open(csv_file, "w", encoding="utf-8-sig", newline="") as cf:
        writer = csv.writer(cf)
        writer.writerow(["target_app", "method", "endpoint", "vuln_type", "severity", "http_status", "confirmed", "evidence"])
        for f in findings:
            writer.writerow([
                f.get("target_app", ""),
                f.get("method", ""),
                f.get("endpoint", ""),
                f.get("vuln_type", ""),
                f.get("severity", ""),
                f.get("http_status", ""),
                f.get("confirmed", False),
                f.get("evidence", ""),
            ])

    # Xuất NDJSON
    ndjson_file.write_text(
        "\n".join(json.dumps(f, ensure_ascii=False) for f in findings) + ("\n" if findings else ""),
        encoding="utf-8",
    )

    # Manifest
    manifest = build_manifest(
        run_id=run_id,
        target_name=Path(spec_path).stem,
        protocol="rest",
        provider=provider,
        model=model or provider_inst.model,
        telemetry=telemetry,
        payload_count=len(payloads),
        status="completed",
        output_path=canonical_file,
        context_path=out_path / "context.json",
    )
    write_manifest(manifest, out_path / "manifest.json")

    print("-" * 65)
    print(" BÁO CÁO KẾT THÚC QUY TRÌNH:")
    print(f" [+] OASIS SARIF Report : {sarif_file}")
    print(f" [+] CSV Findings Report: {csv_file}")
    print(f" [+] NDJSON Findings    : {ndjson_file}")
    print(f" [+] Validated Payloads : {canonical_file}")
    print(f" [+] Fuzzing Payloads   : {fuzz_file}")
    print(f" [+] Run Manifest       : {out_path / 'manifest.json'}")

    passed, gate_msg = security_gate(findings, fail_on=fail_on)
    print(f" [+] Security Gate ({fail_on}): {gate_msg}")
    print("=" * 65)

    return 0 if passed else 1


def main(argv: list[str] | None = None) -> int:
    _ensure_utf8()
    parser = argparse.ArgumentParser(description="LLM-Assisted API Fuzzer — Single Entrypoint CLI")
    subparsers = parser.add_subparsers(dest="command", help="Lệnh thực thi")

    scan_parser = subparsers.add_parser("scan", help="Chạy quét tự động toàn bộ quy trình")
    scan_parser.add_argument("spec", help="Đường dẫn file OpenAPI/Swagger (JSON hoặc YAML)")
    scan_parser.add_argument("--target-url", "-u", help="URL máy chủ API đích (nếu muốn bắn fuzzing thật)")
    scan_parser.add_argument("--provider", "-p", choices=["gemini", "deepseek", "local", "ollama", "vllm"], default="gemini", help="LLM Provider")
    scan_parser.add_argument("--model", "-m", help="Tên model LLM")
    scan_parser.add_argument("--out-dir", "-o", default="results", help="Thư mục xuất báo cáo")
    scan_parser.add_argument("--no-safe-mode", action="store_true", help="Tắt Safe Mode (cho phép bắn DELETE và destructive endpoints)")
    scan_parser.add_argument("--no-mask-data", action="store_true", help="Tắt tính năng Data Masking PII/Internal IP")
    scan_parser.add_argument("--dry-run", action="store_true", help="Chỉ sinh payload và xuất báo cáo, không gửi request mạng thật")
    scan_parser.add_argument("--fail-on", default="high", choices=["critical", "high", "medium", "low", "info"], help="Ngưỡng chặn của Security Gate")
    scan_parser.add_argument("--auth-token", "-t", "--token", help="Bearer token hoặc auth token cho target API")
    scan_parser.add_argument("--auth-header", default="Authorization", help="Tên HTTP header xác thực (mặc định: Authorization)")
    scan_parser.add_argument("--auth-prefix", default="Bearer ", help="Tiền tố auth token (mặc định: 'Bearer ')")
    scan_parser.add_argument("--concurrency", "-c", type=int, default=5, help="Số luồng request đồng thời khi Fuzzing (mặc định: 5)")
    scan_parser.add_argument("--timeout", type=float, default=8.0, help="Thời gian chờ tối đa cho mỗi HTTP request tính bằng giây (mặc định: 8.0)")

    args = parser.parse_args(argv)

    if args.command == "scan":
        return run_full_scan(
            args.spec,
            target_url=args.target_url,
            provider=args.provider,
            model=args.model,
            out_dir=args.out_dir,
            safe_mode=not args.no_safe_mode,
            mask_data=not args.no_mask_data,
            dry_run=args.dry_run,
            fail_on=args.fail_on,
            auth_token=args.auth_token,
            auth_header=args.auth_header,
            auth_prefix=args.auth_prefix,
            concurrency=args.concurrency,
            timeout=args.timeout,
        )
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
