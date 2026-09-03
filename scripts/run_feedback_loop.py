from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))
sys.path.insert(0, str(REPO_ROOT / "Nuclei" / "executor"))

from core import target_config as tc  # noqa: E402
from core.feedback_loop import run_feedback_loop, GenerationRecord  # noqa: E402


def _ensure_utf8_console() -> None:
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name, None)
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (AttributeError, ValueError, OSError):
                pass


def make_real_gen_fn(max_endpoints: int):
    import gen_payloads

    def gen_fn(target: Any, feedback: str | None, seeds, generation: int):
        spec = target.resolve_spec_path()
        tag = "gen0" if feedback is None else f"gen{generation} (có phản hồi)"
        print(f"[loop]   B sinh payload {tag} cho '{target.name}'...")
        return gen_payloads.build_nuclei_suite(
            target.name, spec, target.base_url, max_endpoints, feedback=feedback
        )

    return gen_fn


def make_real_fire_fn():
    from executor import run_nuclei

    def fire_fn(suite: Any, target: Any) -> list[dict[str, Any]]:
        print(f"[loop]   Người 1: bắn {len(suite.test_cases)} test case qua Nuclei -> {target.base_url}")
        result = run_nuclei.execute(suite)
        out_dir = REPO_ROOT / "results" / "nuclei"
        out_dir.mkdir(parents=True, exist_ok=True)
        run_nuclei.export_csv(result, out_dir / "vulnerabilities.csv", only_matched=False)
        run_nuclei.export_ndjson(result, out_dir / "vulnerabilities.ndjson", only_matched=False)
        unified: list[dict[str, Any]] = []
        for f in result.findings:
            d = f.model_dump()
            unified.append(
                {
                    "tool": "nuclei",
                    "endpoint": d.get("endpoint", ""),
                    "method": "",
                    "vuln_type": d.get("vuln_type", ""),
                    "http_status": d.get("response_status"),
                    "confirmed": bool(d.get("matched", False)),
                    "evidence": d.get("evidence") or d.get("matched_at") or "",
                    "severity": d.get("severity", "info"),
                }
            )
        return unified

    return fire_fn


def make_mock_fns():
    scenarios = [
        [{"vuln_type": "SQLI", "endpoint": "/users/v1/login", "method": "POST",
          "http_status": 200, "confirmed": False, "evidence": "HTTP 200; khong co dau hieu", "severity": "info"}],
        [{"vuln_type": "SQLI", "endpoint": "/users/v1/login", "method": "POST",
          "http_status": 500, "confirmed": False,
          "evidence": "HTTP 500; you have an error in your SQL syntax near '''", "severity": "medium"}],
        [{"vuln_type": "SQLI", "endpoint": "/users/v1/login", "method": "POST",
          "http_status": 200, "confirmed": True, "evidence": "auth bypass; matcher trung", "severity": "high"}],
    ]
    state = {"i": 0}

    def gen_fn(target, feedback, seeds, generation):
        print(f"[loop]   (mock) B sinh payload gen{generation}" + (" có phản hồi" if feedback else ""))
        return f"mock-suite-gen{generation}"

    def fire_fn(suite, target):
        i = min(state["i"], len(scenarios) - 1)
        state["i"] += 1
        print(f"[loop]   (mock) Người 1: bắn payload gen -> giả lập kết quả kịch bản {i}")
        return scenarios[i]

    return gen_fn, fire_fn


def _print_gen(rec: GenerationRecord) -> None:
    print(
        f"[loop] Gen {rec.generation}: {rec.n_payloads} payload | "
        f"success={rec.n_success} anomaly={rec.n_anomaly} miss={rec.n_miss} "
        f"{'-> KHAI THÁC THÀNH CÔNG' if rec.exploited else ''}"
    )


def main(argv: list[str] | None = None) -> int:
    _ensure_utf8_console()
    parser = argparse.ArgumentParser(description="Phần C — vòng phản hồi runtime (B->fire->oracle->B).")
    parser.add_argument("--target", default="vampi", help="Tên target trong config/targets.yaml.")
    parser.add_argument("--config", help="File config target (mặc định config/targets.yaml).")
    parser.add_argument("--max-gen", type=int, default=3, help="Số thế hệ payload tối đa.")
    parser.add_argument("--max-no-progress", type=int, default=3, help="Dừng sau N thế hệ liên tiếp không có tín hiệu mới.")
    parser.add_argument("--max-endpoints", type=int, default=15, help="Số endpoint đưa vào prompt mỗi thế hệ.")
    parser.add_argument("--mock", action="store_true", help="Chạy demo bằng dữ liệu giả (không cần LLM/nuclei/target).")
    args = parser.parse_args(argv)

    if args.mock:
        target: Any = type("T", (), {"name": args.target, "base_url": "mock://target"})()
        gen_fn, fire_fn = make_mock_fns()
    else:
        cfg_path = args.config or str(tc.DEFAULT_CONFIG_PATH)
        try:
            target = tc.get_target(args.target, cfg_path)
        except tc.TargetConfigError as exc:
            print(f"[loop] LỖI: {exc}", file=sys.stderr)
            return 1
        gen_fn = make_real_gen_fn(args.max_endpoints)
        fire_fn = make_real_fire_fn()

    print(f"[loop] === VÒNG PHẢN HỒI RUNTIME — target='{args.target}', max_gen={args.max_gen} ===")
    try:
        result = run_feedback_loop(
            target, gen_fn, fire_fn,
            max_generations=args.max_gen,
            max_no_progress=args.max_no_progress,
            on_generation=_print_gen,
        )
    except Exception as exc:  # nuclei/LLM/target lỗi -> báo rõ, không nuốt
        print(f"[loop] LỖI khi chạy vòng lặp: {exc}", file=sys.stderr)
        return 1

    reason = {
        "success": "KHAI THÁC THÀNH CÔNG (dừng sớm)",
        "no_progress": f"{args.max_no_progress} thế hệ liên tiếp không tiến triển (dừng)",
        "budget_exhausted": f"hết ngân sách {args.max_gen} thế hệ",
    }.get(result.status, result.status)
    print(f"\n[loop] KẾT THÚC — {result.total_generations} thế hệ, lý do dừng: {reason}")
    print(f"[loop] Log: results/feedback/feedback_runs.csv + feedback_findings.ndjson")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
