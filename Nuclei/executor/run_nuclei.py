

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import re
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .nuclei_runner import (
    NucleiNotFoundError,
    NucleiRunResult,
    ensure_nuclei,
    run_nuclei as _run_nuclei_cli,
)
from .schemas import ExecutorResult, Finding, Summary, Suite
from .template_builder import template_id, write_templates

logger = logging.getLogger("executor.run_nuclei")

_STATUS_RE = re.compile(r"HTTP/[\d.]+\s+(\d{3})")

DEFAULT_SUITE = Path(__file__).resolve().parent / "benchmark" / "suite.json"


def _extract_status(raw: dict[str, Any]) -> int | None:
    """Lấy HTTP status từ khối response (khi chạy với -include-rr)."""
    resp = raw.get("response")
    if isinstance(resp, str):
        m = _STATUS_RE.search(resp)
        if m:
            return int(m.group(1))
    for key in ("status_code", "status-code"):
        if isinstance(raw.get(key), int):
            return raw[key]
    return None


def _extract_evidence(raw: dict[str, Any]) -> str | None:
    """Tóm tắt bằng chứng: matcher trúng / chuỗi trích xuất."""
    parts: list[str] = []
    if raw.get("matcher-name"):
        parts.append(f"matcher={raw['matcher-name']}")
    extracted = raw.get("extracted-results")
    if isinstance(extracted, list) and extracted:
        parts.append("extracted=" + ", ".join(map(str, extracted[:5])))
    return "; ".join(parts) or None


def _index_by_template_id(raw_findings: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Gom kết quả Nuclei theo template-id để map ngược về test case."""
    index: dict[str, dict[str, Any]] = {}
    for raw in raw_findings:
        tid = raw.get("template-id") or raw.get("templateID")
        if tid and tid not in index:
            index[tid] = raw
    return index


def build_result(
    suite: Suite,
    run: NucleiRunResult,
    duration_sec: float,
    skipped_ids: set[str],
) -> ExecutorResult:
    """Ghép ``ExecutorResult`` từ suite gốc + kết quả Nuclei."""
    index = _index_by_template_id(run.findings)
    findings: list[Finding] = []
    matched_count = 0

    for tc in suite.test_cases:
        tid = template_id(tc)
        raw = index.get(tid)
        if raw is not None:
            matched_count += 1
            findings.append(
                Finding(
                    id=tc.id,
                    endpoint=tc.endpoint,
                    vuln_type=tc.vuln_type,
                    matched=True,
                    severity=tc.severity,
                    matched_at=raw.get("matched-at") or raw.get("host"),
                    response_status=_extract_status(raw),
                    evidence=_extract_evidence(raw),
                    raw=raw,
                )
            )
        else:
            findings.append(
                Finding(
                    id=tc.id,
                    endpoint=tc.endpoint,
                    vuln_type=tc.vuln_type,
                    matched=False,
                    severity=tc.severity,
                )
            )

    errors = len(skipped_ids) + (1 if run.timed_out else 0)
    summary = Summary(
        total=len(suite.test_cases),
        matched=matched_count,
        errors=errors,
        duration_sec=round(duration_sec, 2),
    )
    return ExecutorResult(target=suite.target, summary=summary, findings=findings)


def load_suite(data: dict[str, Any], target_override: str | None = None) -> Suite:
    """Validate dict JSON của B thành ``Suite`` (fail rõ ràng nếu thiếu field)."""
    if target_override:
        data = {**data, "target": target_override.rstrip("/")}
    return Suite.model_validate(data)


def execute(
    suite: Suite,
    *,
    timeout: int = 120,
    rate_limit: int = 50,
    req_timeout: int = 10,
    keep_templates: bool = False,
) -> ExecutorResult:
    """Chạy toàn bộ pipeline cho 1 suite và trả kết quả chuẩn hóa.

    Không crash nếu 1 test case lỗi — case không có matcher được đếm vào errors,
    timeout được bắt trong runner. Thư mục tạm luôn được dọn ở ``finally``.
    """
    ensure_nuclei()

    variables = dict(suite.variables)
    if "jwt" not in variables and os.getenv("JWT"):
        variables["jwt"] = os.environ["JWT"]

    tmpdir = tempfile.mkdtemp(prefix="nuclei_tpl_")
    logger.info("Thư mục template tạm: %s", tmpdir)
    start = time.perf_counter()
    try:
        written = write_templates(suite.test_cases, tmpdir, variables or None)
        skipped_ids = {
            tc.id for tc in suite.test_cases if tc.matchers.is_empty()
        }
        if skipped_ids:
            logger.warning(
                "%d test case không có matcher, bỏ qua: %s",
                len(skipped_ids),
                ", ".join(sorted(skipped_ids)),
            )
        logger.info("Đã sinh %d template, %d case bị bỏ qua", len(written), len(skipped_ids))

        if not written:
            logger.warning("Không có template hợp lệ nào để chạy.")
            run = NucleiRunResult(findings=[], returncode=0, stderr="")
        else:
            run = _run_nuclei_cli(
                tmpdir,
                suite.target,
                timeout=timeout,
                rate_limit=rate_limit,
                req_timeout=req_timeout,
            )

        duration = time.perf_counter() - start
        result = build_result(suite, run, duration, skipped_ids)
        logger.info(
            "Xong: total=%d matched=%d errors=%d duration=%.2fs",
            result.summary.total,
            result.summary.matched,
            result.summary.errors,
            result.summary.duration_sec,
        )
        return result
    finally:
        if keep_templates:
            logger.info("Giữ lại template tạm tại %s (--keep-templates)", tmpdir)
        else:
            import shutil

            shutil.rmtree(tmpdir, ignore_errors=True)


def render_text(result: ExecutorResult) -> str:
    """Render ``ExecutorResult`` thành báo cáo văn bản dễ đọc (tiếng Việt)."""
    s = result.summary
    W = 66
    line = "=" * W
    thin = "-" * W
    out: list[str] = []
    out.append(line)
    out.append(f" KẾT QUẢ FUZZING BẢO MẬT API".ljust(W))
    out.append(f" Mục tiêu : {result.target}")
    out.append(line)
    out.append(
        f" Test case: {s.total:<5} Phát hiện: {s.matched:<5} "
        f"Lỗi/bỏ qua: {s.errors:<5} Thời gian: {s.duration_sec}s"
    )

    matched = [f for f in result.findings if f.matched]
    unmatched = [f for f in result.findings if not f.matched]

    out.append(thin)
    if matched:
        out.append(f" ⚠  LỖ HỔNG PHÁT HIỆN ({len(matched)}):")
        out.append("")
        for f in matched:
            st = f"HTTP {f.response_status}" if f.response_status else "—"
            out.append(f"  [!] {f.id}   ·   {f.vuln_type.upper()}   ·   {f.severity.upper()}   ·   {st}")
            out.append(f"      endpoint : {f.endpoint}")
            if f.matched_at:
                out.append(f"      URL      : {f.matched_at}")
            if f.evidence:
                out.append(f"      bằng chứng: {f.evidence}")
            out.append("")
    else:
        out.append(" ✓  Không phát hiện lỗ hổng nào khớp matcher.")
        out.append("")

    if unmatched:
        out.append(thin)
        out.append(f" Không khớp ({len(unmatched)}):")
        names = ", ".join(f.id for f in unmatched)
        cur = "     "
        for tok in names.split(", "):
            piece = tok + ", "
            if len(cur) + len(piece) > W:
                out.append(cur.rstrip())
                cur = "     "
            cur += piece
        out.append(cur.rstrip().rstrip(","))

    out.append(line)
    rate = (s.matched / s.total * 100) if s.total else 0.0
    out.append(f" Tổng kết: {s.matched}/{s.total} test case phát hiện lỗ hổng ({rate:.0f}%).")
    if s.matched == 0:
        out.append("")
        out.append(" Gợi ý khi 0 phát hiện:")
        out.append("  - Endpoint trong suite có khớp target không? (sai path -> 0 kết quả)")
        out.append("  - Payload/matcher có đúng với phản hồi thực tế của target không?")
        out.append("  - Chạy lại với -v để xem log, hoặc --json để soi 'raw'.")
    out.append(line)
    return "\n".join(out)


_EXPORT_FIELDS = [
    "id", "matched", "vuln_type", "severity",
    "response_status", "endpoint", "matched_at", "evidence",
]


def export_ndjson(result: ExecutorResult, path: str | Path, only_matched: bool = True) -> int:
    """Xuất file cho MÁY: mỗi dòng 1 finding dạng JSON (NDJSON).

    Bỏ trường ``raw`` cho gọn. Trả về số dòng đã ghi.
    """
    findings = [f for f in result.findings if f.matched or not only_matched]
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for f in findings:
            d = f.model_dump()
            d.pop("raw", None)
            fh.write(json.dumps(d, ensure_ascii=False) + "\n")
    return len(findings)


def export_csv(result: ExecutorResult, path: str | Path, only_matched: bool = True) -> int:
    """Xuất file cho NGƯỜI: bảng CSV mở được bằng Excel.

    Dùng utf-8-sig để Excel hiển thị đúng tiếng Việt/ký tự unicode.
    """
    findings = [f for f in result.findings if f.matched or not only_matched]
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=_EXPORT_FIELDS)
        w.writeheader()
        for f in findings:
            w.writerow({k: getattr(f, k) for k in _EXPORT_FIELDS})
    return len(findings)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="python -m executor.run_nuclei",
        description="Nuclei Test Executor — chạy JSON qua Nuclei.",
    )
    p.add_argument(
        "--input", "-i", default=str(DEFAULT_SUITE),
        help=f"File JSON test suite. Mặc định: {DEFAULT_SUITE}",
    )
    p.add_argument("--target", "-u", default=None, help="Ghi đè target trong suite.")
    p.add_argument("--output", "-o", default=None, help="Ghi kết quả chuẩn hóa ra file JSON.")
    p.add_argument("--timeout", type=int, default=120, help="Timeout tổng cho Nuclei (giây).")
    p.add_argument("--rate-limit", type=int, default=50, help="Giới hạn request/giây.")
    p.add_argument("--req-timeout", type=int, default=10, help="Timeout mỗi request (giây).")
    p.add_argument("--keep-templates", action="store_true", help="Không xóa template tạm.")
    p.add_argument("--json", action="store_true", help="In JSON thô thay vì báo cáo văn bản.")
    p.add_argument(
        "--export-dir", "-e", default=None,
        help="Thư mục xuất vulnerabilities.csv (người) + vulnerabilities.ndjson (máy).",
    )
    p.add_argument(
        "--export-all", action="store_true",
        help="Xuất cả case không match (mặc định chỉ xuất lỗ hổng phát hiện).",
    )
    p.add_argument("--verbose", "-v", action="store_true", help="Log chi tiết (DEBUG).")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    input_path = Path(args.input)
    if not input_path.exists():
        logger.error("Không thấy file input: %s", input_path)
        return 2

    try:
        data = json.loads(input_path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        logger.error("File input không phải JSON hợp lệ: %s", exc)
        return 2

    if isinstance(data, dict) and not data.get("target") and not args.target:
        logger.error(
            "Thiếu 'target'. Thêm field \"target\" trong file JSON, "
            "hoặc truyền --target http://muc-tieu. Vd: --target http://demo.testfire.net"
        )
        return 2

    try:
        suite = load_suite(data, args.target)
    except ValidationError as exc:
        errs = [f"  - {'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors()]
        logger.error(
            "JSON test suite không hợp lệ (%d lỗi):\n%s", len(errs), "\n".join(errs)
        )
        return 2

    try:
        result = execute(
            suite,
            timeout=args.timeout,
            rate_limit=args.rate_limit,
            req_timeout=args.req_timeout,
            keep_templates=args.keep_templates,
        )
    except NucleiNotFoundError as exc:
        logger.error("%s", exc)
        return 3

    payload = result.model_dump()
    if args.output:
        Path(args.output).write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        logger.info("Đã ghi kết quả JSON ra %s", args.output)

    if args.export_dir:
        d = Path(args.export_dir)
        d.mkdir(parents=True, exist_ok=True)
        only = not args.export_all
        csv_path = d / "vulnerabilities.csv"
        ndjson_path = d / "vulnerabilities.ndjson"
        n_csv = export_csv(result, csv_path, only_matched=only)
        export_ndjson(result, ndjson_path, only_matched=only)
        logger.info("Đã xuất %d dòng -> %s (người) + %s (máy)", n_csv, csv_path, ndjson_path)

    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(render_text(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
