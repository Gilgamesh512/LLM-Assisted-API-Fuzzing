
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any

from core.finding import normalize_findings, severity_rank

REPO_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_INPUTS = [
    REPO_ROOT / "Schemathesis" / "results" / "vulnerabilities.ndjson",
    REPO_ROOT / "Nuclei" / "executor" / "out" / "vulnerabilities.ndjson",
    REPO_ROOT / "Nuclei" / "executor" / "results" / "vulnerabilities.ndjson",
    REPO_ROOT / "results" / "nuclei" / "vulnerabilities.ndjson",
]

DEFAULT_OUT_DIR = REPO_ROOT / "results"

UNIFIED_FIELDS = [
    "tool",
    "target_app",
    "endpoint",
    "method",
    "vuln_type",
    "severity",
    "http_status",
    "confirmed",
    "evidence",
    "reference",
    "id",
    "vulnerability",
    "confidence",
    "reproduction",
    "recommendation",
    "source_engine",
    "payload_source",
    "baseline_status",
    "confirmation_method",
]


def _ensure_utf8_console() -> None:
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name, None)
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (AttributeError, ValueError, OSError):
                pass


def _norm_schemathesis(d: dict[str, Any]) -> dict[str, Any]:
    return {
        "tool": d.get("tool") or d.get("source") or "schemathesis",
        "target_app": d.get("target_app") or "",
        "endpoint": d.get("endpoint") or "",
        "method": (d.get("method") or "").upper(),
        "vuln_type": d.get("attack_type") or "",
        "severity": d.get("severity") or "info",
        "http_status": d.get("status_code"),
        "confirmed": bool(d.get("confirmed", False)),
        "evidence": d.get("evidence") or "",
        "reference": d.get("matched_cve") or "",
    }


def _norm_nuclei(d: dict[str, Any]) -> dict[str, Any]:
    return {
        "tool": "nuclei",
        "target_app": d.get("target_app") or "",
        "endpoint": d.get("endpoint") or "",
        "method": (d.get("method") or "").upper(),
        "vuln_type": d.get("vuln_type") or "",
        "severity": d.get("severity") or "info",
        "http_status": d.get("response_status"),
        "confirmed": bool(d.get("matched", False)),
        "evidence": d.get("evidence") or d.get("matched_at") or "",
        "reference": d.get("matched_at") or "",
    }


def _classify_and_norm(d: dict[str, Any]) -> dict[str, Any] | None:
    if "attack_type" in d:
        return _norm_schemathesis(d)
    if "vuln_type" in d and "matched" in d:
        return _norm_nuclei(d)
    if "vuln_type" in d:
        return _norm_nuclei(d)
    return None


def load_ndjson(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def dedup(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple] = set()
    out: list[dict[str, Any]] = []
    for f in findings:
        key = (f["tool"], f["target_app"], f["endpoint"], f["method"], f["vuln_type"])
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def write_outputs(findings: list[dict[str, Any]], out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    ndjson_path = out_dir / "findings_summary.ndjson"
    csv_path = out_dir / "findings_summary.csv"

    with open(ndjson_path, "w", encoding="utf-8", newline="\n") as fh:
        for f in findings:
            fh.write(json.dumps(f, ensure_ascii=False) + "\n")

    with open(csv_path, "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=UNIFIED_FIELDS)
        w.writeheader()
        for f in findings:
            w.writerow({k: f.get(k) for k in UNIFIED_FIELDS})

    return csv_path, ndjson_path


def print_summary(findings: list[dict[str, Any]]) -> None:
    confirmed = [f for f in findings if f["confirmed"]]
    by_tool: dict[str, int] = {}
    by_sev: dict[str, int] = {}
    by_vuln: dict[str, int] = {}
    for f in findings:
        by_tool[f["tool"]] = by_tool.get(f["tool"], 0) + 1
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        by_vuln[f["vuln_type"]] = by_vuln.get(f["vuln_type"], 0) + 1

    W = 60
    print("=" * W)
    print(" TỔNG HỢP LỖ HỔNG (nuclei + schemathesis)")
    print("=" * W)
    print(f" Tổng finding : {len(findings)}   |   Đã xác nhận (confirmed): {len(confirmed)}")
    print("-" * W)
    print(" Theo tool   :", ", ".join(f"{k}={v}" for k, v in sorted(by_tool.items())))
    print(
        " Theo mức độ :",
        ", ".join(f"{k}={v}" for k, v in sorted(by_sev.items(), key=lambda x: -severity_rank(x[0]))),
    )
    print(" Theo loại   :", ", ".join(f"{k}={v}" for k, v in sorted(by_vuln.items())))
    print("=" * W)


def main(argv: list[str] | None = None) -> int:
    _ensure_utf8_console()
    parser = argparse.ArgumentParser(description="Gộp kết quả nuclei + schemathesis thành 1 báo cáo.")
    parser.add_argument(
        "--input", "-i", action="append", default=None,
        help="File .ndjson kết quả (lặp lại nhiều lần). Bỏ trống = dò vị trí mặc định.",
    )
    parser.add_argument("--out-dir", "-o", default=str(DEFAULT_OUT_DIR), help="Thư mục xuất báo cáo gộp.")
    parser.add_argument("--no-dedup", action="store_true", help="Không khử trùng lặp.")
    parser.add_argument(
        "--only-confirmed", action="store_true",
        help="Chỉ xuất finding đã xác nhận (confirmed/matched=true).",
    )
    args = parser.parse_args(argv)

    inputs = [Path(p) for p in (args.input or [])] or DEFAULT_INPUTS
    existing = [p for p in inputs if p.is_file()]
    if not existing:
        print("[agg] Không tìm thấy file kết quả nào. Đã dò:", file=sys.stderr)
        for p in inputs:
            print(f"    - {p}", file=sys.stderr)
        print("[agg] Chạy nuclei/schemathesis trước, hoặc truyền --input.", file=sys.stderr)
        return 1

    findings: list[dict[str, Any]] = []
    for path in existing:
        rows = load_ndjson(path)
        kept = 0
        for d in rows:
            norm = _classify_and_norm(d)
            if norm is None:
                continue
            findings.append(norm)
            kept += 1
        print(f"[agg] {path.name}: {kept}/{len(rows)} dòng nhận diện được")

    if args.only_confirmed:
        findings = [f for f in findings if f["confirmed"]]
    if not args.no_dedup:
        before = len(findings)
        findings = dedup(findings)
        if before != len(findings):
            print(f"[agg] Khử trùng lặp: {before} -> {len(findings)}")

    findings = normalize_findings(findings)
    findings.sort(key=lambda f: (-severity_rank(f["severity"]), f["tool"], f["endpoint"]))

    csv_path, ndjson_path = write_outputs(findings, Path(args.out_dir))
    print()
    print_summary(findings)
    print()
    print(f"[agg] Máy đọc  : {ndjson_path}")
    print(f"[agg] Người đọc: {csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
