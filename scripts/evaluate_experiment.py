"""Evaluate comparable fuzzing runs from a JSON experiment manifest."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from core.evaluation import evaluate_run, write_metrics  # noqa: E402


def _load_rows(path: Path) -> list[dict[str, Any]]:
    if path.suffix.lower() == ".jsonl" or path.suffix.lower() == ".ndjson":
        return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, list):
        raise ValueError(f"Expected a JSON array in {path}")
    return data


def _artifact_path(base_dir: Path, value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else base_dir / path


def evaluate_manifest(manifest_path: Path) -> list[dict[str, Any]]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    base_dir = manifest_path.parent
    known = manifest.get("known_vulnerabilities")
    runs = manifest.get("runs")
    if runs is None:
        runs = [{
            "treatment": manifest.get("treatment", "unknown"),
            "target": (manifest.get("target") or {}).get("name", "unknown"),
            "run_id": manifest.get("run_id", "unknown"),
            "payloads": (manifest.get("artifacts") or {}).get("payloads"),
            "findings": (manifest.get("artifacts") or {}).get("findings"),
            "runtime_seconds": (manifest.get("runtime") or {}).get("total_ms", 0) / 1000,
            "llm_tokens": (manifest.get("llm") or {}).get("total_tokens"),
        }]
    rows: list[dict[str, Any]] = []
    for run in runs:
        payload_path = run.get("payloads")
        finding_path = run.get("findings")
        payloads = _load_rows(_artifact_path(base_dir, payload_path)) if payload_path else []
        findings = _load_rows(_artifact_path(base_dir, finding_path)) if finding_path else []
        metrics = evaluate_run(
            payloads,
            findings,
            runtime_seconds=run.get("runtime_seconds", 0),
            llm_cost_usd=run.get("llm_cost_usd", 0),
            llm_tokens=run.get("llm_tokens", 0),
            known_vulnerabilities=run.get("known_vulnerabilities", known),
        )
        rows.append({
            "treatment": run.get("treatment", "unknown"),
            "target": run.get("target", "unknown"),
            "run_id": run.get("run_id", len(rows) + 1),
            **metrics,
        })
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate a reproducible API fuzzing experiment manifest.")
    parser.add_argument("manifest", type=Path, help="JSON manifest containing protocol metadata and run artifacts")
    parser.add_argument("--output", "-o", type=Path, default=REPO_ROOT / "results" / "experiment_metrics.json")
    args = parser.parse_args(argv)
    try:
        rows = evaluate_manifest(args.manifest)
        write_metrics(rows, args.output)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"[evaluate] error: {exc}", file=sys.stderr)
        return 1
    print(f"[evaluate] evaluated {len(rows)} run(s)")
    print(f"[evaluate] JSON: {args.output}")
    print(f"[evaluate] CSV: {args.output.with_suffix('.csv')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())