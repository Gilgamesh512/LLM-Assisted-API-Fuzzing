from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from core.baseline import compare_baseline, load_findings, security_gate


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare security findings and enforce a severity gate.")
    parser.add_argument("current", type=Path, help="Current findings_summary.ndjson")
    parser.add_argument("--baseline", type=Path, help="Previous findings_summary.ndjson")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "info"], default="high")
    args = parser.parse_args()

    current = load_findings(args.current)
    if args.baseline:
        diff = compare_baseline(load_findings(args.baseline), current)
        print(json.dumps({"new": diff.new_by_severity, "new_count": len(diff.new), "resolved_count": len(diff.resolved)}, ensure_ascii=False))
        gate_findings = diff.new
    else:
        print(json.dumps({"new": {"all": len(current)}, "new_count": len(current), "resolved_count": 0}, ensure_ascii=False))
        gate_findings = current

    passed, message = security_gate(gate_findings, args.fail_on)
    print(message)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
