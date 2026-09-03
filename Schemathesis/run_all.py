#!/usr/bin/env python3
"""
run_all.py

MAIN LAB/BOOTSTRAP CONTROLLER
=============================

This controller deliberately stops BEFORE the user's security-testing
fuzzers are executed.

Pipeline owned by this controller:

    start_lab.py
        |
        +--> VAmPI
        +--> crAPI
        +--> DVGA
        |
        v
    run_auth.py
        |
        +--> VAMPI_AUTH_HEADER
        +--> CRAPI_AUTH_HEADER
        |
        v
    run_dvga.py
        |
        +--> DVGA_AUTH_HEADER
        +--> dvga_schema.json
        |
        v
    validate handoff
        |
        +--> tokens.env: 3 authentication headers READY
        +--> dvga_schema.json: READY
        |
        v
    HANDOFF / STOP

IMPORTANT OWNERSHIP BOUNDARY
----------------------------
run_schemathesis1.py and run_graphql_fuzz1.py are NOT called here.
They are the user's security-testing components and consume the handoff
artifacts produced by this controller.

run_dvga_fuzzer.py is a legacy/experimental DVGA baseline fuzzer and is
NOT called here either. Its old analyze/triage chain is kept standalone.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PYTHON = sys.executable

START_LAB = ROOT / "start_lab.py"
RUN_AUTH = ROOT / "run_auth.py"
RUN_DVGA = ROOT / "run_dvga.py"
RUN_SECURITY_TESTS = ROOT / "run_security_tests.py"
TOKENS_FILE = ROOT / "tokens.env"
DVGA_SCHEMA = ROOT / "dvga_schema.json"

# These are intentionally NOT executed by run_all.py.


def banner(title: str) -> None:
    print()
    print("=" * 70)
    print(title)
    print("=" * 70)


def run_script(script: Path) -> None:
    if not script.exists():
        raise FileNotFoundError(f"Missing required script: {script.name}")

    print(f"\n[+] RUNNING: {script.name}")
    result = subprocess.run([PYTHON, str(script)], cwd=ROOT)

    if result.returncode != 0:
        raise RuntimeError(
            f"{script.name} failed with exit code {result.returncode}"
        )

    print(f"[+] {script.name}: OK")


def parse_tokens_env() -> dict[str, str]:
    """Parse shell-style tokens.env without sourcing/executing it."""
    if not TOKENS_FILE.exists():
        return {}

    tokens: dict[str, str] = {}

    for raw in TOKENS_FILE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        if line.startswith("export "):
            line = line[len("export "):].strip()

        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()

        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]

        if key.endswith("_AUTH_HEADER"):
            tokens[key] = value

    return tokens


def validate_handoff() -> bool:
    banner("VALIDATING FUZZING HANDOFF")

    required_tokens = (
        "VAMPI_AUTH_HEADER",
        "CRAPI_AUTH_HEADER",
        "DVGA_AUTH_HEADER",
    )

    tokens = parse_tokens_env()
    ok = True

    if not TOKENS_FILE.exists():
        print(f"[X] Missing {TOKENS_FILE.name}")
        ok = False
    else:
        for key in required_tokens:
            value = tokens.get(key, "")
            if value:
                print(f"[+] {key}: READY")
            else:
                print(f"[X] {key}: MISSING")
                ok = False

    if DVGA_SCHEMA.exists():
        try:
            import json
            data = json.loads(DVGA_SCHEMA.read_text(encoding="utf-8"))
            if data.get("target") != "dvga":
                print("[X] dvga_schema.json exists but target != dvga")
                ok = False
            elif data.get("protocol") != "graphql":
                print("[X] dvga_schema.json exists but protocol != graphql")
                ok = False
            else:
                print("[+] dvga_schema.json: READY")
        except Exception as exc:
            print(f"[X] Cannot parse dvga_schema.json: {exc}")
            ok = False
    else:
        print("[X] dvga_schema.json: MISSING")
        ok = False

    print()
    if ok:
        print("[+] HANDOFF READY")
        print("[+] Security-testing handoff validated.")
        print()
        print("Next step: main controller will launch run_security_tests.py.")
        print("    run_security_tests.py -> VAmPI/crAPI + DVGA")
    else:
        print("[X] HANDOFF NOT READY")

    return ok


def main() -> int:
    banner("API FUZZING LAB - MAIN CONTROLLER")

    print("[i] This controller prepares the lab, authentication, and launches main security testing.")
    print("[i] Security fuzzing is executed by run_security_tests.py.")
    print("[i] Legacy pipeline is completely isolated.")

    try:
        banner("1/4 CHECKING MAIN PIPELINE FILES")
        for path in (START_LAB, RUN_AUTH, RUN_DVGA):
            if path.exists():
                print(f"[+] {path.name}")
            else:
                print(f"[X] Missing: {path.name}")
                return 1

        banner("2/4 STARTING TARGET LAB")
        run_script(START_LAB)

        banner("3/4 AUTHENTICATING REST TARGETS")
        run_script(RUN_AUTH)

        banner("4/4 AUTHENTICATING + DISCOVERING DVGA")
        run_script(RUN_DVGA)

        if not validate_handoff():
            return 1

        banner("5/5 RUNNING MAIN SECURITY TESTING PIPELINE")

        if not RUN_SECURITY_TESTS.exists():
            print(f"[X] Missing: {RUN_SECURITY_TESTS.name}")
            return 1

        run_script(RUN_SECURITY_TESTS)

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        return 130
    except Exception as exc:
        print(f"\n[X] MAIN PIPELINE FAILED: {exc}")
        return 1

    banner("MAIN PIPELINE COMPLETE")
    print("[+] Lab: READY")
    print("[+] REST tokens: READY")
    print("[+] DVGA token: READY")
    print("[+] DVGA schema: READY")
    print("[+] REST fuzzing: DONE")
    print("[+] GraphQL fuzzing: DONE")
    print("[+] Main results: READY")
    print()
    print("OUTPUT:")
    print(f"    {ROOT / 'results' / 'vulnerabilities.csv'}")
    print(f"    {ROOT / 'results' / 'vulnerabilities.ndjson'}")
    print(f"    {ROOT / 'results' / 'experiment_runs.csv'}")
    print()
    print("[+] Legacy pipeline remains completely independent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
