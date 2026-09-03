#!/usr/bin/env python3

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


MAIN_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = MAIN_DIR.parent

sys.path.insert(0, str(PROJECT_ROOT))
_CFG_BASE_URLS: dict[str, str] = {}
_CFG_SPECS: dict[str, Path] = {}
try:
    from core import target_config as _tc

    for _n, _t in _tc.load_targets().targets.items():
        _CFG_BASE_URLS[_n] = _t.base_url
        if _t.spec:
            _p = Path(_t.spec)
            _CFG_SPECS[_n] = _p if _p.is_absolute() else PROJECT_ROOT / _p
except Exception:
    pass

RESULTS_DIR = MAIN_DIR / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

PYTHON = sys.executable

REST_FUZZER = MAIN_DIR / "run_schemathesis1.py"
GRAPHQL_FUZZER = MAIN_DIR / "run_graphql_fuzz1.py"

RULES = MAIN_DIR / "rules.json"

TOKENS_FILE = MAIN_DIR / "tokens.env"

VAMPI_PAYLOADS_CANDIDATES = [
    MAIN_DIR / "payload_rest.json",
    PROJECT_ROOT / "payload_rest.json",
]

CRAPI_PAYLOADS_CANDIDATES = [
    MAIN_DIR / "payload_crapi.json",
    PROJECT_ROOT / "payload_crapi.json",
]

GRAPHQL_PAYLOADS_CANDIDATES = [
    PROJECT_ROOT / "payload_graphql.json",
    MAIN_DIR / "payload_graphql.json",
]

VAMPI_SPEC_CANDIDATES = [
    p for p in [_CFG_SPECS.get("vampi"), PROJECT_ROOT / "vampi_spec.yaml", MAIN_DIR / "vampi_spec.yaml"] if p
]

CRAPI_SPEC_CANDIDATES = [
    p for p in [_CFG_SPECS.get("crapi"), PROJECT_ROOT / "crapi_openapi_spec.json", MAIN_DIR / "crapi_openapi_spec.json"] if p
]

TARGET_BASE_URLS = {
    "vampi": _CFG_BASE_URLS.get("vampi", "http://localhost:5002"),
    "crapi": _CFG_BASE_URLS.get("crapi", "http://localhost:8888"),
    "dvga": _CFG_BASE_URLS.get("dvga", "http://localhost:5013"),
}


def banner(title: str) -> None:
    print()
    print("=" * 70)
    print(title)
    print("=" * 70)


def first_existing(candidates: list[Path], label: str) -> Path:
    for path in candidates:
        if path.exists():
            return path.resolve()
    print(f"[X] {label}: NOT FOUND")
    for path in candidates:
        print(f"    checked: {path}")
    raise FileNotFoundError(label)


def parse_tokens_env() -> dict[str, str]:
    if not TOKENS_FILE.exists():
        print(f"[CANH BAO] Khong thay {TOKENS_FILE} - fuzzing se chay KHONG co auth header.")
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


def run_command(label: str, args: list[str], extra_env: dict[str, str] | None = None) -> None:
    print()
    print(f"[+] RUNNING: {label}")
    print("[CMD]")
    print(" ".join(str(x) for x in args))
    print()

    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        [str(MAIN_DIR), str(PROJECT_ROOT), env.get("PYTHONPATH", "")]
    ).rstrip(os.pathsep)

    if extra_env:
        env.update(extra_env)
        if extra_env.get("FUZZ_AUTH_HEADER"):
            print("[INFO] FUZZ_AUTH_HEADER duoc set RIENG cho buoc nay tu tokens.env "
                  "(khong lay tu bien moi truong cua shell hien tai).")
    else:
        env.pop("FUZZ_AUTH_HEADER", None)

    result = subprocess.run(args, cwd=MAIN_DIR, env=env)
    if result.returncode != 0:
        raise RuntimeError(f"{label} failed with exit code {result.returncode}")
    print(f"[+] {label}: OK")


def check_file(path: Path, label: str) -> None:
    if not path.exists():
        raise FileNotFoundError(f"{label} missing: {path}")
    print(f"[+] {label}: {path}")


def auth_env_for(tokens: dict[str, str], key: str) -> dict[str, str] | None:
    value = tokens.get(key)
    return {"FUZZ_AUTH_HEADER": value} if value else None


def main() -> int:
    banner("MAIN SECURITY TESTING PIPELINE")
    print("[i] Controller belongs ONLY to main_pipeline.")
    print("[i] Legacy pipeline is completely independent.")
    print("[i] Legacy DVGA fuzzer is NOT executed here.")
    print(f"[i] Main results: {RESULTS_DIR}")

    try:
        banner("1/4 CHECKING MAIN SECURITY PIPELINE")
        check_file(REST_FUZZER, "run_schemathesis1.py")
        check_file(GRAPHQL_FUZZER, "run_graphql_fuzz1.py")

        banner("2/4 RESOLVING FUZZING INPUTS")
        vampi_payloads = first_existing(
            VAMPI_PAYLOADS_CANDIDATES,
            "VAmPI REST payload corpus"
        )
        crapi_payloads = first_existing(
            CRAPI_PAYLOADS_CANDIDATES,
            "crAPI REST payload corpus"
        )
        graphql_payloads = first_existing(
            GRAPHQL_PAYLOADS_CANDIDATES,
            "GraphQL payload corpus"
        )
        check_file(RULES, "rules.json")
        vampi_spec = first_existing(VAMPI_SPEC_CANDIDATES, "VAmPI OpenAPI spec")
        crapi_spec = first_existing(CRAPI_SPEC_CANDIDATES, "crAPI OpenAPI spec")

        tokens = parse_tokens_env()
        for key in ("VAMPI_AUTH_HEADER", "CRAPI_AUTH_HEADER", "DVGA_AUTH_HEADER"):
            status = "READY" if tokens.get(key) else "MISSING - buoc lien quan se chay khong auth"
            mark = "+" if tokens.get(key) else "X"
            print(f"[{mark}] {key}: {status}")

        print()
        print("[+] VAmPI payloads :", vampi_payloads)
        print("[+] crAPI payloads :", crapi_payloads)
        print("[+] GraphQL payloads:", graphql_payloads)
        print("[+] Rules          :", RULES)
        print("[+] VAmPI spec     :", vampi_spec)
        print("[+] crAPI spec     :", crapi_spec)

        banner("3/4 RUNNING REST FUZZING - VAmPI + crAPI")

        run_command(
            "REST FUZZING - VAmPI",
            [PYTHON, str(REST_FUZZER),
             "--targets", f"vampi={vampi_spec}",
             "--base-urls", f"vampi={TARGET_BASE_URLS['vampi']}",
             "--payloads", str(vampi_payloads),
             "--rules", str(RULES),
             "--results-dir", str(RESULTS_DIR),
             "--concurrency", "3"],
            extra_env=auth_env_for(tokens, "VAMPI_AUTH_HEADER"),
        )

        run_command(
            "REST FUZZING - crAPI",
            [PYTHON, str(REST_FUZZER),
             "--targets", f"crapi={crapi_spec}",
             "--base-urls", f"crapi={TARGET_BASE_URLS['crapi']}",
             "--payloads", str(crapi_payloads),
             "--rules", str(RULES),
             "--results-dir", str(RESULTS_DIR),
             "--concurrency", "3"],
            extra_env=auth_env_for(tokens, "CRAPI_AUTH_HEADER"),
        )

        banner("4/4 RUNNING GRAPHQL FUZZING - DVGA")

        run_command(
            "GRAPHQL FUZZING - DVGA",
            [PYTHON, str(GRAPHQL_FUZZER),
             "--base-url", TARGET_BASE_URLS["dvga"],
             "--payloads", str(graphql_payloads),
             "--rules", str(RULES),
             "--results-dir", str(RESULTS_DIR),
             "--concurrency", "3"],
            extra_env=auth_env_for(tokens, "DVGA_AUTH_HEADER"),
        )

        banner("MAIN SECURITY PIPELINE COMPLETE")
        print("[+] VAmPI fuzzing : OK")
        print("[+] crAPI fuzzing : OK")
        print("[+] DVGA fuzzing  : OK")
        print()
        print("[+] MAIN OUTPUT DIRECTORY:")
        print(f"    {RESULTS_DIR}")
        print()
        print("[+] Main pipeline output:")
        print(f"    {RESULTS_DIR / 'vulnerabilities.csv'}")
        print(f"    {RESULTS_DIR / 'vulnerabilities.ndjson'}")
        print(f"    {RESULTS_DIR / 'experiment_runs.csv'}")
        print(f"    {RESULTS_DIR / 'state.json'}")
        print(f"    {RESULTS_DIR / 'state_graphql.json'}")
        print()
        print("[i] Legacy pipeline was NOT touched.")
        return 0

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        return 130
    except Exception as exc:
        print()
        print(f"[X] MAIN SECURITY PIPELINE FAILED: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
