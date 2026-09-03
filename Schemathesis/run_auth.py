#!/usr/bin/env python3
"""REST authentication helper for VAmPI and crAPI.

This script owns ONLY REST authentication. It writes/updates tokens.env with:
    VAMPI_AUTH_HEADER
    CRAPI_AUTH_HEADER

It deliberately does not authenticate DVGA; DVGA authentication is handled by
run_dvga.py because DVGA exposes login as a GraphQL mutation.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import requests

BASE_DIR = Path(__file__).resolve().parent
ENV_FILE = BASE_DIR / "tokens.env"
MAX_RETRIES = 12
RETRY_DELAY = 5

TARGETS = {
    "vampi": {
        "base_url": "http://localhost:5002",
        "login_url": "http://localhost:5002/users/v1/login",
        "register_url": "http://localhost:5002/users/v1/register",
        "creds": {"username": "pentester_auto", "password": "password123"},
        "register_payload": {
            "username": "pentester_auto",
            "password": "password123",
            "email": "pentester_auto@example.com",
        },
    },
    "crapi": {
        "base_url": "http://localhost:8888",
        "login_url": "http://localhost:8888/identity/api/auth/login",
        "register_url": "http://localhost:8888/identity/api/auth/signup",
        "creds": {
            "email": "pentester_auto_2026@example.com",
            "password": "Password123!",
        },
        "register_payload": {
            "name": "Pentester Auto",
            "email": "pentester_auto_2026@example.com",
            "number": "0901234568",
            "password": "Password123!",
        },
    },
}


def get_json(response: requests.Response) -> dict:
    try:
        data = response.json()
        return data if isinstance(data, dict) else {}
    except ValueError:
        return {}


def wait_for_service(name: str, url: str) -> bool:
    print(f"\n[*] Waiting for {name.upper()}...")
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.get(url, timeout=5)
            print(f"    [+] HTTP {response.status_code}")
            return True
        except requests.RequestException:
            print(f"    [-] Not ready ({attempt}/{MAX_RETRIES})")
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)
    return False


def register_account(name: str, config: dict) -> bool:
    print(f"\n[*] {name.upper()} REGISTER")
    try:
        response = requests.post(
            config["register_url"],
            json=config["register_payload"],
            timeout=10,
        )
    except requests.RequestException as exc:
        print(f"    [X] Connection error: {exc}")
        return False

    data = get_json(response)
    if 200 <= response.status_code < 300:
        print(f"    [+] Account created (HTTP {response.status_code})")
        return True

    message = str(data.get("message", "")).lower()
    if response.status_code in (400, 403, 409) and any(
        text in message for text in ("already registered", "already exists")
    ):
        print("    [!] Account already exists -> continue to login.")
        return True

    # Some APIs return a non-standard duplicate response. Login is authoritative,
    # so don't prevent authentication solely because registration was rejected.
    if response.status_code in (400, 409):
        print("    [!] Registration was rejected; attempting login anyway.")
        return True

    print(f"    [X] Registration failed (HTTP {response.status_code})")
    print(f"    Response: {data}")
    return False


def login(name: str, config: dict) -> str | None:
    print(f"\n[*] {name.upper()} LOGIN")

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.post(
                config["login_url"],
                json=config["creds"],
                timeout=10,
            )
        except requests.RequestException as exc:
            print(f"    [-] Connection error ({attempt}/{MAX_RETRIES}): {exc}")
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)
            continue

        data = get_json(response)

        if response.status_code == 200:
            token = (
                data.get("token")
                or data.get("access_token")
                or data.get("auth_token")
            )
            if token:
                print("    [+] LOGIN SUCCESS")
                return str(token)
            print("    [X] HTTP 200 but no token was found.")
            print(f"    Response keys: {sorted(data.keys())}")
            return None

        if response.status_code == 401:
            print("    [X] Invalid credentials.")
            return None

        if response.status_code == 404:
            print(f"    [X] Login endpoint not found: {config['login_url']}")
            return None

        if 500 <= response.status_code < 600:
            print(f"    [-] Server error {response.status_code} ({attempt}/{MAX_RETRIES})")
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)
            continue

        print(f"    [X] Unexpected HTTP {response.status_code}")
        print(f"    Response: {data}")
        return None

    return None


def authenticate(name: str, config: dict) -> str | None:
    if not wait_for_service(name, config["base_url"]):
        return None

    register_account(name, config)
    return login(name, config)


def _read_env_lines() -> list[str]:
    if not ENV_FILE.exists():
        return []
    return ENV_FILE.read_text(encoding="utf-8").splitlines()


def update_tokens_env(values: dict[str, str]) -> None:
    """Merge REST auth headers into tokens.env without deleting DVGA token."""
    lines = _read_env_lines()
    output: list[str] = []
    written: set[str] = set()

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("export ") and "=" in stripped:
            key = stripped[len("export "):].split("=", 1)[0].strip()
            if key in values:
                output.append(f'export {key}="{values[key]}"')
                written.add(key)
                continue
        output.append(line)

    if output and output[-1].strip():
        output.append("")

    for key, value in values.items():
        if key not in written:
            output.append(f'export {key}="{value}"')

    ENV_FILE.write_text("\n".join(output).rstrip() + "\n", encoding="utf-8")
    try:
        os.chmod(ENV_FILE, 0o600)
    except OSError:
        pass


def main() -> int:
    print("=" * 60)
    print(" REST AUTHENTICATION — VAmPI + crAPI")
    print("=" * 60)

    headers: dict[str, str] = {}
    failures: list[str] = []

    for name, config in TARGETS.items():
        token = authenticate(name, config)
        if token:
            headers[f"{name.upper()}_AUTH_HEADER"] = f"Authorization: Bearer {token}"
        else:
            failures.append(name)

    update_tokens_env(headers)

    print("\n" + "=" * 60)
    print(" REST AUTH STATUS")
    print("=" * 60)
    for name in TARGETS:
        key = f"{name.upper()}_AUTH_HEADER"
        print(f"[{ '+' if key in headers else 'X' }] {name.upper():<8} TOKEN READY" if key in headers
              else f"[X] {name.upper():<8} TOKEN FAILED")

    print(f"\n[+] Updated: {ENV_FILE}")
    if failures:
        print("[X] Authentication failed for: " + ", ".join(failures))
        return 1

    print("[+] REST authentication complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
