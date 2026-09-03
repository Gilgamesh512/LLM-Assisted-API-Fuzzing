#!/usr/bin/env python3

import os
import subprocess
import sys
import time


PATHS = {
    "vampi": os.path.expanduser("~/VAmPI"),
    "crapi": os.path.expanduser("~/crAPI"),
    "dvga": os.path.expanduser(
        "~/Damn-Vulnerable-GraphQL-Application"
    ),
}


def run_cmd(cmd, cwd=None, show_output=False):
    """
    Run shell command.
    """

    if show_output:
        result = subprocess.run(
            cmd,
            shell=True,
            cwd=cwd,
        )
    else:
        result = subprocess.run(
            cmd,
            shell=True,
            cwd=cwd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    return result.returncode


# ============================================================
# VAmPI
# ============================================================

def start_vampi():

    print("\n" + "=" * 60)
    print("[VAmPI]")
    print("=" * 60)

    path = PATHS["vampi"]

    if not os.path.isdir(path):

        print(
            f"[X] Không tìm thấy VAmPI: {path}"
        )

        return False

    print(
        "[*] Stopping old containers..."
    )

    run_cmd(
        "sudo docker-compose down -v",
        cwd=path,
    )

    print(
        "[*] Starting VAmPI..."
    )

    result = run_cmd(
        "sudo docker-compose up -d",
        cwd=path,
        show_output=True,
    )

    if result != 0:

        print(
            "[X] VAmPI startup failed."
        )

        return False

    print(
        "[+] VAmPI containers started."
    )

    # Give Flask a moment.
    time.sleep(3)

    print(
        "[*] Initializing VAmPI database..."
    )

    result = run_cmd(
        "curl -s http://localhost:5002/createdb",
    )

    if result != 0:

        print(
            "[!] /createdb returned an error."
        )

    else:

        print(
            "[+] VAmPI database initialized."
        )

    return True


# ============================================================
# crAPI
# ============================================================

def start_crapi():

    print("\n" + "=" * 60)
    print("[crAPI]")
    print("=" * 60)

    path = PATHS["crapi"]

    if not os.path.isdir(path):

        print(
            f"[X] Không tìm thấy crAPI: {path}"
        )

        return False

    print(
        "[*] Stopping old crAPI stack..."
    )

    run_cmd(
        "sudo docker-compose down -v",
        cwd=path,
    )

    print(
        "[*] Starting crAPI..."
    )

    result = run_cmd(
        "sudo docker-compose up -d",
        cwd=path,
        show_output=True,
    )

    if result != 0:

        print(
            "[X] crAPI startup failed."
        )

        return False

    print(
        "[+] crAPI microservices started."
    )

    return True


# ============================================================
# DVGA
# ============================================================

def start_dvga():

    print("\n" + "=" * 60)
    print("[DVGA]")
    print("=" * 60)

    path = PATHS["dvga"]

    if not os.path.isdir(path):

        print(
            f"[X] Không tìm thấy DVGA: {path}"
        )

        return False

    print(
        "[*] Removing old DVGA container..."
    )

    run_cmd(
        "sudo docker stop dvga"
    )

    run_cmd(
        "sudo docker rm dvga"
    )

    print(
        "[*] Building DVGA image..."
    )

    result = run_cmd(
        "sudo docker build -t dvga .",
        cwd=path,
        show_output=True,
    )

    if result != 0:

        print(
            "[X] DVGA build failed."
        )

        return False

    print(
        "[*] Starting DVGA..."
    )

    result = run_cmd(
        (
            "sudo docker run -d "
            "-p 5013:5013 "
            "-e WEB_HOST=0.0.0.0 "
            "--name dvga "
            "dvga"
        ),
        show_output=True,
    )

    if result != 0:

        print(
            "[X] DVGA startup failed."
        )

        return False

    print(
        "[+] DVGA container started."
    )

    return True


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 60)
    print(" START LAB")
    print("=" * 60)

    results = {}

    results["vampi"] = start_vampi()
    results["crapi"] = start_crapi()
    results["dvga"] = start_dvga()

    print("\n" + "=" * 60)
    print(" LAB STARTUP STATUS")
    print("=" * 60)

    for target, status in results.items():

        if status:
            print(
                f"[+] {target.upper():<8} READY"
            )
        else:
            print(
                f"[X] {target.upper():<8} FAILED"
            )

    if not all(results.values()):

        print(
            "\n[X] Một hoặc nhiều target không start được."
        )

        sys.exit(1)

    print(
        "\n[+] ALL TARGETS STARTED."
    )

    sys.exit(0)


if __name__ == "__main__":
    main()
