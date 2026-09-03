from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

logger = logging.getLogger("executor.nuclei_runner")


class NucleiNotFoundError(RuntimeError):
    """Nuclei chưa được cài / không có trên PATH."""


class NucleiRunResult:
    """Gói kết quả 1 lần chạy Nuclei."""

    def __init__(
        self,
        findings: list[dict[str, Any]],
        returncode: int,
        stderr: str,
        timed_out: bool = False,
    ) -> None:
        self.findings = findings
        self.returncode = returncode
        self.stderr = stderr
        self.timed_out = timed_out


def ensure_nuclei(binary: str = "nuclei") -> str:
    """Trả về đường dẫn nuclei hoặc raise lỗi thân thiện.

    Thứ tự tìm: biến môi trường ``NUCLEI_BIN`` (đường dẫn tuyệt đối) -> PATH.
    Dùng ``NUCLEI_BIN`` khi nuclei không nằm trên PATH (vd chạy qua WSL).
    """
    env_bin = os.environ.get("NUCLEI_BIN")
    if env_bin:
        p = Path(env_bin).expanduser()
        if p.is_file():
            return str(p)
        raise NucleiNotFoundError(f"NUCLEI_BIN trỏ tới file không tồn tại: {env_bin}")

    path = shutil.which(binary)
    if not path:
        raise NucleiNotFoundError(
            "Không tìm thấy 'nuclei' trên PATH (và chưa đặt NUCLEI_BIN). Cài đặt: "
            "https://github.com/projectdiscovery/nuclei/releases "
            "hoặc `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`."
        )
    return path


def build_command(
    template_dir: str | Path,
    target: str,
    out_file: str | Path,
    *,
    binary: str = "nuclei",
    rate_limit: int = 50,
    req_timeout: int = 10,
    retries: int = 1,
    include_rr: bool = True,
) -> list[str]:
    """Dựng argv cho Nuclei. Không dùng chuỗi/shell.

    ``include_rr`` thêm ``-include-rr`` để output có request/response, phục vụ
    trích ``response_status`` và ``evidence``.
    """
    cmd = [
        binary,
        "-t", str(template_dir),
        "-u", target,
        "-jsonl", "-o", str(out_file),
        "-silent",
        "-disable-update-check",
        "-timeout", str(req_timeout),
        "-retries", str(retries),
        "-rate-limit", str(rate_limit),
    ]
    if include_rr:
        cmd.append("-include-rr")
    return cmd


def _read_jsonl(out_file: Path) -> list[dict[str, Any]]:
    if not out_file.exists():
        return []
    findings: list[dict[str, Any]] = []
    for line in out_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            logger.warning("Bỏ qua dòng JSONL không parse được: %.120s", line)
    return findings


def run_nuclei(
    template_dir: str | Path,
    target: str,
    *,
    timeout: int = 120,
    binary: str = "nuclei",
    rate_limit: int = 50,
    req_timeout: int = 10,
    retries: int = 1,
    include_rr: bool = True,
) -> NucleiRunResult:
    """Chạy Nuclei 1 lần trên toàn bộ template trong ``template_dir``.

    Nuclei trả 0 kể cả khi không match; ta căn cứ file kết quả + stderr, không
    dựa vào returncode để suy ra "có lỗ hổng".
    """
    resolved = ensure_nuclei(binary)
    template_dir = Path(template_dir)
    out_file = template_dir / "results.jsonl"

    cmd = build_command(
        template_dir,
        target,
        out_file,
        binary=resolved,
        rate_limit=rate_limit,
        req_timeout=req_timeout,
        retries=retries,
        include_rr=include_rr,
    )
    logger.info("Chạy Nuclei: %s", " ".join(cmd))

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        logger.error("Nuclei timeout sau %ss", timeout)
        partial = _read_jsonl(out_file)
        return NucleiRunResult(partial, returncode=-1, stderr=str(exc), timed_out=True)

    if proc.stderr.strip():
        logger.debug("Nuclei stderr: %s", proc.stderr.strip())

    findings = _read_jsonl(out_file)
    return NucleiRunResult(findings, returncode=proc.returncode, stderr=proc.stderr)


def validate_templates(template_dir: str | Path, *, binary: str = "nuclei") -> tuple[bool, str]:
    """Chạy ``nuclei -validate`` để kiểm tra template hợp lệ.

    Trả về (ok, output). Hữu ích trong CI / test tích hợp nhẹ.
    """
    ensure_nuclei(binary)
    cmd = [binary, "-t", str(template_dir), "-validate", "-disable-update-check"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
    except subprocess.TimeoutExpired as exc:
        return False, f"validate timeout: {exc}"
    ok = proc.returncode == 0
    return ok, (proc.stdout + proc.stderr).strip()
