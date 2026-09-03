from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

SQL_ERROR_KEYWORDS = [
    "sql syntax", "syntax error", "sqlstate", "sqlite", "mysql",
    "postgresql", "psql", "odbc", "ora-", "unclosed quotation",
    "you have an error in your sql", "warning: pg_", "sqlexception",
]
LEAK_KEYWORDS = ["traceback", "stack trace", "exception", "internal server error"]
ANOMALY_STATUS = {500, 502, 503, 504}
TIMEOUT_HINTS = ["timeout", "timed out", "read timeout"]


class Signal(str, Enum):
    SUCCESS = "success"
    ANOMALY = "anomaly"
    MISS = "miss"


@dataclass
class Classified:
    finding: dict[str, Any]
    signal: Signal
    reason: str


@dataclass
class Analysis:
    classified: list[Classified]

    @property
    def successes(self) -> list[Classified]:
        return [c for c in self.classified if c.signal is Signal.SUCCESS]

    @property
    def anomalies(self) -> list[Classified]:
        return [c for c in self.classified if c.signal is Signal.ANOMALY]

    @property
    def misses(self) -> list[Classified]:
        return [c for c in self.classified if c.signal is Signal.MISS]

    @property
    def exploited(self) -> bool:
        return len(self.successes) > 0

    def has_signal(self) -> bool:
        return bool(self.successes or self.anomalies)

    def hits(self) -> list[dict[str, Any]]:
        return [c.finding for c in (self.successes + self.anomalies)]


def classify_one(f: dict[str, Any]) -> Classified:
    evidence = str(f.get("evidence", "")).lower()
    status = f.get("http_status")
    try:
        status = int(status) if status is not None else None
    except (TypeError, ValueError):
        status = None

    if f.get("confirmed"):
        return Classified(f, Signal.SUCCESS, "matcher trúng / signal xác nhận")
    if any(k in evidence for k in SQL_ERROR_KEYWORDS):
        return Classified(f, Signal.ANOMALY, "rò rỉ lỗi SQL trong response")
    if status in ANOMALY_STATUS:
        return Classified(f, Signal.ANOMALY, f"HTTP {status}")
    if any(k in evidence for k in TIMEOUT_HINTS):
        return Classified(f, Signal.ANOMALY, "timeout")
    if any(k in evidence for k in LEAK_KEYWORDS):
        return Classified(f, Signal.ANOMALY, "rò rỉ lỗi/stack trace")
    return Classified(f, Signal.MISS, "không có tín hiệu bất thường")


def analyze(findings: list[dict[str, Any]]) -> Analysis:
    return Analysis([classify_one(f) for f in findings])


def _fmt(c: Classified) -> str:
    f = c.finding
    return f"{f.get('vuln_type', '?')} @ {f.get('method', '')} {f.get('endpoint', '?')} -> {c.reason}"


def summarize_for_llm(analysis: Analysis, max_examples: int = 5) -> str:
    hits = analysis.successes + analysis.anomalies
    lines: list[str] = []
    lines.append(
        f"KẾT QUẢ THẾ HỆ TRƯỚC: {len(analysis.successes)} khai thác thành công, "
        f"{len(analysis.anomalies)} bất thường (500/timeout/lỗi rò rỉ), {len(analysis.misses)} không trúng."
    )
    if hits:
        lines.append("PAYLOAD ĐÃ TẠO TÍN HIỆU (ưu tiên tạo biến thể tương tự — shared bugs):")
        for c in hits[:max_examples]:
            lines.append(f"  - {_fmt(c)}")
    if analysis.misses:
        lines.append("PAYLOAD KHÔNG TRÚNG (đổi kỹ thuật/encoding khác, đừng lặp lại y hệt):")
        for c in analysis.misses[:max_examples]:
            lines.append(f"  - {_fmt(c)}")
    lines.append(
        "HÃY SINH THẾ HỆ PAYLOAD MỚI: giữ & biến hóa các payload đã trúng, thay các payload "
        "không trúng bằng kỹ thuật/encoding khác. Chỉ trả JSON theo đúng schema."
    )
    return "\n".join(lines)
