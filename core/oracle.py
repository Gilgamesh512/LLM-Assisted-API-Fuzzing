from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

SQL_ERROR_EXPLICIT_KEYWORDS = [
    "sql syntax", "sqlstate", "unclosed quotation",
    "you have an error in your sql", "warning: pg_", "sqlexception",
    "syntax error at or near", "syntax error in sql",
    "sqlite3.operationalerror", "sqlite3.error", "mysql_fetch",
    "microsoft ole db provider for sql server", "odbc driver",
    "driver [{sql server}]", "postgresql query failed",
    "org.hibernate.exception", "ora-0", "ora-1",
]
DB_CONTEXT_KEYWORDS = ["sqlite", "mysql", "postgresql", "psql", "odbc", "oracle", "mariadb", "database"]
CLIENT_SYNTAX_HINTS = ["json syntax", "jsondecodeerror", "yaml syntax", "unexpected token in json", "invalid json", "syntax error in json"]

LEAK_KEYWORDS_STRICT = [
    "traceback (most recent call last)",
    "stack trace:",
    "stacktrace",
    "fatal error:",
    "uncaught exception",
    "system.exception",
    "java.lang.",
    "nullpointerexception",
    "internal server error",
]
ANOMALY_STATUS = {500, 502, 503, 504}
TIMEOUT_HINTS = ["timeout", "timed out", "read timeout"]
OAST_KEYWORDS = ["interactsh", "oast", "collaborator", "dns interaction", "out-of-band"]


def is_sql_error(evidence: str) -> bool:
    """Kiểm tra chính xác lỗi SQL, loại bỏ báo động giả từ JSON/Client syntax errors."""
    ev_lower = evidence.lower()
    # 1. Các từ khóa SQL tường minh
    if any(k in ev_lower for k in SQL_ERROR_EXPLICIT_KEYWORDS):
        return True
    # 2. Cặp từ khóa Database + error/syntax
    has_db = any(db in ev_lower for db in DB_CONTEXT_KEYWORDS)
    if has_db and any(err in ev_lower for err in ("syntax", "error", "warning", "fatal", "exception")):
        return True
    # 3. Nếu chỉ có 'syntax error' đơn thuần: kiểm tra xem có phải lỗi format JSON/YAML của client không
    if "syntax error" in ev_lower:
        if any(hint in ev_lower for hint in CLIENT_SYNTAX_HINTS) and not has_db:
            return False
        # Nếu có từ khóa sql syntax hoặc ngữ cảnh database
        return True
    return False


def is_server_leak(evidence: str, status: int | None = None) -> bool:
    """Kiểm tra rò rỉ stack trace/lỗi hệ thống, tránh báo động giả với từ 'exception' trong phản hồi 200/400 bình thường."""
    ev_lower = evidence.lower()
    if any(k in ev_lower for k in LEAK_KEYWORDS_STRICT):
        return True
    # Nếu là lỗi 5xx kèm chữ exception thì coi là leak
    if status in ANOMALY_STATUS and "exception" in ev_lower:
        return True
    return False


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


def classify_one(f: dict[str, Any], timing_threshold_ms: float = 4000.0) -> Classified:
    evidence = str(f.get("evidence", "")).lower()
    status = f.get("http_status")
    try:
        status = int(status) if status is not None else None
    except (TypeError, ValueError):
        status = None

    # 1. Matcher trúng chuẩn
    if f.get("confirmed"):
        return Classified(f, Signal.SUCCESS, "matcher trúng / signal xác nhận")

    # 2. Tương tác Out-of-band (OAST / Collaborator)
    if f.get("oast_confirmed") or any(k in evidence for k in OAST_KEYWORDS):
        return Classified(f, Signal.SUCCESS, "tương tác out-of-band (OAST)")

    # 3. Phân tích khác biệt quyền truy cập (BOLA / IDOR)
    if f.get("bola_detected") or f.get("differential_match"):
        return Classified(f, Signal.SUCCESS, "truy cập trái phép đối tượng (BOLA/IDOR)")

    # 4. Phân tích độ trễ phản hồi (Time-based Blind SQLi / ReDoS)
    resp_time = f.get("response_time_ms")
    if resp_time is not None:
        try:
            if float(resp_time) >= timing_threshold_ms:
                return Classified(f, Signal.ANOMALY, f"độ trễ bất thường ({resp_time}ms - time-based blind)")
        except (TypeError, ValueError):
            pass

    # 5. Rò rỉ thông báo lỗi cú pháp SQL (đã loại trừ báo động giả client syntax)
    if is_sql_error(evidence):
        return Classified(f, Signal.ANOMALY, "rò rỉ lỗi SQL trong response")

    # 6. Mã lỗi máy chủ nội bộ HTTP 5xx
    if status in ANOMALY_STATUS:
        return Classified(f, Signal.ANOMALY, f"HTTP {status}")

    # 7. Quá thời gian chờ (Timeout)
    if any(k in evidence for k in TIMEOUT_HINTS):
        return Classified(f, Signal.ANOMALY, "timeout")

    # 8. Rò rỉ Stack trace / Internal exception
    if is_server_leak(evidence, status):
        return Classified(f, Signal.ANOMALY, "rò rỉ lỗi/stack trace")

    return Classified(f, Signal.MISS, "không có tín hiệu bất thường")


def analyze(findings: list[dict[str, Any]], timing_threshold_ms: float = 4000.0) -> Analysis:
    return Analysis([classify_one(f, timing_threshold_ms=timing_threshold_ms) for f in findings])


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
    return "\n".join(lines)


__all__ = ["Signal", "Classified", "Analysis", "classify_one", "analyze", "summarize_for_llm", "is_sql_error", "is_server_leak"]
