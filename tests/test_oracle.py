from __future__ import annotations

from core import oracle
from core.oracle import Signal


def test_confirmed_is_success():
    c = oracle.classify_one({"confirmed": True, "http_status": 200, "evidence": "matcher hit"})
    assert c.signal is Signal.SUCCESS


def test_sql_error_leak_is_anomaly():
    c = oracle.classify_one({"confirmed": False, "http_status": 200, "evidence": "you have an error in your SQL syntax"})
    assert c.signal is Signal.ANOMALY


def test_http_500_is_anomaly():
    c = oracle.classify_one({"confirmed": False, "http_status": 500, "evidence": ""})
    assert c.signal is Signal.ANOMALY


def test_timeout_is_anomaly():
    c = oracle.classify_one({"confirmed": False, "http_status": None, "evidence": "read timeout after 10s"})
    assert c.signal is Signal.ANOMALY


def test_plain_200_is_miss():
    c = oracle.classify_one({"confirmed": False, "http_status": 200, "evidence": "HTTP 200 ok"})
    assert c.signal is Signal.MISS


def test_analyze_flags():
    a = oracle.analyze([
        {"confirmed": True, "evidence": "hit"},
        {"confirmed": False, "http_status": 500, "evidence": ""},
        {"confirmed": False, "http_status": 200, "evidence": "ok"},
    ])
    assert a.exploited is True
    assert a.has_signal() is True
    assert len(a.successes) == 1 and len(a.anomalies) == 1 and len(a.misses) == 1
    assert len(a.hits()) == 2


def test_summarize_mentions_counts():
    a = oracle.analyze([{"confirmed": False, "http_status": 500, "evidence": "", "vuln_type": "SQLI", "endpoint": "/x"}])
    txt = oracle.summarize_for_llm(a)
    assert "bất thường" in txt and "/x" in txt
