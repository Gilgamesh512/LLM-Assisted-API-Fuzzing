from __future__ import annotations

from core.oracle import Signal, classify_one


def test_classify_oast_interaction_is_success():
    finding = {
        "confirmed": False,
        "http_status": 200,
        "evidence": "Received DNS callback at xyz.oast.live via interactsh",
    }
    c = classify_one(finding)
    assert c.signal is Signal.SUCCESS
    assert "OAST" in c.reason


def test_classify_differential_bola_is_success():
    finding = {
        "confirmed": False,
        "http_status": 200,
        "bola_detected": True,
        "evidence": "Resource owned by user A returned to user B token",
    }
    c = classify_one(finding)
    assert c.signal is Signal.SUCCESS
    assert "BOLA/IDOR" in c.reason


def test_classify_timing_anomaly():
    finding = {
        "confirmed": False,
        "http_status": 200,
        "response_time_ms": 5200.0,
        "evidence": "Payload SLEEP(5) delayed response",
    }
    c = classify_one(finding, timing_threshold_ms=4000.0)
    assert c.signal is Signal.ANOMALY
    assert "độ trễ bất thường" in c.reason
