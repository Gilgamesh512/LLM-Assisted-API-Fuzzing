from __future__ import annotations

from core.validator import (
    AttackPayload,
    ParamLocation,
    VulnerabilityType,
    convert_attack_payload_to_fuzz,
    convert_fuzz_to_attack_payload,
)


def test_convert_attack_payload_to_fuzz():
    payload = AttackPayload(
        method="POST",
        path="/identity/api/auth/login",
        target_parameter="email",
        location=ParamLocation.BODY,
        vulnerability_type=VulnerabilityType.SQLI,
        payload_value="admin' OR '1'='1",
        rationale="SQLi via login body",
        expected_indicator="sql syntax error, 500",
    )
    fuzz = convert_attack_payload_to_fuzz(payload, target_app="crapi")
    assert fuzz["endpoint"] == "/identity/api/auth/login"
    assert fuzz["method"] == "POST"
    assert fuzz["target_param"] == "email"
    assert fuzz["param_location"] == "body"
    assert fuzz["attack_type"] == "SQL_INJECTION"
    assert fuzz["payload_value"] == "admin' OR '1'='1"
    assert fuzz["target_app"] == "crapi"
    assert "sql syntax error" in fuzz["expected_signal"]


def test_convert_fuzz_to_attack_payload():
    fuzz = {
        "endpoint": "/community/api/v2/community/posts/{postId}",
        "method": "GET",
        "target_param": "postId",
        "param_location": "path",
        "attack_type": "BOLA",
        "payload_value": "9999",
        "context": "Try accessing another user post",
        "expected_signal": ["author", "content"],
    }
    ap = convert_fuzz_to_attack_payload(fuzz)
    assert ap.path == "/community/api/v2/community/posts/{postId}"
    assert ap.method == "GET"
    assert ap.target_parameter == "postId"
    assert ap.location == ParamLocation.PATH
    assert ap.vulnerability_type == VulnerabilityType.BOLA
    assert ap.payload_value == "9999"
