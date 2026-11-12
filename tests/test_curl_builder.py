"""
tests/test_curl_builder.py — Unit tests cho core/curl_builder.py.
"""

from core.curl_builder import build_curl_command


def test_build_curl_basic_get():
    cmd = build_curl_command("GET", "https://api.example.com/users", params={"page": 1, "limit": 10})
    assert cmd.startswith("curl -i -s -X GET")
    assert '"https://api.example.com/users?page=1&limit=10"' in cmd


def test_build_curl_post_json():
    cmd = build_curl_command(
        "POST",
        "https://api.example.com/users",
        headers={"Authorization": "Bearer test-jwt"},
        json_data={"username": "admin", "role": "superuser"},
    )
    assert "-X POST" in cmd
    assert '-H "Authorization: Bearer test-jwt"' in cmd
    assert '-H "Content-Type: application/json"' in cmd
    assert "-d '{\"username\": \"admin\", \"role\": \"superuser\"}'" in cmd


def test_build_curl_insecure_flag():
    cmd = build_curl_command("GET", "https://internal.corp.local/api", insecure=True)
    assert " -k " in cmd


def test_build_curl_cookies_and_header_filtering():
    cmd = build_curl_command(
        "DELETE",
        "https://api.example.com/item/1",
        headers={"Content-Length": "123", "Host": "api.example.com", "X-Custom": "val"},
        cookies={"session_id": "abc123xyz"},
    )
    assert "-X DELETE" in cmd
    assert "Content-Length" not in cmd
    assert 'Host:' not in cmd
    assert '-H "X-Custom: val"' in cmd
    assert '-H "Cookie: session_id=abc123xyz"' in cmd


def test_build_curl_escaped_quotes_in_json():
    cmd = build_curl_command(
        "POST",
        "https://api.example.com/comment",
        json_data={"text": "It's a test's payload"},
    )
    assert "-d '{\"text\": \"It'\\''s a test'\\''s payload\"}'" in cmd
