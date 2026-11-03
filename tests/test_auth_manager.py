from __future__ import annotations

from unittest.mock import Mock

from core.auth_manager import TokenManager


def test_token_manager_static_token():
    mgr = TokenManager(auth_type="static", static_token="my-static-token")
    assert not mgr.is_expired
    assert mgr.get_token() == "my-static-token"
    assert mgr.get_headers() == {"Authorization": "Bearer my-static-token"}


def test_token_manager_login_and_auto_refresh():
    mock_session = Mock()
    mock_resp = Mock()
    mock_resp.ok = True
    mock_resp.json.return_value = {"token": "refreshed_jwt_123"}
    mock_session.post.return_value = mock_resp

    mgr = TokenManager(
        auth_type="login",
        login_url="http://auth.local/login",
        credentials={"user": "admin", "pass": "secret"},
        ttl_seconds=300,
    )

    token = mgr.get_token(session=mock_session)
    assert token == "refreshed_jwt_123"
    assert mgr.get_headers(session=mock_session) == {"Authorization": "Bearer refreshed_jwt_123"}
    assert mock_session.post.called


def test_token_manager_handles_401():
    mock_session = Mock()
    mock_resp = Mock()
    mock_resp.ok = True
    mock_resp.json.return_value = {"token": "renewed_token_456"}
    mock_session.post.return_value = mock_resp

    mgr = TokenManager(
        auth_type="login",
        login_url="http://auth.local/login",
    )

    resp_401 = Mock()
    resp_401.status_code = 401

    should_retry = mgr.handle_response(resp_401, session=mock_session)
    assert should_retry is True
    assert mgr._current_token == "renewed_token_456"
