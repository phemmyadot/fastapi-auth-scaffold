"""Tests for audit logging (if ENABLE_AUDIT_LOGGING)."""
import pytest
from unittest.mock import patch, MagicMock, call

from app.core.config import settings
from tests.conftest import create_test_user, login_user

pytestmark = pytest.mark.skipif(
    not settings.ENABLE_AUDIT_LOGGING,
    reason="ENABLE_AUDIT_LOGGING is disabled",
)


@pytest.mark.asyncio
async def test_register_emits_audit_log(client):
    """Registration should emit a REGISTER audit event."""
    with patch("app.api.v1.auth.router.emit_audit_log") as mock_audit:
        await create_test_user(client)
        mock_audit.assert_called()
        event_types = [c.args[0].value for c in mock_audit.call_args_list]
        assert "register" in event_types


@pytest.mark.asyncio
async def test_login_success_emits_audit_log(client):
    with patch("app.api.v1.auth.router.emit_audit_log") as mock_audit:
        await create_test_user(client)
        mock_audit.reset_mock()
        await login_user(client)
        event_types = [c.args[0].value for c in mock_audit.call_args_list]
        assert "login_success" in event_types


@pytest.mark.asyncio
async def test_login_failed_emits_audit_log(client):
    with patch("app.api.v1.auth.router.emit_audit_log") as mock_audit:
        await create_test_user(client)
        mock_audit.reset_mock()
        await client.post("/api/v1/auth/login", json={
            "email": "test@example.com",
            "password": "WrongPassword!",
        })
        event_types = [c.args[0].value for c in mock_audit.call_args_list]
        assert "login_failed" in event_types


@pytest.mark.asyncio
async def test_logout_emits_audit_log(client):
    with patch("app.api.v1.auth.router.emit_audit_log") as mock_audit:
        await create_test_user(client)
        tokens = await login_user(client)
        mock_audit.reset_mock()
        await client.post("/api/v1/auth/logout", json={"refresh_token": tokens["refresh_token"]})
        event_types = [c.args[0].value for c in mock_audit.call_args_list]
        assert "logout" in event_types


@pytest.mark.asyncio
async def test_password_reset_request_emits_audit_log(client):
    from unittest.mock import AsyncMock
    with patch("app.api.v1.auth.router.emit_audit_log") as mock_audit, \
         patch("app.services.auth_service.send_password_reset_email", new_callable=AsyncMock):
        await create_test_user(client)
        mock_audit.reset_mock()
        await client.post("/api/v1/auth/password-reset/request", json={"email": "test@example.com"})
        event_types = [c.args[0].value for c in mock_audit.call_args_list]
        assert "password_reset_request" in event_types


@pytest.mark.asyncio
async def test_refresh_emits_audit_log(client):
    with patch("app.api.v1.auth.router.emit_audit_log") as mock_audit:
        await create_test_user(client)
        tokens = await login_user(client)
        mock_audit.reset_mock()
        await client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
        event_types = [c.args[0].value for c in mock_audit.call_args_list]
        assert "token_refreshed" in event_types
