"""Tests for email verification (if ENABLE_EMAIL_VERIFICATION)."""
import pytest
from datetime import timedelta
from unittest.mock import patch, AsyncMock

from app.core.config import settings
from tests.conftest import auth_header, create_test_user, login_user

pytestmark = pytest.mark.skipif(
    not settings.ENABLE_EMAIL_VERIFICATION,
    reason="ENABLE_EMAIL_VERIFICATION is disabled",
)


@pytest.mark.asyncio
async def test_send_verification_email(client):
    await create_test_user(client)
    tokens = await login_user(client)
    with patch("app.services.email_verification_service.send_verification_email", new_callable=AsyncMock):
        resp = await client.post(
            "/api/v1/auth/email/send-verification",
            headers=auth_header(tokens["access_token"]),
        )
    assert resp.status_code == 204


@pytest.mark.asyncio
async def test_verify_email(client):
    await create_test_user(client)
    tokens = await login_user(client)

    from app.core.security import create_signed_token, decode_access_token
    payload = decode_access_token(tokens["access_token"])
    user_id = payload["sub"]

    token = create_signed_token(subject=user_id, purpose="email_verification", expires_delta=timedelta(hours=24))

    resp = await client.get(f"/api/v1/auth/email/verify?token={token}")
    assert resp.status_code == 200
    assert resp.json()["detail"] == "Email verified successfully"


@pytest.mark.asyncio
async def test_verify_email_expired_token(client):
    await create_test_user(client)
    tokens = await login_user(client)

    from app.core.security import create_signed_token, decode_access_token
    payload = decode_access_token(tokens["access_token"])
    user_id = payload["sub"]

    # Negative expiry = already expired
    token = create_signed_token(subject=user_id, purpose="email_verification", expires_delta=timedelta(seconds=-1))

    resp = await client.get(f"/api/v1/auth/email/verify?token={token}")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_resend_throttle(client):
    """Max 3 resends per hour (Spec §4 Standard)."""
    await create_test_user(client)
    tokens = await login_user(client)
    headers = auth_header(tokens["access_token"])

    # Clear tracker
    from app.services.email_verification_service import _resend_tracker
    _resend_tracker.clear()

    with patch("app.services.email_verification_service.send_verification_email", new_callable=AsyncMock):
        for _ in range(3):
            resp = await client.post("/api/v1/auth/email/send-verification", headers=headers)
            assert resp.status_code == 204

        # 4th should be throttled
        resp = await client.post("/api/v1/auth/email/send-verification", headers=headers)
        assert resp.status_code == 422
