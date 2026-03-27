"""Tests for phone OTP verification (if ENABLE_PHONE_VERIFICATION)."""
import pytest
from unittest.mock import patch, MagicMock

from app.core.config import settings
from tests.conftest import auth_header, create_test_user, login_user

pytestmark = pytest.mark.skipif(
    not settings.ENABLE_PHONE_VERIFICATION,
    reason="ENABLE_PHONE_VERIFICATION is disabled",
)


@pytest.mark.asyncio
async def test_send_otp(client):
    await create_test_user(client)
    tokens = await login_user(client)
    with patch("app.services.phone_verification_service.send_sms"):
        resp = await client.post(
            "/api/v1/auth/phone/send-otp",
            headers=auth_header(tokens["access_token"]),
            json={"phone_number": "+15551234567"},
        )
    assert resp.status_code == 204


@pytest.mark.asyncio
async def test_verify_otp_success(client):
    await create_test_user(client)
    tokens = await login_user(client)
    headers = auth_header(tokens["access_token"])

    # Inject known OTP
    from app.core.security import decode_access_token, hash_token
    from app.services.phone_verification_service import _otp_store
    from datetime import datetime, timedelta, timezone

    payload = decode_access_token(tokens["access_token"])
    user_id = payload["sub"]
    known_otp = "123456"
    _otp_store[user_id] = (hash_token(known_otp), datetime.now(timezone.utc) + timedelta(minutes=10))

    resp = await client.post(
        "/api/v1/auth/phone/verify-otp",
        headers=headers,
        json={"otp_code": known_otp},
    )
    assert resp.status_code == 200
    assert resp.json()["detail"] == "Phone verified successfully"


@pytest.mark.asyncio
async def test_verify_otp_expired(client):
    await create_test_user(client)
    tokens = await login_user(client)
    headers = auth_header(tokens["access_token"])

    from app.core.security import decode_access_token, hash_token
    from app.services.phone_verification_service import _otp_store
    from datetime import datetime, timedelta, timezone

    payload = decode_access_token(tokens["access_token"])
    user_id = payload["sub"]
    _otp_store[user_id] = (hash_token("123456"), datetime.now(timezone.utc) - timedelta(minutes=1))

    resp = await client.post(
        "/api/v1/auth/phone/verify-otp",
        headers=headers,
        json={"otp_code": "123456"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_otp_single_use(client):
    """OTP should be consumed after first use."""
    await create_test_user(client)
    tokens = await login_user(client)
    headers = auth_header(tokens["access_token"])

    from app.core.security import decode_access_token, hash_token
    from app.services.phone_verification_service import _otp_store
    from datetime import datetime, timedelta, timezone

    payload = decode_access_token(tokens["access_token"])
    user_id = payload["sub"]
    _otp_store[user_id] = (hash_token("654321"), datetime.now(timezone.utc) + timedelta(minutes=10))

    # First use succeeds
    resp = await client.post("/api/v1/auth/phone/verify-otp", headers=headers, json={"otp_code": "654321"})
    assert resp.status_code == 200

    # Second use fails
    resp = await client.post("/api/v1/auth/phone/verify-otp", headers=headers, json={"otp_code": "654321"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_send_otp_rate_limit(client):
    """Max 3 sends per hour per number (Spec §4 Standard)."""
    await create_test_user(client)
    tokens = await login_user(client)
    headers = auth_header(tokens["access_token"])

    from app.services.phone_verification_service import _send_tracker
    _send_tracker.clear()

    with patch("app.services.phone_verification_service.send_sms"):
        for _ in range(3):
            resp = await client.post(
                "/api/v1/auth/phone/send-otp", headers=headers, json={"phone_number": "+15559999999"}
            )
            assert resp.status_code == 204

        # 4th should be throttled
        resp = await client.post(
            "/api/v1/auth/phone/send-otp", headers=headers, json={"phone_number": "+15559999999"}
        )
        assert resp.status_code == 422
