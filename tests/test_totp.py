"""Tests for TOTP 2FA (if ENABLE_TOTP_2FA)."""
import pytest
from unittest.mock import patch

from app.core.config import settings
from tests.conftest import auth_header, create_test_user, login_user

pytestmark = pytest.mark.skipif(
    not settings.ENABLE_TOTP_2FA,
    reason="ENABLE_TOTP_2FA is disabled",
)


@pytest.mark.asyncio
async def test_totp_setup(client):
    await create_test_user(client)
    tokens = await login_user(client)
    resp = await client.post(
        "/api/v1/auth/totp/setup",
        headers=auth_header(tokens["access_token"]),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "secret" in data
    assert "otpauth_url" in data
    assert "qr_code_data_uri" in data
    assert len(data["backup_codes"]) == 8


@pytest.mark.asyncio
async def test_totp_enable(client):
    await create_test_user(client)
    tokens = await login_user(client)
    headers = auth_header(tokens["access_token"])

    # Setup
    setup_resp = await client.post("/api/v1/auth/totp/setup", headers=headers)
    secret = setup_resp.json()["secret"]

    # Generate valid TOTP code
    from app.core.totp import verify_totp_code
    import pyotp
    totp = pyotp.TOTP(secret)
    code = totp.now()

    resp = await client.post("/api/v1/auth/totp/enable", headers=headers, json={"totp_code": code})
    assert resp.status_code == 204


@pytest.mark.asyncio
async def test_totp_enable_invalid_code(client):
    await create_test_user(client)
    tokens = await login_user(client)
    headers = auth_header(tokens["access_token"])

    await client.post("/api/v1/auth/totp/setup", headers=headers)

    resp = await client.post("/api/v1/auth/totp/enable", headers=headers, json={"totp_code": "000000"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_two_step_login(client):
    """After TOTP is enabled, login should return a session_token challenge."""
    await create_test_user(client)
    tokens = await login_user(client)
    headers = auth_header(tokens["access_token"])

    # Setup + enable TOTP
    setup_resp = await client.post("/api/v1/auth/totp/setup", headers=headers)
    secret = setup_resp.json()["secret"]
    import pyotp
    totp = pyotp.TOTP(secret)
    await client.post("/api/v1/auth/totp/enable", headers=headers, json={"totp_code": totp.now()})

    # Login should now return TOTP challenge
    resp = await client.post("/api/v1/auth/login", json={
        "email": "test@example.com",
        "password": "TestPass123!",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data.get("requires_totp") is True
    assert "session_token" in data

    # Verify TOTP to get final tokens
    resp = await client.post("/api/v1/auth/totp/verify", json={
        "session_token": data["session_token"],
        "totp_code": totp.now(),
    })
    assert resp.status_code == 200
    assert "access_token" in resp.json()
    assert "refresh_token" in resp.json()


@pytest.mark.asyncio
async def test_backup_code_login(client):
    """Backup codes should work as alternative to TOTP."""
    await create_test_user(client)
    tokens = await login_user(client)
    headers = auth_header(tokens["access_token"])

    setup_resp = await client.post("/api/v1/auth/totp/setup", headers=headers)
    data = setup_resp.json()
    secret = data["secret"]
    backup_codes = data["backup_codes"]

    import pyotp
    totp = pyotp.TOTP(secret)
    await client.post("/api/v1/auth/totp/enable", headers=headers, json={"totp_code": totp.now()})

    # Login to get session token
    resp = await client.post("/api/v1/auth/login", json={
        "email": "test@example.com",
        "password": "TestPass123!",
    })
    session_token = resp.json()["session_token"]

    # Use backup code instead of TOTP
    resp = await client.post("/api/v1/auth/totp/verify", json={
        "session_token": session_token,
        "totp_code": backup_codes[0],
    })
    assert resp.status_code == 200
    assert "access_token" in resp.json()


@pytest.mark.asyncio
async def test_totp_disable(client):
    await create_test_user(client)
    tokens = await login_user(client)
    headers = auth_header(tokens["access_token"])

    # Setup + enable
    setup_resp = await client.post("/api/v1/auth/totp/setup", headers=headers)
    secret = setup_resp.json()["secret"]
    import pyotp
    totp = pyotp.TOTP(secret)
    await client.post("/api/v1/auth/totp/enable", headers=headers, json={"totp_code": totp.now()})

    # Disable
    resp = await client.post("/api/v1/auth/totp/disable", headers=headers, json={
        "password": "TestPass123!",
        "totp_code": totp.now(),
    })
    assert resp.status_code == 204

    # Login should no longer require TOTP
    resp = await client.post("/api/v1/auth/login", json={
        "email": "test@example.com",
        "password": "TestPass123!",
    })
    assert resp.status_code == 200
    assert "access_token" in resp.json()
    assert "requires_totp" not in resp.json()
