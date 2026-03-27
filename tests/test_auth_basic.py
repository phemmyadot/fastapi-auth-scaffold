"""Tests for basic auth: register, login, refresh, logout, logout-all, password reset, lockout."""
import pytest
import pytest_asyncio
from unittest.mock import patch, AsyncMock

from tests.conftest import auth_header, create_test_user, login_user


@pytest.mark.asyncio
async def test_register_success(client):
    resp = await client.post("/api/v1/auth/register", json={
        "email": "new@example.com",
        "password": "StrongPass1!",
        "username": "newuser",
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["email"] == "new@example.com"
    assert data["username"] == "newuser"
    assert "id" in data


@pytest.mark.asyncio
async def test_register_duplicate_email(client):
    await create_test_user(client, email="dup@example.com")
    resp = await client.post("/api/v1/auth/register", json={
        "email": "dup@example.com",
        "password": "StrongPass1!",
    })
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_register_duplicate_username(client):
    await create_test_user(client, email="u1@example.com", username="taken")
    resp = await client.post("/api/v1/auth/register", json={
        "email": "u2@example.com",
        "password": "StrongPass1!",
        "username": "taken",
    })
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_register_short_password(client):
    resp = await client.post("/api/v1/auth/register", json={
        "email": "short@example.com",
        "password": "abc",
    })
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_login_success(client):
    await create_test_user(client)
    tokens = await login_user(client)
    assert "access_token" in tokens
    assert "refresh_token" in tokens
    assert tokens["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_login_wrong_password(client):
    await create_test_user(client)
    resp = await client.post("/api/v1/auth/login", json={
        "email": "test@example.com",
        "password": "WrongPassword!",
    })
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_login_nonexistent_user(client):
    resp = await client.post("/api/v1/auth/login", json={
        "email": "nobody@example.com",
        "password": "whatever123!",
    })
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_login_identical_error_messages(client):
    """Spec §8: same error for wrong email vs wrong password (prevent enumeration)."""
    await create_test_user(client)
    resp_wrong_email = await client.post("/api/v1/auth/login", json={
        "email": "nobody@example.com",
        "password": "whatever123!",
    })
    resp_wrong_pass = await client.post("/api/v1/auth/login", json={
        "email": "test@example.com",
        "password": "WrongPassword!",
    })
    assert resp_wrong_email.json()["detail"] == resp_wrong_pass.json()["detail"]


@pytest.mark.asyncio
async def test_refresh_token(client):
    await create_test_user(client)
    tokens = await login_user(client)
    resp = await client.post("/api/v1/auth/refresh", json={
        "refresh_token": tokens["refresh_token"],
    })
    assert resp.status_code == 200
    new_tokens = resp.json()
    assert new_tokens["access_token"] != tokens["access_token"]
    assert new_tokens["refresh_token"] != tokens["refresh_token"]


@pytest.mark.asyncio
async def test_refresh_token_rotation_invalidates_old(client):
    """After rotation, the old refresh token should be invalid."""
    await create_test_user(client)
    tokens = await login_user(client)
    old_refresh = tokens["refresh_token"]

    # Rotate
    await client.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh})

    # Old token should fail
    resp = await client.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_refresh_invalid_token(client):
    resp = await client.post("/api/v1/auth/refresh", json={
        "refresh_token": "totally-invalid-token",
    })
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_logout(client):
    await create_test_user(client)
    tokens = await login_user(client)
    resp = await client.post("/api/v1/auth/logout", json={
        "refresh_token": tokens["refresh_token"],
    })
    assert resp.status_code == 204

    # Refresh should now fail
    resp = await client.post("/api/v1/auth/refresh", json={
        "refresh_token": tokens["refresh_token"],
    })
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_logout_all(client):
    await create_test_user(client)
    tokens1 = await login_user(client)
    tokens2 = await login_user(client)

    resp = await client.post(
        "/api/v1/auth/logout-all",
        headers=auth_header(tokens1["access_token"]),
    )
    assert resp.status_code == 204

    # Both refresh tokens should be invalid
    assert (await client.post("/api/v1/auth/refresh", json={"refresh_token": tokens1["refresh_token"]})).status_code == 401
    assert (await client.post("/api/v1/auth/refresh", json={"refresh_token": tokens2["refresh_token"]})).status_code == 401


@pytest.mark.asyncio
async def test_password_reset_request(client):
    await create_test_user(client)
    with patch("app.services.auth_service.send_password_reset_email", new_callable=AsyncMock):
        resp = await client.post("/api/v1/auth/password-reset/request", json={
            "email": "test@example.com",
        })
    assert resp.status_code == 204


@pytest.mark.asyncio
async def test_password_reset_no_enumeration(client):
    """Password reset always returns 204 even for unknown emails (Spec §8)."""
    with patch("app.services.auth_service.send_password_reset_email", new_callable=AsyncMock):
        resp = await client.post("/api/v1/auth/password-reset/request", json={
            "email": "nobody@example.com",
        })
    assert resp.status_code == 204


@pytest.mark.asyncio
async def test_password_reset_confirm(client):
    await create_test_user(client)
    from app.core.security import create_signed_token
    from datetime import timedelta
    from app.db.repositories.user_repo import UserRepository

    # Get user id
    user_data = await login_user(client)
    from app.core.security import decode_access_token
    payload = decode_access_token(user_data["access_token"])
    user_id = payload["sub"]

    token = create_signed_token(subject=user_id, purpose="password_reset", expires_delta=timedelta(hours=1))

    resp = await client.post("/api/v1/auth/password-reset/confirm", json={
        "token": token,
        "new_password": "NewSecurePass1!",
    })
    assert resp.status_code == 204

    # Old password should fail
    resp = await client.post("/api/v1/auth/login", json={
        "email": "test@example.com",
        "password": "TestPass123!",
    })
    assert resp.status_code == 401

    # New password should work
    resp = await client.post("/api/v1/auth/login", json={
        "email": "test@example.com",
        "password": "NewSecurePass1!",
    })
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_account_lockout(client):
    """After 5 failed attempts in 10 minutes, account should be locked (Spec §4 Basic)."""
    await create_test_user(client)

    # Clear any existing failed attempts
    from app.services.auth_service import _failed_attempts
    _failed_attempts.clear()

    for _ in range(5):
        await client.post("/api/v1/auth/login", json={
            "email": "test@example.com",
            "password": "WrongPassword!",
        })

    # 6th attempt should be locked (429)
    resp = await client.post("/api/v1/auth/login", json={
        "email": "test@example.com",
        "password": "WrongPassword!",
    })
    assert resp.status_code == 429


@pytest.mark.asyncio
async def test_get_me(client):
    await create_test_user(client, username="meuser")
    tokens = await login_user(client)
    resp = await client.get("/api/v1/users/me", headers=auth_header(tokens["access_token"]))
    assert resp.status_code == 200
    assert resp.json()["email"] == "test@example.com"
    assert resp.json()["username"] == "meuser"


@pytest.mark.asyncio
async def test_get_me_unauthorized(client):
    resp = await client.get("/api/v1/users/me")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_update_me(client):
    await create_test_user(client)
    tokens = await login_user(client)
    resp = await client.patch(
        "/api/v1/users/me",
        headers=auth_header(tokens["access_token"]),
        json={"username": "updated_name"},
    )
    assert resp.status_code == 200
    assert resp.json()["username"] == "updated_name"


@pytest.mark.asyncio
async def test_security_headers(client):
    """Spec §8: security headers on every response."""
    resp = await client.get("/docs")
    assert resp.headers.get("x-content-type-options") == "nosniff"
    assert resp.headers.get("x-frame-options") == "DENY"
    assert "strict-transport-security" in resp.headers


@pytest.mark.asyncio
async def test_rfc7807_error_format(client):
    """Error responses should follow RFC 7807 Problem JSON."""
    resp = await client.post("/api/v1/auth/login", json={
        "email": "nobody@example.com",
        "password": "whatever123!",
    })
    data = resp.json()
    assert "type" in data
    assert "title" in data
    assert "status" in data
    assert "detail" in data
