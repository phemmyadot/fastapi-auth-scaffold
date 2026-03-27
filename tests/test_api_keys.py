"""Tests for API key auth (if ENABLE_API_KEY_AUTH)."""
import pytest

from app.core.config import settings
from tests.conftest import auth_header, create_test_user, login_user

pytestmark = pytest.mark.skipif(
    not settings.ENABLE_API_KEY_AUTH,
    reason="ENABLE_API_KEY_AUTH is disabled",
)


@pytest.mark.asyncio
async def test_create_api_key(client):
    await create_test_user(client)
    tokens = await login_user(client)
    resp = await client.post(
        "/api/v1/users/me/api-keys",
        headers=auth_header(tokens["access_token"]),
        json={"name": "test-key", "scopes": ["read"]},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert "raw_key" in data
    assert data["name"] == "test-key"
    assert data["scopes"] == ["read"]
    assert data["revoked"] is False


@pytest.mark.asyncio
async def test_list_api_keys(client):
    await create_test_user(client)
    tokens = await login_user(client)
    headers = auth_header(tokens["access_token"])

    # Create two keys
    await client.post("/api/v1/users/me/api-keys", headers=headers, json={"name": "key1", "scopes": ["read"]})
    await client.post("/api/v1/users/me/api-keys", headers=headers, json={"name": "key2", "scopes": ["write"]})

    resp = await client.get("/api/v1/users/me/api-keys", headers=headers)
    assert resp.status_code == 200
    keys = resp.json()
    assert len(keys) == 2
    # raw_key should NOT be returned in list
    for key in keys:
        assert "raw_key" not in key


@pytest.mark.asyncio
async def test_authenticate_via_api_key(client):
    await create_test_user(client)
    tokens = await login_user(client)
    resp = await client.post(
        "/api/v1/users/me/api-keys",
        headers=auth_header(tokens["access_token"]),
        json={"name": "auth-key", "scopes": ["read"]},
    )
    raw_key = resp.json()["raw_key"]

    # Use API key to access /users/me
    resp = await client.get("/api/v1/users/me", headers={"Authorization": f"ApiKey {raw_key}"})
    assert resp.status_code == 200
    assert resp.json()["email"] == "test@example.com"


@pytest.mark.asyncio
async def test_revoke_api_key(client):
    await create_test_user(client)
    tokens = await login_user(client)
    headers = auth_header(tokens["access_token"])

    resp = await client.post(
        "/api/v1/users/me/api-keys", headers=headers, json={"name": "revoke-me", "scopes": ["read"]}
    )
    key_id = resp.json()["id"]
    raw_key = resp.json()["raw_key"]

    # Revoke
    resp = await client.delete(f"/api/v1/users/me/api-keys/{key_id}", headers=headers)
    assert resp.status_code == 204

    # Revoked key should not work
    resp = await client.get("/api/v1/users/me", headers={"Authorization": f"ApiKey {raw_key}"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_invalid_api_key(client):
    resp = await client.get("/api/v1/users/me", headers={"Authorization": "ApiKey fake-key"})
    assert resp.status_code == 401
