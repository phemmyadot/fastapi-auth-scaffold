"""Tests for RBAC (if ENABLE_RBAC)."""
import pytest

from app.core.config import settings
from tests.conftest import auth_header, create_test_user, login_user

pytestmark = pytest.mark.skipif(
    not settings.ENABLE_RBAC,
    reason="ENABLE_RBAC is disabled",
)


@pytest.mark.asyncio
async def test_admin_list_users_requires_admin_role(client):
    """Non-admin user should be forbidden from listing users."""
    await create_test_user(client)
    tokens = await login_user(client)
    resp = await client.get("/api/v1/admin/users", headers=auth_header(tokens["access_token"]))
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_admin_list_users_as_admin(client, db_session):
    """Admin user should be able to list users."""
    await create_test_user(client)
    tokens = await login_user(client)

    # Manually assign admin role
    from app.core.security import decode_access_token
    from app.db.models.role import Role, UserRole
    import uuid

    payload = decode_access_token(tokens["access_token"])
    user_id = uuid.UUID(payload["sub"])

    # Create admin role
    role = Role(name="admin", description="Administrator")
    db_session.add(role)
    await db_session.flush()

    # Assign role
    await db_session.execute(UserRole.insert().values(user_id=user_id, role_id=role.id))
    await db_session.commit()

    resp = await client.get("/api/v1/admin/users", headers=auth_header(tokens["access_token"]))
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_assign_role_requires_super_admin(client, db_session):
    """Only super_admin can assign roles."""
    await create_test_user(client)
    tokens = await login_user(client)

    # Create admin role and assign
    from app.core.security import decode_access_token
    from app.db.models.role import Role, UserRole
    import uuid

    payload = decode_access_token(tokens["access_token"])
    user_id = uuid.UUID(payload["sub"])

    admin_role = Role(name="admin", description="Administrator")
    db_session.add(admin_role)
    await db_session.flush()

    await db_session.execute(UserRole.insert().values(user_id=user_id, role_id=admin_role.id))
    await db_session.commit()

    # Admin (not super_admin) should be forbidden from assigning roles
    target_role = Role(name="user", description="Regular user")
    db_session.add(target_role)
    await db_session.flush()
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/admin/users/{user_id}/roles?role_id={target_role.id}",
        headers=auth_header(tokens["access_token"]),
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_ban_unban_user(client, db_session):
    """Admin can ban and unban users."""
    # Create admin + target user
    await create_test_user(client, email="admin@example.com")
    admin_tokens = await login_user(client, email="admin@example.com")

    target_data = await create_test_user(client, email="target@example.com", password="TargetPass1!")
    target_id = target_data["id"]

    # Assign admin role
    from app.core.security import decode_access_token
    from app.db.models.role import Role, UserRole
    import uuid

    payload = decode_access_token(admin_tokens["access_token"])
    admin_id = uuid.UUID(payload["sub"])

    admin_role = Role(name="admin", description="Administrator")
    db_session.add(admin_role)
    await db_session.flush()
    await db_session.execute(UserRole.insert().values(user_id=admin_id, role_id=admin_role.id))
    await db_session.commit()

    headers = auth_header(admin_tokens["access_token"])

    # Ban
    resp = await client.post(f"/api/v1/admin/users/{target_id}/ban", headers=headers)
    assert resp.status_code == 204

    # Banned user cannot login
    resp = await client.post("/api/v1/auth/login", json={"email": "target@example.com", "password": "TargetPass1!"})
    assert resp.status_code == 401

    # Unban
    resp = await client.post(f"/api/v1/admin/users/{target_id}/unban", headers=headers)
    assert resp.status_code == 204

    # User can login again
    resp = await client.post("/api/v1/auth/login", json={"email": "target@example.com", "password": "TargetPass1!"})
    assert resp.status_code == 200
