import uuid
from typing import Annotated

from fastapi import Depends, Header, Request
from jose import JWTError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AuthError, PermissionError
from app.core.security import decode_access_token
from app.db.base import get_db
from app.db.models.user import User
from app.db.repositories.user_repo import UserRepository
from app.core.config import settings


async def get_current_user(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
    db: AsyncSession = Depends(get_db),
) -> User:
    """Extract and validate the current user from Bearer token or ApiKey header."""
    if not authorization:
        raise AuthError("Missing authorization header")

    # API Key auth (complex tier, Spec §4 Complex)
    if settings.ENABLE_API_KEY_AUTH and authorization.startswith("ApiKey "):
        from app.db.models.api_key import ApiKey
        from app.core.security import hash_token
        from sqlalchemy import select
        from datetime import datetime, timezone

        raw_key = authorization[7:]
        key_hash = hash_token(raw_key)
        stmt = select(ApiKey).where(
            ApiKey.key_hash == key_hash,
            ApiKey.revoked.is_(False),
        )
        result = await db.execute(stmt)
        api_key = result.scalar_one_or_none()

        if not api_key:
            raise AuthError("Invalid API key")
        if api_key.expires_at and api_key.expires_at < datetime.now(timezone.utc):
            raise AuthError("API key expired")

        # Update last_used_at
        api_key.last_used_at = datetime.now(timezone.utc)

        # Store scopes on request for require_scope
        request.state.api_key_scopes = api_key.scopes

        user_repo = UserRepository(db)
        user = await user_repo.get_by_id(api_key.user_id)
        if not user or not user.is_active:
            raise AuthError("User not found or inactive")
        return user

    # Bearer token auth
    if not authorization.startswith("Bearer "):
        raise AuthError("Invalid authorization scheme")

    token = authorization[7:]
    try:
        payload = decode_access_token(token)
    except JWTError:
        raise AuthError("Invalid or expired token")

    user_id = payload.get("sub")
    if not user_id:
        raise AuthError("Invalid token payload")

    user_repo = UserRepository(db)
    user = await user_repo.get_by_id(uuid.UUID(user_id))
    if not user or not user.is_active:
        raise AuthError("User not found or inactive")

    return user


def require_role(role_name: str):
    """Dependency factory: raises 403 if user lacks the specified role (Spec §4 Complex)."""
    async def _check(current_user: User = Depends(get_current_user)) -> User:
        if not settings.ENABLE_RBAC:
            return current_user
        if not hasattr(current_user, "roles"):
            raise PermissionError(f"Role '{role_name}' required")
        user_role_names = {r.name for r in current_user.roles}
        if role_name not in user_role_names and "super_admin" not in user_role_names:
            raise PermissionError(f"Role '{role_name}' required")
        return current_user
    return _check


def require_permission(permission: str):
    """Dependency factory: raises 403 if user lacks the specified permission (Spec §4 Complex)."""
    async def _check(current_user: User = Depends(get_current_user)) -> User:
        if not settings.ENABLE_RBAC:
            return current_user
        if not hasattr(current_user, "roles"):
            raise PermissionError(f"Permission '{permission}' required")
        for role in current_user.roles:
            if permission in role.permissions:
                return current_user
        raise PermissionError(f"Permission '{permission}' required")
    return _check


def require_scope(scope: str):
    """Dependency factory: raises 403 if API key lacks the specified scope (Spec §4 Complex)."""
    async def _check(request: Request, current_user: User = Depends(get_current_user)) -> User:
        scopes = getattr(request.state, "api_key_scopes", None)
        # If not using API key auth, allow through (Bearer token has full access)
        if scopes is None:
            return current_user
        if scope not in scopes:
            raise PermissionError(f"Scope '{scope}' required")
        return current_user
    return _check


def require_verified_email():
    """Dependency: raises 403 if user email is not verified (Spec §4 Standard)."""
    async def _check(current_user: User = Depends(get_current_user)) -> User:
        if not settings.ENABLE_EMAIL_VERIFICATION:
            return current_user
        if not getattr(current_user, "email_verified_at", None):
            raise PermissionError("Email verification required")
        return current_user
    return _check
