import uuid

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.auth.dependencies import get_current_user
from app.core.config import settings
from app.db.base import get_db
from app.db.models.user import User
from app.schemas.user import UserResponse, UserUpdate
from app.services.user_service import UserService

router = APIRouter(prefix="/users", tags=["users"])


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user profile",
    description="Returns the authenticated user's profile.",
)
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user


@router.patch(
    "/me",
    response_model=UserResponse,
    summary="Update current user profile",
    description="Update username or display name.",
)
async def update_me(
    body: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    service = UserService(db)
    return await service.update_profile(user_id=current_user.id, username=body.username)


# --- API Keys (Complex tier, ENABLE_API_KEY_AUTH) ---

if settings.ENABLE_API_KEY_AUTH:
    from app.schemas.api_key import ApiKeyCreate, ApiKeyCreatedResponse, ApiKeyResponse
    from app.services.api_key_service import ApiKeyService

    @router.post(
        "/me/api-keys",
        response_model=ApiKeyCreatedResponse,
        status_code=status.HTTP_201_CREATED,
        summary="Generate new API key",
        description="Creates a new API key. The raw key is returned exactly once in the response.",
        tags=["api-keys"],
    )
    async def create_api_key(
        body: ApiKeyCreate,
        current_user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ):
        service = ApiKeyService(db)
        api_key, raw_key = await service.create(
            user_id=current_user.id,
            name=body.name,
            scopes=body.scopes,
            expires_at=body.expires_at,
        )
        return ApiKeyCreatedResponse(
            id=api_key.id,
            name=api_key.name,
            prefix=api_key.prefix,
            scopes=api_key.scopes,
            last_used_at=api_key.last_used_at,
            expires_at=api_key.expires_at,
            revoked=api_key.revoked,
            created_at=api_key.created_at,
            raw_key=raw_key,
        )

    @router.get(
        "/me/api-keys",
        response_model=list[ApiKeyResponse],
        summary="List API keys",
        description="Returns all API keys for the current user (prefix + metadata, never raw key).",
        tags=["api-keys"],
    )
    async def list_api_keys(
        current_user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ):
        service = ApiKeyService(db)
        return await service.list_for_user(user_id=current_user.id)

    @router.delete(
        "/me/api-keys/{key_id}",
        status_code=status.HTTP_204_NO_CONTENT,
        summary="Revoke API key",
        description="Revokes an API key by ID.",
        tags=["api-keys"],
    )
    async def revoke_api_key(
        key_id: uuid.UUID,
        current_user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ):
        service = ApiKeyService(db)
        await service.revoke(user_id=current_user.id, key_id=key_id)
