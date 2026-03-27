import uuid

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.auth.dependencies import require_role
from app.db.base import get_db
from app.db.models.user import User
from app.schemas.user import UserResponse
from app.services.admin_service import AdminService

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get(
    "/users",
    response_model=list[UserResponse],
    summary="List all users",
    description="Returns a paginated list of all users. Admin only.",
)
async def list_users(
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=100),
    _current_user: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    service = AdminService(db)
    return await service.list_users(offset=offset, limit=limit)


@router.post(
    "/users/{user_id}/roles",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Assign role to user",
    description="Assigns a role to a user by role_id. Super admin only.",
)
async def assign_role(
    user_id: uuid.UUID,
    role_id: uuid.UUID = Query(...),
    _current_user: User = Depends(require_role("super_admin")),
    db: AsyncSession = Depends(get_db),
):
    service = AdminService(db)
    await service.assign_role(user_id=user_id, role_id=role_id)


@router.delete(
    "/users/{user_id}/roles/{role_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remove role from user",
    description="Removes a role from a user. Super admin only.",
)
async def remove_role(
    user_id: uuid.UUID,
    role_id: uuid.UUID,
    _current_user: User = Depends(require_role("super_admin")),
    db: AsyncSession = Depends(get_db),
):
    service = AdminService(db)
    await service.remove_role(user_id=user_id, role_id=role_id)


@router.post(
    "/users/{user_id}/ban",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Ban user",
    description="Deactivates account and revokes all tokens. Admin only.",
)
async def ban_user(
    user_id: uuid.UUID,
    _current_user: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    service = AdminService(db)
    await service.ban_user(user_id=user_id)


@router.post(
    "/users/{user_id}/unban",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Unban user",
    description="Reactivates a banned account. Admin only.",
)
async def unban_user(
    user_id: uuid.UUID,
    _current_user: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    service = AdminService(db)
    await service.unban_user(user_id=user_id)
