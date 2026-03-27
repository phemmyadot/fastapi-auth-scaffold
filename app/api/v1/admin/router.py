import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.auth.dependencies import require_role
from app.core.audit import emit_audit_log
from app.db.base import get_db
from app.db.models.audit_log import AuditEventType, AuditLog
from app.db.models.user import User
from app.schemas.audit import AuditLogResponse
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
    emit_audit_log(
        AuditEventType.ROLE_ASSIGNED,
        user_id=user_id,
        metadata={"role_id": str(role_id), "assigned_by": str(_current_user.id)},
    )


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
    emit_audit_log(
        AuditEventType.ROLE_REMOVED,
        user_id=user_id,
        metadata={"role_id": str(role_id), "removed_by": str(_current_user.id)},
    )


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
    emit_audit_log(
        AuditEventType.USER_BANNED,
        user_id=user_id,
        metadata={"banned_by": str(_current_user.id)},
    )


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


@router.get(
    "/audit-logs",
    response_model=list[AuditLogResponse],
    summary="List audit logs",
    description="Returns paginated audit logs. Filterable by user_id, event_type, and date range. Admin only.",
)
async def list_audit_logs(
    user_id: uuid.UUID | None = Query(default=None),
    event_type: AuditEventType | None = Query(default=None),
    start_date: datetime | None = Query(default=None),
    end_date: datetime | None = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=100),
    _current_user: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    query = select(AuditLog)
    if user_id:
        query = query.where(AuditLog.user_id == user_id)
    if event_type:
        query = query.where(AuditLog.event_type == event_type)
    if start_date:
        query = query.where(AuditLog.created_at >= start_date)
    if end_date:
        query = query.where(AuditLog.created_at <= end_date)
    query = query.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit)
    result = await db.execute(query)
    return list(result.scalars().all())
