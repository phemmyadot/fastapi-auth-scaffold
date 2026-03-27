from fastapi import APIRouter

from app.api.v1.auth.router import router as auth_router
from app.api.v1.users.router import router as users_router
from app.core.config import settings

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(auth_router)
api_router.include_router(users_router)

if settings.ENABLE_RBAC:
    from app.api.v1.admin.router import router as admin_router
    api_router.include_router(admin_router)
