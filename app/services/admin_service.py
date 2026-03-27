import uuid

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError, ValidationError
from app.db.models.role import Role, UserRole
from app.db.models.user import User
from app.db.repositories.token_repo import TokenRepository
from app.db.repositories.user_repo import UserRepository


class AdminService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.user_repo = UserRepository(session)
        self.token_repo = TokenRepository(session)

    async def list_users(self, offset: int = 0, limit: int = 50) -> list[User]:
        return await self.user_repo.list_all(offset=offset, limit=limit)

    async def assign_role(self, user_id: uuid.UUID, role_id: uuid.UUID) -> None:
        user = await self.user_repo.get_by_id(user_id)
        if not user:
            raise NotFoundError("User not found")

        role = await self.session.get(Role, role_id)
        if not role:
            raise NotFoundError("Role not found")

        # Check if already assigned
        stmt = select(UserRole).where(
            UserRole.c.user_id == user_id, UserRole.c.role_id == role_id
        )
        result = await self.session.execute(stmt)
        if result.first():
            raise ValidationError("Role already assigned to user")

        await self.session.execute(UserRole.insert().values(user_id=user_id, role_id=role_id))
        await self.session.flush()

    async def remove_role(self, user_id: uuid.UUID, role_id: uuid.UUID) -> None:
        user = await self.user_repo.get_by_id(user_id)
        if not user:
            raise NotFoundError("User not found")

        stmt = delete(UserRole).where(
            UserRole.c.user_id == user_id, UserRole.c.role_id == role_id
        )
        result = await self.session.execute(stmt)
        if result.rowcount == 0:
            raise NotFoundError("Role assignment not found")

    async def ban_user(self, user_id: uuid.UUID) -> None:
        user = await self.user_repo.get_by_id(user_id)
        if not user:
            raise NotFoundError("User not found")

        await self.user_repo.update_by_id(user_id, is_active=False)
        await self.token_repo.revoke_all_for_user(user_id)

    async def unban_user(self, user_id: uuid.UUID) -> None:
        user = await self.user_repo.get_by_id(user_id)
        if not user:
            raise NotFoundError("User not found")

        await self.user_repo.update_by_id(user_id, is_active=True)
