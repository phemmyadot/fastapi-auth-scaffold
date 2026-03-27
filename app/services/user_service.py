import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError, ValidationError
from app.db.models.user import User
from app.db.repositories.user_repo import UserRepository


class UserService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.user_repo = UserRepository(session)

    async def get_profile(self, user_id: uuid.UUID) -> User:
        user = await self.user_repo.get_by_id(user_id)
        if not user:
            raise NotFoundError("User not found")
        return user

    async def update_profile(self, user_id: uuid.UUID, username: str | None = None) -> User:
        if username is not None:
            existing = await self.user_repo.get_by_username(username)
            if existing and existing.id != user_id:
                raise ValidationError("Username already taken")
            await self.user_repo.update_by_id(user_id, username=username)

        user = await self.user_repo.get_by_id(user_id)
        if not user:
            raise NotFoundError("User not found")
        return user
