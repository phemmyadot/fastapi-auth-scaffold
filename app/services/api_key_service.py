import secrets
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AuthError, NotFoundError
from app.core.security import hash_token
from app.db.models.api_key import ApiKey
from app.db.repositories.user_repo import UserRepository


def _generate_raw_key() -> str:
    return secrets.token_urlsafe(48)


class ApiKeyService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.user_repo = UserRepository(session)

    async def create(
        self, user_id: uuid.UUID, name: str, scopes: list[str], expires_at: datetime | None = None
    ) -> tuple[ApiKey, str]:
        """Create a new API key. Returns (api_key, raw_key). Raw key is only available here."""
        raw_key = _generate_raw_key()
        prefix = raw_key[:8]

        api_key = ApiKey(
            user_id=user_id,
            name=name,
            key_hash=hash_token(raw_key),
            prefix=prefix,
            scopes=scopes,
            expires_at=expires_at,
        )
        self.session.add(api_key)
        await self.session.flush()
        return api_key, raw_key

    async def list_for_user(self, user_id: uuid.UUID) -> list[ApiKey]:
        stmt = (
            select(ApiKey)
            .where(ApiKey.user_id == user_id)
            .order_by(ApiKey.created_at.desc())
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def revoke(self, user_id: uuid.UUID, key_id: uuid.UUID) -> None:
        stmt = select(ApiKey).where(ApiKey.id == key_id, ApiKey.user_id == user_id)
        result = await self.session.execute(stmt)
        api_key = result.scalar_one_or_none()
        if not api_key:
            raise NotFoundError("API key not found")
        api_key.revoked = True
        await self.session.flush()
