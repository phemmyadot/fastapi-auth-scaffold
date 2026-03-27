import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.email import send_password_reset_email
from app.core.exceptions import AuthError, NotFoundError, ValidationError
from app.core.security import (
    create_access_token,
    create_signed_token,
    decode_signed_token,
    generate_refresh_token,
    hash_password,
    hash_token,
    verify_password,
    verify_token_hash,
)
from app.db.models.user import User
from app.db.repositories.token_repo import TokenRepository
from app.db.repositories.user_repo import UserRepository
from app.schemas.auth import TokenResponse

# In-memory failed login tracker: {email: [(timestamp, ...),]}
_failed_attempts: dict[str, list[datetime]] = defaultdict(list)
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_WINDOW = timedelta(minutes=10)


def _check_lockout(email: str) -> None:
    """Raise AuthError if account is locked due to too many failed attempts."""
    now = datetime.now(timezone.utc)
    cutoff = now - LOCKOUT_WINDOW
    # Prune old attempts
    _failed_attempts[email] = [t for t in _failed_attempts[email] if t > cutoff]
    if len(_failed_attempts[email]) >= MAX_FAILED_ATTEMPTS:
        raise AuthError("Account temporarily locked. Try again later.", status_code=429)


def _record_failed_attempt(email: str) -> None:
    _failed_attempts[email].append(datetime.now(timezone.utc))


def _clear_failed_attempts(email: str) -> None:
    _failed_attempts.pop(email, None)


class AuthService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.user_repo = UserRepository(session)
        self.token_repo = TokenRepository(session)

    async def register(self, email: str, password: str, username: str | None = None) -> User:
        email = email.lower().strip()

        if await self.user_repo.get_by_email(email):
            raise ValidationError("Email already registered")

        if username and await self.user_repo.get_by_username(username):
            raise ValidationError("Username already taken")

        user = await self.user_repo.create(
            email=email,
            username=username,
            hashed_password=hash_password(password),
        )
        return user

    async def login(
        self, email: str, password: str, user_agent: str = "", ip_address: str = ""
    ) -> TokenResponse:
        email = email.lower().strip()
        _check_lockout(email)

        user = await self.user_repo.get_by_email(email)

        # Identical error for wrong email or wrong password (Spec §8 — prevent enumeration)
        if not user or not user.hashed_password or not verify_password(password, user.hashed_password):
            if user:
                _record_failed_attempt(email)
            else:
                _record_failed_attempt(email)
            raise AuthError("Invalid email or password")

        if not user.is_active:
            raise AuthError("Account is deactivated")

        _clear_failed_attempts(email)

        access_token = create_access_token(subject=str(user.id))
        raw_refresh = generate_refresh_token()
        await self.token_repo.create(
            user_id=user.id,
            token_hash=hash_token(raw_refresh),
            expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
            user_agent=user_agent,
            ip_address=ip_address,
        )

        return TokenResponse(access_token=access_token, refresh_token=raw_refresh)

    async def refresh(
        self, refresh_token: str, user_agent: str = "", ip_address: str = ""
    ) -> TokenResponse:
        token_hash = hash_token(refresh_token)
        stored = await self.token_repo.get_by_token_hash(token_hash)

        if not stored:
            raise AuthError("Invalid or expired refresh token")

        # Rotate: revoke old, issue new
        await self.token_repo.revoke(stored.id)

        access_token = create_access_token(subject=str(stored.user_id))
        new_raw = generate_refresh_token()
        await self.token_repo.create(
            user_id=stored.user_id,
            token_hash=hash_token(new_raw),
            expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
            user_agent=user_agent,
            ip_address=ip_address,
        )

        return TokenResponse(access_token=access_token, refresh_token=new_raw)

    async def logout(self, refresh_token: str) -> None:
        token_hash = hash_token(refresh_token)
        stored = await self.token_repo.get_by_token_hash(token_hash)
        if stored:
            await self.token_repo.revoke(stored.id)

    async def logout_all(self, user_id: uuid.UUID) -> None:
        await self.token_repo.revoke_all_for_user(user_id)

    async def request_password_reset(self, email: str) -> None:
        email = email.lower().strip()
        user = await self.user_repo.get_by_email(email)
        # Always return success to prevent user enumeration (Spec §8)
        if not user:
            return

        token = create_signed_token(
            subject=str(user.id),
            purpose="password_reset",
            expires_delta=timedelta(hours=1),
        )
        await send_password_reset_email(to=user.email, reset_token=token)

    async def confirm_password_reset(self, token: str, new_password: str) -> None:
        try:
            payload = decode_signed_token(token, expected_purpose="password_reset")
        except Exception:
            raise AuthError("Invalid or expired reset token")

        user_id = uuid.UUID(payload["sub"])
        user = await self.user_repo.get_by_id(user_id)
        if not user:
            raise NotFoundError("User not found")

        await self.user_repo.update_by_id(user_id, hashed_password=hash_password(new_password))
        # Invalidate all refresh tokens on password change
        await self.token_repo.revoke_all_for_user(user_id)
