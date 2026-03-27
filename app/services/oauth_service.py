import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.exceptions import AuthError, NotFoundError, ValidationError
from app.core.oauth2 import exchange_github_code, exchange_google_code
from app.core.security import create_access_token, generate_refresh_token, hash_token
from app.db.models.oauth_account import OAuthAccount, OAuthProvider
from app.db.models.user import User
from app.db.repositories.token_repo import TokenRepository
from app.db.repositories.user_repo import UserRepository
from app.schemas.auth import TokenResponse


class OAuthService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.user_repo = UserRepository(session)
        self.token_repo = TokenRepository(session)

    async def handle_callback(
        self, provider: str, code: str, state: str, user_agent: str = "", ip_address: str = ""
    ) -> TokenResponse:
        """Exchange OAuth code, create/link user, and issue tokens."""
        if provider == "google":
            user_info = await exchange_google_code(code, state)
        elif provider == "github":
            user_info = await exchange_github_code(code, state)
        else:
            raise ValidationError(f"Unsupported OAuth provider: {provider}")

        email = user_info["email"]
        if not email:
            raise AuthError("Could not retrieve email from OAuth provider")

        email = email.lower().strip()
        provider_enum = OAuthProvider(provider)

        # Check if this OAuth account already exists
        existing_oauth = await self._get_oauth_account(provider_enum, user_info["provider_user_id"])

        if existing_oauth:
            # Update tokens
            existing_oauth.access_token = user_info["access_token"]
            existing_oauth.refresh_token = user_info.get("refresh_token")
            existing_oauth.token_expires_at = user_info["expires_at"]
            await self.session.flush()
            user = await self.user_repo.get_by_id(existing_oauth.user_id)
        else:
            # Check if a user with this email already exists → link
            user = await self.user_repo.get_by_email(email)
            if not user:
                # Create new user (no password — OAuth-only)
                user = await self.user_repo.create(
                    email=email, username=None, hashed_password=None
                )

            # Create OAuth account link
            oauth_account = OAuthAccount(
                user_id=user.id,
                provider=provider_enum,
                provider_user_id=user_info["provider_user_id"],
                access_token=user_info["access_token"],
                refresh_token=user_info.get("refresh_token"),
                token_expires_at=user_info["expires_at"],
            )
            self.session.add(oauth_account)
            await self.session.flush()

        if not user or not user.is_active:
            raise AuthError("Account is deactivated")

        # Issue tokens
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

    async def list_connected_accounts(self, user_id: uuid.UUID) -> list[OAuthAccount]:
        result = await self.session.execute(
            select(OAuthAccount).where(OAuthAccount.user_id == user_id)
        )
        return list(result.scalars().all())

    async def unlink_account(self, user_id: uuid.UUID, provider: str) -> None:
        provider_enum = OAuthProvider(provider)

        # Find the OAuth account
        result = await self.session.execute(
            select(OAuthAccount).where(
                OAuthAccount.user_id == user_id,
                OAuthAccount.provider == provider_enum,
            )
        )
        oauth_account = result.scalar_one_or_none()
        if not oauth_account:
            raise NotFoundError(f"No linked {provider} account found")

        # Unlink guard: cannot remove last login method
        user = await self.user_repo.get_by_id(user_id)
        has_password = user.hashed_password is not None

        other_oauth = await self.session.execute(
            select(OAuthAccount).where(
                OAuthAccount.user_id == user_id,
                OAuthAccount.provider != provider_enum,
            )
        )
        has_other_provider = other_oauth.scalar_one_or_none() is not None

        if not has_password and not has_other_provider:
            raise ValidationError(
                "Cannot unlink last login method. Set a password or link another provider first."
            )

        await self.session.delete(oauth_account)
        await self.session.flush()

    async def _get_oauth_account(
        self, provider: OAuthProvider, provider_user_id: str
    ) -> OAuthAccount | None:
        result = await self.session.execute(
            select(OAuthAccount).where(
                OAuthAccount.provider == provider,
                OAuthAccount.provider_user_id == provider_user_id,
            )
        )
        return result.scalar_one_or_none()
