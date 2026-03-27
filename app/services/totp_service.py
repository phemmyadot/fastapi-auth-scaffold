import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.exceptions import AuthError
from app.core.security import (
    create_access_token,
    generate_refresh_token,
    hash_password,
    hash_token,
    verify_password,
)
from app.core.totp import (
    generate_backup_codes,
    generate_qr_code_data_uri,
    generate_totp_secret,
    get_totp_uri,
    verify_totp_code,
)
from app.db.repositories.token_repo import TokenRepository
from app.db.repositories.user_repo import UserRepository
from app.schemas.auth import TokenResponse
from app.schemas.totp import TOTPSetupResponse

# In-memory store for pending TOTP secrets (before enable) and backup codes
_pending_secrets: dict[str, str] = {}
_backup_codes: dict[str, list[str]] = {}  # {user_id: [hashed_code, ...]}

# Session tokens for two-step login: {session_token_hash: (user_id, expires_at)}
_totp_sessions: dict[str, tuple[str, datetime]] = {}


class TOTPService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.user_repo = UserRepository(session)
        self.token_repo = TokenRepository(session)

    async def setup(self, user_id: uuid.UUID, email: str) -> TOTPSetupResponse:
        """Generate TOTP secret and backup codes. Not yet enabled until verify."""
        secret = generate_totp_secret()
        uri = get_totp_uri(secret, email)
        qr = generate_qr_code_data_uri(uri)
        backup_codes = generate_backup_codes(8)

        # Store pending secret and hashed backup codes
        key = str(user_id)
        _pending_secrets[key] = secret
        _backup_codes[key] = [hash_token(code) for code in backup_codes]

        return TOTPSetupResponse(
            secret=secret,
            otpauth_url=uri,
            qr_code_data_uri=qr,
            backup_codes=backup_codes,
        )

    async def enable(self, user_id: uuid.UUID, totp_code: str) -> None:
        """Verify first TOTP code and activate 2FA."""
        key = str(user_id)
        secret = _pending_secrets.get(key)
        if not secret:
            raise AuthError("No TOTP setup in progress. Call /auth/totp/setup first.")

        if not verify_totp_code(secret, totp_code):
            raise AuthError("Invalid TOTP code")

        # Persist secret and enable
        await self.user_repo.update_by_id(user_id, totp_secret=secret, totp_enabled=True)
        del _pending_secrets[key]

    async def disable(self, user_id: uuid.UUID, password: str, totp_code: str) -> None:
        """Disable 2FA — requires current password + valid TOTP code."""
        user = await self.user_repo.get_by_id(user_id)
        if not user or not user.hashed_password:
            raise AuthError("Cannot disable TOTP")

        if not verify_password(password, user.hashed_password):
            raise AuthError("Invalid password")

        secret = getattr(user, "totp_secret", None)
        if not secret:
            raise AuthError("TOTP is not enabled")

        if not verify_totp_code(secret, totp_code):
            raise AuthError("Invalid TOTP code")

        await self.user_repo.update_by_id(user_id, totp_secret=None, totp_enabled=False)
        _backup_codes.pop(str(user_id), None)

    async def create_session_token(self, user_id: uuid.UUID) -> str:
        """Create a short-lived session token for the two-step login flow."""
        import secrets as _secrets
        raw = _secrets.token_urlsafe(48)
        expires = datetime.now(timezone.utc) + timedelta(minutes=5)
        _totp_sessions[hash_token(raw)] = (str(user_id), expires)
        return raw

    async def verify_and_issue_tokens(
        self, session_token: str, totp_code: str, user_agent: str = "", ip_address: str = ""
    ) -> TokenResponse:
        """Exchange session_token + TOTP code for final access/refresh tokens."""
        session_hash = hash_token(session_token)
        entry = _totp_sessions.pop(session_hash, None)

        if not entry:
            raise AuthError("Invalid or expired session token")

        stored_user_id, expires_at = entry
        if datetime.now(timezone.utc) > expires_at:
            raise AuthError("Session token expired. Please login again.")

        user = await self.user_repo.get_by_id(uuid.UUID(stored_user_id))
        if not user:
            raise AuthError("User not found")

        secret = getattr(user, "totp_secret", None)
        if not secret:
            raise AuthError("TOTP not configured")

        # Try TOTP code first, then backup codes
        if not verify_totp_code(secret, totp_code):
            if not self._try_backup_code(stored_user_id, totp_code):
                raise AuthError("Invalid TOTP code")

        access_token = create_access_token(subject=stored_user_id)
        raw_refresh = generate_refresh_token()
        await self.token_repo.create(
            user_id=uuid.UUID(stored_user_id),
            token_hash=hash_token(raw_refresh),
            expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
            user_agent=user_agent,
            ip_address=ip_address,
        )

        return TokenResponse(access_token=access_token, refresh_token=raw_refresh)

    def _try_backup_code(self, user_id: str, code: str) -> bool:
        """Check and consume a single-use backup code."""
        codes = _backup_codes.get(user_id, [])
        code_hash = hash_token(code)
        for i, stored_hash in enumerate(codes):
            if stored_hash == code_hash:
                codes.pop(i)
                return True
        return False
