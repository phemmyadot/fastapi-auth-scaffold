import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.email import send_verification_email
from app.core.exceptions import AuthError, ValidationError
from app.core.security import create_signed_token, decode_signed_token
from app.db.repositories.user_repo import UserRepository

# In-memory resend throttle: {user_id: [timestamp, ...]}
_resend_tracker: dict[str, list[datetime]] = defaultdict(list)
MAX_RESENDS_PER_HOUR = 3
THROTTLE_WINDOW = timedelta(hours=1)


def _check_resend_throttle(user_id: str) -> None:
    now = datetime.now(timezone.utc)
    cutoff = now - THROTTLE_WINDOW
    _resend_tracker[user_id] = [t for t in _resend_tracker[user_id] if t > cutoff]
    if len(_resend_tracker[user_id]) >= MAX_RESENDS_PER_HOUR:
        raise ValidationError("Maximum verification email resends exceeded. Try again later.")


def _record_resend(user_id: str) -> None:
    _resend_tracker[user_id].append(datetime.now(timezone.utc))


class EmailVerificationService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.user_repo = UserRepository(session)

    async def send_verification(self, user_id: uuid.UUID, email: str) -> None:
        _check_resend_throttle(str(user_id))

        token = create_signed_token(
            subject=str(user_id),
            purpose="email_verification",
            expires_delta=timedelta(hours=24),
        )
        await send_verification_email(to=email, verification_token=token)
        _record_resend(str(user_id))

    async def verify_email(self, token: str) -> None:
        try:
            payload = decode_signed_token(token, expected_purpose="email_verification")
        except Exception:
            raise AuthError("Invalid or expired verification token")

        user_id = uuid.UUID(payload["sub"])
        user = await self.user_repo.get_by_id(user_id)
        if not user:
            raise AuthError("Invalid verification token")

        if getattr(user, "email_verified_at", None):
            return  # Already verified

        await self.user_repo.update_by_id(
            user_id, email_verified_at=datetime.now(timezone.utc)
        )
