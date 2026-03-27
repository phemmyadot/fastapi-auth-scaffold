import secrets
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AuthError, ValidationError
from app.core.security import hash_token, verify_token_hash
from app.core.sms import send_sms
from app.db.repositories.user_repo import UserRepository

# In-memory OTP store: {user_id: (otp_hash, expires_at)}
_otp_store: dict[str, tuple[str, datetime]] = {}

# In-memory rate limiter: {phone_number: [timestamp, ...]}
_send_tracker: dict[str, list[datetime]] = defaultdict(list)
MAX_SENDS_PER_HOUR = 3
THROTTLE_WINDOW = timedelta(hours=1)
OTP_EXPIRY = timedelta(minutes=10)


def _generate_otp() -> str:
    """Generate a 6-digit OTP."""
    return f"{secrets.randbelow(1000000):06d}"


def _check_send_throttle(phone_number: str) -> None:
    now = datetime.now(timezone.utc)
    cutoff = now - THROTTLE_WINDOW
    _send_tracker[phone_number] = [t for t in _send_tracker[phone_number] if t > cutoff]
    if len(_send_tracker[phone_number]) >= MAX_SENDS_PER_HOUR:
        raise ValidationError("Maximum OTP sends exceeded. Try again later.")


def _record_send(phone_number: str) -> None:
    _send_tracker[phone_number].append(datetime.now(timezone.utc))


class PhoneVerificationService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.user_repo = UserRepository(session)

    async def send_otp(self, user_id: uuid.UUID, phone_number: str) -> None:
        _check_send_throttle(phone_number)

        # Update phone number on user if needed
        user = await self.user_repo.get_by_id(user_id)
        if not user:
            raise AuthError("User not found")

        if getattr(user, "phone_number", None) != phone_number:
            await self.user_repo.update_by_id(user_id, phone_number=phone_number)

        otp = _generate_otp()
        _otp_store[str(user_id)] = (hash_token(otp), datetime.now(timezone.utc) + OTP_EXPIRY)

        send_sms(to=phone_number, body=f"Your verification code is: {otp}")
        _record_send(phone_number)

    async def verify_otp(self, user_id: uuid.UUID, otp_code: str) -> None:
        key = str(user_id)
        stored = _otp_store.get(key)

        if not stored:
            raise AuthError("No OTP found. Request a new one.")

        otp_hash, expires_at = stored

        # Single-use: remove immediately
        del _otp_store[key]

        if datetime.now(timezone.utc) > expires_at:
            raise AuthError("OTP has expired. Request a new one.")

        if not verify_token_hash(otp_code, otp_hash):
            raise AuthError("Invalid OTP code")

        await self.user_repo.update_by_id(
            user_id, phone_verified_at=datetime.now(timezone.utc)
        )
