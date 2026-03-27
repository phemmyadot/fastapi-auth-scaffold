import base64
import io
import secrets

import pyotp

from app.core.config import settings


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def get_totp_uri(secret: str, email: str) -> str:
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name=settings.PROJECT_NAME)


def generate_qr_code_data_uri(uri: str) -> str:
    """Generate a QR code as a base64 data URI. Falls back to empty string if qrcode not installed."""
    try:
        import qrcode
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        b64 = base64.b64encode(buf.getvalue()).decode()
        return f"data:image/png;base64,{b64}"
    except ImportError:
        return ""


def verify_totp_code(secret: str, code: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(code)


def generate_backup_codes(count: int = 8) -> list[str]:
    """Generate single-use backup codes (8 hex chars each)."""
    return [secrets.token_hex(4) for _ in range(count)]
