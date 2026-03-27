from enum import Enum
from typing import Any

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AuthTier(str, Enum):
    BASIC = "basic"
    STANDARD = "standard"
    COMPLEX = "complex"


TIER_ORDER = {AuthTier.BASIC: 0, AuthTier.STANDARD: 1, AuthTier.COMPLEX: 2}

# Maps each feature flag to its minimum required tier (Spec §5)
FLAG_MIN_TIER: dict[str, AuthTier] = {
    "ENABLE_EMAIL_VERIFICATION": AuthTier.STANDARD,
    "ENABLE_PHONE_VERIFICATION": AuthTier.STANDARD,
    "ENABLE_TOTP_2FA": AuthTier.STANDARD,
    "ENABLE_API_KEY_AUTH": AuthTier.COMPLEX,
    "ENABLE_RBAC": AuthTier.COMPLEX,
    "ENABLE_OAUTH2": AuthTier.COMPLEX,
    "ENABLE_AUDIT_LOGGING": AuthTier.COMPLEX,
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
    )

    # Core
    PROJECT_NAME: str = "my_project"
    AUTH_TIER: AuthTier = AuthTier.BASIC
    DATABASE_URL: str = "postgresql+asyncpg://user:password@localhost:5432/dbname"
    JWT_SECRET: str = "change_me_in_production"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    CORS_ORIGINS: list[str] = ["http://localhost:3000"]

    # Feature flags
    ENABLE_EMAIL_VERIFICATION: bool = False
    ENABLE_PHONE_VERIFICATION: bool = False
    ENABLE_TOTP_2FA: bool = False
    ENABLE_API_KEY_AUTH: bool = False
    ENABLE_RBAC: bool = False
    ENABLE_OAUTH2: bool = False
    ENABLE_AUDIT_LOGGING: bool = False

    # Email (aiosmtplib)
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    EMAIL_FROM: str = "no-reply@yourdomain.com"

    # Twilio (ENABLE_PHONE_VERIFICATION)
    TWILIO_ACCOUNT_SID: str = ""
    TWILIO_AUTH_TOKEN: str = ""
    TWILIO_FROM_NUMBER: str = ""

    # OAuth2 (ENABLE_OAUTH2)
    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    GITHUB_CLIENT_ID: str = ""
    GITHUB_CLIENT_SECRET: str = ""
    OAUTH2_REDIRECT_BASE_URL: str = "http://localhost:8000"

    @model_validator(mode="after")
    def enforce_tier_requirements(self) -> "Settings":
        """Disable feature flags that exceed the selected AUTH_TIER (Spec §5)."""
        current_level = TIER_ORDER[self.AUTH_TIER]
        for flag_name, min_tier in FLAG_MIN_TIER.items():
            if getattr(self, flag_name) and TIER_ORDER[min_tier] > current_level:
                object.__setattr__(self, flag_name, False)
        return self

    @property
    def effective_flags(self) -> dict[str, bool]:
        return {name: getattr(self, name) for name in FLAG_MIN_TIER}


settings = Settings()
