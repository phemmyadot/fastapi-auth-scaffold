from app.db.models.user import User
from app.db.models.token import RefreshToken

__all__ = ["User", "RefreshToken"]

# Conditional model imports based on feature flags
from app.core.config import settings

if settings.ENABLE_API_KEY_AUTH:
    from app.db.models.api_key import ApiKey
    __all__.append("ApiKey")

if settings.ENABLE_RBAC:
    from app.db.models.role import Role, UserRole
    __all__.extend(["Role", "UserRole"])

if settings.ENABLE_OAUTH2:
    from app.db.models.oauth_account import OAuthAccount
    __all__.append("OAuthAccount")

if settings.ENABLE_AUDIT_LOGGING:
    from app.db.models.audit_log import AuditLog
    __all__.append("AuditLog")
