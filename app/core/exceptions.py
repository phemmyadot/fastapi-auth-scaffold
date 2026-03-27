class AuthError(Exception):
    """Authentication failure (invalid credentials, expired token, locked account)."""

    def __init__(self, detail: str = "Authentication failed", status_code: int = 401) -> None:
        self.detail = detail
        self.status_code = status_code


class NotFoundError(Exception):
    """Requested resource does not exist."""

    def __init__(self, detail: str = "Resource not found") -> None:
        self.detail = detail
        self.status_code = 404


class PermissionError(Exception):
    """Caller lacks required role or permission."""

    def __init__(self, detail: str = "Insufficient permissions") -> None:
        self.detail = detail
        self.status_code = 403


class ValidationError(Exception):
    """Request data failed business-rule validation."""

    def __init__(self, detail: str = "Validation error") -> None:
        self.detail = detail
        self.status_code = 422
