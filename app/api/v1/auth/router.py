from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.auth.dependencies import get_current_user
from app.core.audit import emit_audit_log
from app.core.rate_limit import limiter
from app.db.base import get_db
from app.db.models.audit_log import AuditEventType
from app.db.models.user import User
from app.schemas.auth import (
    LoginRequest,
    PasswordResetConfirm,
    PasswordResetRequest,
    RefreshRequest,
    RegisterRequest,
    TOTPChallengeResponse,
    TokenResponse,
)
from app.core.config import settings
from app.schemas.user import UserResponse
from app.services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
    description="Create a new account with email + password (and optional username). Returns the created user.",
)
@limiter.limit("5/minute")
async def register(
    request: Request,
    body: RegisterRequest,
    db: AsyncSession = Depends(get_db),
):
    service = AuthService(db)
    user = await service.register(
        email=body.email,
        password=body.password,
        username=body.username,
    )
    emit_audit_log(
        AuditEventType.REGISTER,
        user_id=user.id,
        ip_address=request.client.host if request.client else "",
        user_agent=request.headers.get("user-agent", ""),
    )
    return user


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate user",
    description="Returns access + refresh tokens. If TOTP is enabled, returns a session token for the two-step flow. Locks account after 5 failed attempts in 10 minutes.",
)
@limiter.limit("10/minute")
async def login(
    request: Request,
    body: LoginRequest,
    db: AsyncSession = Depends(get_db),
):
    service = AuthService(db)
    ip = request.client.host if request.client else ""
    ua = request.headers.get("user-agent", "")
    try:
        result = await service.login(
            email=body.email,
            password=body.password,
            user_agent=ua,
            ip_address=ip,
        )
    except Exception:
        emit_audit_log(AuditEventType.LOGIN_FAILED, ip_address=ip, user_agent=ua, metadata={"email": body.email})
        raise

    user = await service.user_repo.get_by_email(body.email.lower().strip())

    # Two-step TOTP login flow (Spec §4 Standard)
    if settings.ENABLE_TOTP_2FA:
        from app.services.totp_service import TOTPService
        if user and getattr(user, "totp_enabled", False):
            # Revoke the tokens we just issued — they shouldn't be usable without TOTP
            await service.logout(refresh_token=result.refresh_token)
            totp_service = TOTPService(db)
            session_token = await totp_service.create_session_token(user.id)
            return TOTPChallengeResponse(session_token=session_token).model_dump()

    emit_audit_log(AuditEventType.LOGIN_SUCCESS, user_id=user.id if user else None, ip_address=ip, user_agent=ua)
    return result


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refresh access token",
    description="Validates refresh token hash, rotates tokens (old invalidated).",
)
async def refresh(
    request: Request,
    body: RefreshRequest,
    db: AsyncSession = Depends(get_db),
):
    service = AuthService(db)
    result = await service.refresh(
        refresh_token=body.refresh_token,
        user_agent=request.headers.get("user-agent", ""),
        ip_address=request.client.host if request.client else "",
    )
    emit_audit_log(
        AuditEventType.TOKEN_REFRESHED,
        ip_address=request.client.host if request.client else "",
        user_agent=request.headers.get("user-agent", ""),
    )
    return result


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Logout (revoke refresh token)",
    description="Revokes the provided refresh token.",
)
async def logout(
    body: RefreshRequest,
    db: AsyncSession = Depends(get_db),
):
    service = AuthService(db)
    await service.logout(refresh_token=body.refresh_token)
    emit_audit_log(AuditEventType.LOGOUT)


@router.post(
    "/logout-all",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Logout all sessions",
    description="Revokes all refresh tokens for the current user.",
)
async def logout_all(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    service = AuthService(db)
    await service.logout_all(user_id=current_user.id)
    emit_audit_log(AuditEventType.LOGOUT_ALL, user_id=current_user.id)


@router.post(
    "/password-reset/request",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Request password reset",
    description="Sends a reset link via email (1-hour token, single-use). Always returns success.",
)
@limiter.limit("3/minute")
async def password_reset_request(
    request: Request,
    body: PasswordResetRequest,
    db: AsyncSession = Depends(get_db),
):
    service = AuthService(db)
    await service.request_password_reset(email=body.email)
    emit_audit_log(
        AuditEventType.PASSWORD_RESET_REQUEST,
        ip_address=request.client.host if request.client else "",
        user_agent=request.headers.get("user-agent", ""),
    )


@router.post(
    "/password-reset/confirm",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Confirm password reset",
    description="Validates token, updates password, and invalidates all refresh tokens.",
)
async def password_reset_confirm(
    body: PasswordResetConfirm,
    db: AsyncSession = Depends(get_db),
):
    service = AuthService(db)
    await service.confirm_password_reset(token=body.token, new_password=body.new_password)
    emit_audit_log(AuditEventType.PASSWORD_RESET_CONFIRM)


# --- Email Verification (Standard tier, ENABLE_EMAIL_VERIFICATION) ---

if settings.ENABLE_EMAIL_VERIFICATION:
    from app.services.email_verification_service import EmailVerificationService

    @router.post(
        "/email/send-verification",
        status_code=status.HTTP_204_NO_CONTENT,
        summary="Send email verification link",
        description="Sends a signed verification link valid for 24 hours. Max 3 resends per hour.",
    )
    async def send_email_verification(
        current_user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ):
        service = EmailVerificationService(db)
        await service.send_verification(user_id=current_user.id, email=current_user.email)
        emit_audit_log(AuditEventType.EMAIL_VERIFICATION_SENT, user_id=current_user.id)

    @router.get(
        "/email/verify",
        status_code=status.HTTP_200_OK,
        summary="Verify email address",
        description="Marks the user's email as verified using the token from the verification link.",
    )
    async def verify_email(
        token: str,
        db: AsyncSession = Depends(get_db),
    ):
        service = EmailVerificationService(db)
        await service.verify_email(token=token)
        emit_audit_log(AuditEventType.EMAIL_VERIFIED)
        return {"detail": "Email verified successfully"}


# --- Phone Verification (Standard tier, ENABLE_PHONE_VERIFICATION) ---

if settings.ENABLE_PHONE_VERIFICATION:
    from app.schemas.phone import SendOTPRequest, VerifyOTPRequest
    from app.services.phone_verification_service import PhoneVerificationService

    @router.post(
        "/phone/send-otp",
        status_code=status.HTTP_204_NO_CONTENT,
        summary="Send phone OTP",
        description="Sends a 6-digit OTP via Twilio SMS. 10-minute expiry. Max 3 sends per hour per number.",
    )
    async def send_phone_otp(
        body: SendOTPRequest,
        current_user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ):
        service = PhoneVerificationService(db)
        await service.send_otp(user_id=current_user.id, phone_number=body.phone_number)
        emit_audit_log(AuditEventType.PHONE_OTP_SENT, user_id=current_user.id)

    @router.post(
        "/phone/verify-otp",
        status_code=status.HTTP_200_OK,
        summary="Verify phone OTP",
        description="Validates the OTP code and marks phone as verified. OTP is single-use.",
    )
    async def verify_phone_otp(
        body: VerifyOTPRequest,
        current_user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ):
        service = PhoneVerificationService(db)
        await service.verify_otp(user_id=current_user.id, otp_code=body.otp_code)
        emit_audit_log(AuditEventType.PHONE_VERIFIED, user_id=current_user.id)
        return {"detail": "Phone verified successfully"}


# --- TOTP 2FA (Standard tier, ENABLE_TOTP_2FA) ---

if settings.ENABLE_TOTP_2FA:
    from app.schemas.auth import TOTPVerifyRequest
    from app.schemas.totp import TOTPDisableRequest, TOTPEnableRequest, TOTPSetupResponse
    from app.services.totp_service import TOTPService

    @router.post(
        "/totp/setup",
        response_model=TOTPSetupResponse,
        summary="Setup TOTP 2FA",
        description="Generates a TOTP secret, returns QR code data URI and 8 single-use backup codes.",
    )
    async def totp_setup(
        current_user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ):
        service = TOTPService(db)
        return await service.setup(user_id=current_user.id, email=current_user.email)

    @router.post(
        "/totp/enable",
        status_code=status.HTTP_204_NO_CONTENT,
        summary="Enable TOTP 2FA",
        description="Verifies the first TOTP code from the authenticator app and activates 2FA.",
    )
    async def totp_enable(
        body: TOTPEnableRequest,
        current_user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ):
        service = TOTPService(db)
        await service.enable(user_id=current_user.id, totp_code=body.totp_code)
        emit_audit_log(AuditEventType.TOTP_ENABLED, user_id=current_user.id)

    @router.post(
        "/totp/disable",
        status_code=status.HTTP_204_NO_CONTENT,
        summary="Disable TOTP 2FA",
        description="Disables 2FA. Requires current password and a valid TOTP code.",
    )
    async def totp_disable(
        body: TOTPDisableRequest,
        current_user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ):
        service = TOTPService(db)
        await service.disable(
            user_id=current_user.id, password=body.password, totp_code=body.totp_code
        )
        emit_audit_log(AuditEventType.TOTP_DISABLED, user_id=current_user.id)

    @router.post(
        "/totp/verify",
        response_model=TokenResponse,
        summary="Verify TOTP code (two-step login)",
        description="Exchange session_token + TOTP code for final access/refresh tokens.",
    )
    async def totp_verify(
        request: Request,
        body: TOTPVerifyRequest,
        db: AsyncSession = Depends(get_db),
    ):
        service = TOTPService(db)
        return await service.verify_and_issue_tokens(
            session_token=body.session_token,
            totp_code=body.totp_code,
            user_agent=request.headers.get("user-agent", ""),
            ip_address=request.client.host if request.client else "",
        )


# --- OAuth2 (Complex tier, ENABLE_OAUTH2) ---

if settings.ENABLE_OAUTH2:
    from fastapi.responses import RedirectResponse
    from app.core.oauth2 import get_google_auth_url, get_github_auth_url
    from app.services.oauth_service import OAuthService

    @router.get(
        "/oauth/{provider}",
        summary="Initiate OAuth2 flow",
        description="Redirects to the provider's OAuth consent screen with PKCE state.",
        tags=["oauth"],
    )
    async def oauth_redirect(provider: str):
        if provider == "google":
            url, _state = get_google_auth_url()
        elif provider == "github":
            url, _state = get_github_auth_url()
        else:
            from app.core.exceptions import ValidationError
            raise ValidationError(f"Unsupported OAuth provider: {provider}")
        return RedirectResponse(url=url)

    @router.get(
        "/oauth/{provider}/callback",
        summary="OAuth2 callback",
        description="Handles OAuth callback, exchanges code for user info, creates or links user account, and returns tokens.",
        tags=["oauth"],
    )
    async def oauth_callback(
        provider: str,
        code: str,
        state: str,
        request: Request,
        db: AsyncSession = Depends(get_db),
    ):
        service = OAuthService(db)
        result = await service.handle_callback(
            provider=provider,
            code=code,
            state=state,
            user_agent=request.headers.get("user-agent", ""),
            ip_address=request.client.host if request.client else "",
        )
        emit_audit_log(
            AuditEventType.OAUTH_LOGIN,
            ip_address=request.client.host if request.client else "",
            user_agent=request.headers.get("user-agent", ""),
            metadata={"provider": provider},
        )
        return result
