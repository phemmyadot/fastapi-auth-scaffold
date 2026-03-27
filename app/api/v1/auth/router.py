from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.auth.dependencies import get_current_user
from app.core.rate_limit import limiter
from app.db.base import get_db
from app.db.models.user import User
from app.schemas.auth import (
    LoginRequest,
    PasswordResetConfirm,
    PasswordResetRequest,
    RefreshRequest,
    RegisterRequest,
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
    return user


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate user",
    description="Returns access + refresh tokens. Locks account after 5 failed attempts in 10 minutes.",
)
@limiter.limit("10/minute")
async def login(
    request: Request,
    body: LoginRequest,
    db: AsyncSession = Depends(get_db),
):
    service = AuthService(db)
    return await service.login(
        email=body.email,
        password=body.password,
        user_agent=request.headers.get("user-agent", ""),
        ip_address=request.client.host if request.client else "",
    )


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
    return await service.refresh(
        refresh_token=body.refresh_token,
        user_agent=request.headers.get("user-agent", ""),
        ip_address=request.client.host if request.client else "",
    )


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
        return {"detail": "Phone verified successfully"}
