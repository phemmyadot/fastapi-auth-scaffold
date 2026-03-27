# FastAPI Authentication Scaffold — Implementation Plan

## [CONFIGURATION]

```
PROJECT_NAME=my_project
AUTH_TIER=basic                    # basic | standard | complex
DB_URL=postgresql+asyncpg://user:password@localhost:5432/dbname
JWT_SECRET=your_secret_here
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7

# Optional feature flags — set to true/false
ENABLE_EMAIL_VERIFICATION=true
ENABLE_PHONE_VERIFICATION=true     # Requires Twilio
ENABLE_TOTP_2FA=true               # Time-based OTP (Google Authenticator)
ENABLE_OAUTH2=true                 # Google + GitHub
ENABLE_API_KEY_AUTH=true
ENABLE_RBAC=true
ENABLE_AUDIT_LOGGING=true

# Twilio (only if ENABLE_PHONE_VERIFICATION=true)
TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
TWILIO_AUTH_TOKEN=your_twilio_auth_token
TWILIO_FROM_NUMBER=+1xxxxxxxxxx

# OAuth2 (only if ENABLE_OAUTH2=true)
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
OAUTH2_REDIRECT_BASE_URL=http://localhost:8000

# Email (for verification + password reset)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=you@gmail.com
SMTP_PASSWORD=your_app_password
EMAIL_FROM=no-reply@yourdomain.com
```

---

## Phase 1: Project Setup & Configuration

- [ ] **1.1** Create `requirements.txt` with all dependencies (fastapi, uvicorn, sqlalchemy[asyncio], asyncpg, alembic, pydantic, passlib[bcrypt], python-jose[cryptography], python-multipart, httpx, pyotp, twilio, aiosmtplib, jinja2, slowapi, structlog, pytest-asyncio)
- [ ] **1.2** Create `.env.example` with all configuration variables (no real secrets)
- [ ] **1.3** Create `alembic.ini` configured for async PostgreSQL
- [ ] **1.4** Create `Makefile` with targets: dev, migrate, revision, test, lint, seed
- [ ] **1.5** Create `app/core/config.py` — Pydantic Settings class loading from `.env`, with all feature flags and tier logic

## Phase 2: Database Layer

- [ ] **2.1** Create `app/db/base.py` — SQLAlchemy async engine + session factory
- [ ] **2.2** Create `app/db/models/__init__.py` — model registry
- [ ] **2.3** Create `app/db/models/user.py` — `User` model (id UUID, email, username, hashed_password, is_active, is_verified, created_at, updated_at)
- [ ] **2.4** Create `app/db/models/token.py` — `RefreshToken` model (id, user_id FK, token_hash SHA-256, expires_at, revoked, created_at, user_agent, ip_address)
- [ ] **2.5** Create `app/db/models/api_key.py` — `ApiKey` model *(complex tier, if ENABLE_API_KEY_AUTH)*
- [ ] **2.6** Create `app/db/models/audit_log.py` — `AuditLog` model *(complex tier, if ENABLE_AUDIT_LOGGING)*
- [ ] **2.7** Create `app/db/repositories/__init__.py`
- [ ] **2.8** Create `app/db/repositories/user_repo.py` — CRUD for User
- [ ] **2.9** Create `app/db/repositories/token_repo.py` — CRUD for RefreshToken
- [ ] **2.10** Create `migrations/env.py` — Alembic async migration environment
- [ ] **2.11** Generate initial Alembic migration

## Phase 3: Schemas (Pydantic v2)

- [ ] **3.1** Create `app/schemas/auth.py` — RegisterRequest, LoginRequest, TokenResponse, RefreshRequest, PasswordResetRequest, PasswordResetConfirm
- [ ] **3.2** Create `app/schemas/user.py` — UserResponse, UserUpdate
- [ ] **3.3** Create `app/schemas/token.py` — token-related schemas
- [ ] **3.4** Create `app/schemas/api_key.py` — ApiKeyCreate, ApiKeyResponse *(complex tier)*

## Phase 4: Core Security & Utilities

- [ ] **4.1** Create `app/core/security.py` — password hashing (bcrypt 12 rounds), JWT creation/verification (HS256), token comparison with `hmac.compare_digest`
- [ ] **4.2** Create `app/core/email.py` — async email sending via aiosmtplib + jinja2 templates
- [ ] **4.3** Create `app/core/rate_limit.py` — slowapi limiter configuration
- [ ] **4.4** Create custom exception classes: `AuthError`, `NotFoundError`, `PermissionError`, `ValidationError`

## Phase 5: Services (Business Logic)

- [ ] **5.1** Create `app/services/auth_service.py` — register, login (with account lockout after 5 failed attempts in 10 min), refresh, logout, logout-all, password-reset-request, password-reset-confirm
- [ ] **5.2** Create `app/services/user_service.py` — get profile, update profile

## Phase 6: API Routes — BASIC Tier

- [ ] **6.1** Create `app/api/v1/auth/dependencies.py` — `get_current_user`, `require_role`, etc.
- [ ] **6.2** Create `app/api/v1/auth/__init__.py`
- [ ] **6.3** Create `app/api/v1/auth/router.py` — all auth endpoints:
  - `POST /auth/register` — email + password (or username + password), returns 201 with user
  - `POST /auth/login` — returns {access_token, refresh_token, token_type}, lockout logic
  - `POST /auth/refresh` — validate refresh token hash, rotate tokens
  - `POST /auth/logout` — revoke current refresh token
  - `POST /auth/logout-all` — revoke all user refresh tokens
  - `POST /auth/password-reset/request` — send reset link via email (1hr token)
  - `POST /auth/password-reset/confirm` — validate token, update password, revoke tokens
- [ ] **6.4** Create `app/api/v1/users/__init__.py`
- [ ] **6.5** Create `app/api/v1/users/router.py` — `GET /users/me`, `PATCH /users/me`
- [ ] **6.6** Create `app/api/__init__.py`
- [ ] **6.7** Create `app/api/router.py` — aggregate all v1 routers
- [ ] **6.8** Create `app/main.py` — FastAPI app, CORS, security headers middleware, global exception handler (RFC 7807 Problem JSON), rate limiting, router inclusion
- [ ] **6.9** Rate limits: 10 req/min on `/auth/login`, 5 req/min on `/auth/register`, 3 req/min on `/auth/password-reset/request`

## Phase 7: STANDARD Tier Features (skip if AUTH_TIER=basic)

### Email Verification (if ENABLE_EMAIL_VERIFICATION=true)
- [ ] **7.1** Add `email_verified_at` (nullable datetime) to `User` model
- [ ] **7.2** `POST /auth/email/send-verification` — sends signed verification link (valid 24h)
- [ ] **7.3** `GET /auth/email/verify?token=...` — marks email verified
- [ ] **7.4** `require_verified_email` dependency — raises 403 if unverified
- [ ] **7.5** Resend throttle: max 3 resends per hour per user

### Phone Verification (if ENABLE_PHONE_VERIFICATION=true)
- [ ] **7.6** Create `app/core/sms.py` — Twilio SMS sending
- [ ] **7.7** Add `phone_number` (unique, nullable), `phone_verified_at` to `User` model
- [ ] **7.8** `POST /auth/phone/send-otp` — sends 6-digit OTP via Twilio, store hashed OTP + expiry (10 min)
- [ ] **7.9** `POST /auth/phone/verify-otp` — validates OTP, marks phone verified, OTP single-use
- [ ] **7.10** Rate limit: max 3 OTP sends per hour per phone number

### TOTP 2FA (if ENABLE_TOTP_2FA=true)
- [ ] **7.11** Create `app/core/totp.py` — TOTP helpers using pyotp
- [ ] **7.12** Add `totp_secret` (encrypted at rest), `totp_enabled` (bool) to `User` model
- [ ] **7.13** `POST /auth/totp/setup` — generates secret, returns {secret, otpauth_url, qr_code_data_uri}
- [ ] **7.14** `POST /auth/totp/enable` — verifies first TOTP code, enables 2FA
- [ ] **7.15** `POST /auth/totp/disable` — requires current password + TOTP code
- [ ] **7.16** `POST /auth/totp/verify` — standalone TOTP check (used during login as second factor)
- [ ] **7.17** Login flow modification: if `totp_enabled=true`, `/auth/login` returns `{requires_totp: true, session_token: "..."}`, client calls `/auth/totp/verify` with session_token + totp_code
- [ ] **7.18** Generate 8 single-use backup codes on TOTP setup, store hashed

## Phase 8: COMPLEX Tier Features (skip if AUTH_TIER=basic or standard)

### API Key Auth (if ENABLE_API_KEY_AUTH=true)
- [ ] **8.1** `ApiKey` model: id, user_id FK, name, key_hash SHA-256, prefix (first 8 chars), scopes (array of strings), last_used_at, expires_at (nullable), revoked, created_at
- [ ] **8.2** `POST /users/me/api-keys` — generates new API key, return raw key ONCE, store only hash
- [ ] **8.3** `GET /users/me/api-keys` — list keys (prefix + metadata, never raw key)
- [ ] **8.4** `DELETE /users/me/api-keys/{key_id}` — revoke key
- [ ] **8.5** Update `get_current_user` dependency: detect `Authorization: ApiKey <key>` header, lookup by hash, validate scopes, update `last_used_at`
- [ ] **8.6** `require_scope("read:profile")` dependency for protected routes

### RBAC (if ENABLE_RBAC=true)
- [ ] **8.7** `Role` model: id, name (unique), description, permissions (JSONB array of strings)
- [ ] **8.8** `UserRole` join table: user_id, role_id
- [ ] **8.9** Seed default roles: super_admin, admin, user
- [ ] **8.10** `require_role("admin")` dependency — raises 403 if user lacks role
- [ ] **8.11** `require_permission("users:delete")` dependency
- [ ] **8.12** `GET /admin/users` — list all users (admin only)
- [ ] **8.13** `POST /admin/users/{user_id}/roles` — assign role (super_admin only)
- [ ] **8.14** `DELETE /admin/users/{user_id}/roles/{role_id}` — remove role (super_admin only)
- [ ] **8.15** `POST /admin/users/{user_id}/ban` — set is_active=false, revoke all tokens
- [ ] **8.16** `POST /admin/users/{user_id}/unban`
- [ ] **8.17** Create `app/scripts/seed_roles.py` for `make seed`

### OAuth2 (if ENABLE_OAUTH2=true)
- [ ] **8.18** Create `app/core/oauth2.py` — OAuth2 flows for Google + GitHub with PKCE
- [ ] **8.19** `OAuthAccount` model: id, user_id FK, provider (enum: google, github), provider_user_id, access_token (encrypted), refresh_token (encrypted, nullable), token_expires_at, created_at
- [ ] **8.20** `GET /auth/oauth/{provider}` — redirects to provider's OAuth consent screen with PKCE state
- [ ] **8.21** `GET /auth/oauth/{provider}/callback` — handles callback, exchanges code for user info, creates or links user account
- [ ] **8.22** Account linking: if email exists link to existing user; if not create new user (hashed_password=null)
- [ ] **8.23** `GET /users/me/connected-accounts` — list linked OAuth providers
- [ ] **8.24** `DELETE /users/me/connected-accounts/{provider}` — unlink (only if user has password or another provider linked)

### Audit Logging (if ENABLE_AUDIT_LOGGING=true)
- [ ] **8.25** Create `app/core/audit.py` — fire-and-forget audit log writer using `asyncio.create_task`
- [ ] **8.26** `AuditLog` model: id, user_id FK (nullable), event_type (enum), ip_address, user_agent, metadata (JSONB), created_at
- [ ] **8.27** Event types: register, login_success, login_failed, logout, logout_all, password_reset_request, password_reset_confirm, email_verification_sent, email_verified, phone_otp_sent, phone_verified, totp_enabled, totp_disabled, totp_failed, api_key_created, api_key_revoked, oauth_login, role_assigned, role_removed, user_banned, token_refreshed
- [ ] **8.28** Instrument all auth endpoints with audit logging calls
- [ ] **8.29** `GET /admin/audit-logs` — paginated, filterable by user_id, event_type, date range (admin only)

## Phase 9: Testing

- [ ] **9.1** Create `tests/conftest.py` — async test client, test DB setup/teardown, user fixtures per tier
- [ ] **9.2** Create `tests/test_auth_basic.py` — register, login, refresh, logout, password reset
- [ ] **9.3** Create `tests/test_email_verification.py` *(if enabled)* — send, verify, resend throttle
- [ ] **9.4** Create `tests/test_phone_otp.py` *(if enabled)* — send OTP, verify OTP, expired OTP, reuse rejection
- [ ] **9.5** Create `tests/test_totp.py` *(if enabled)* — setup, enable, login with TOTP, backup codes
- [ ] **9.6** Create `tests/test_api_keys.py` *(if enabled)* — create, list, use on route, revoke
- [ ] **9.7** Create `tests/test_rbac.py` *(if enabled)* — role assignment, permission enforcement, admin routes
- [ ] **9.8** Create `tests/test_audit.py` *(if enabled)* — verify events are logged correctly
- [ ] **9.9** Mock Twilio and SMTP in tests using `unittest.mock.patch`

## Phase 10: Documentation & Final Wiring

- [ ] **10.1** Add `tags`, `summary`, and `description` to every router endpoint
- [ ] **10.2** Create `docs/AUTH_FLOWS.md` — login flows for each tier with ASCII sequence diagrams
- [ ] **10.3** Final review: ensure no plaintext passwords logged, no stack traces exposed, parameterized queries only, UUIDs for all PKs, emails lowercased/stripped, security headers middleware in place
