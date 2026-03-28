# FastAPI Authentication Scaffold — Implementation Plan

> Reference: `docs/auth_scaffold_spec.pdf` (Technical Specification v1.0)

## [CONFIGURATION]

```
PROJECT_NAME=my_project
AUTH_TIER=basic                    # basic | standard | complex
DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/dbname
JWT_SECRET=your_secret_here
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7
CORS_ORIGINS=http://localhost:3000

# Optional feature flags — set to true/false
# Flags have minimum tier requirements (see Spec §5):
#   standard: EMAIL_VERIFICATION, PHONE_VERIFICATION, TOTP_2FA
#   complex:  API_KEY_AUTH, RBAC, OAUTH2, AUDIT_LOGGING
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

## Phase 1: Project Setup & Configuration [Spec §2, §3, §9, §11]

- [x] **1.1** Create `requirements.txt` — always: fastapi, uvicorn, sqlalchemy[asyncio], asyncpg, alembic, pydantic, passlib[bcrypt], python-jose[cryptography], python-multipart, slowapi, aiosmtplib, jinja2; conditional: twilio (phone), pyotp (totp), httpx (oauth2), structlog (audit); dev: pytest-asyncio, httpx [Spec §3]
- [x] **1.2** Create `.env.example` with all configuration variables, no real secrets [Spec §9]
- [x] **1.3** Create `alembic.ini` configured for async PostgreSQL
- [x] **1.4** Create `Makefile` with targets: dev, migrate, revision, test, lint, seed [Spec §11]
- [x] **1.5** Create `app/core/config.py` — Pydantic Settings class reading from `.env`; include AUTH_TIER, all feature flags, CORS_ORIGINS; enforce min-tier requirements per flag (e.g. ENABLE_RBAC requires complex) [Spec §5, §9]

## Phase 2: Database Layer [Spec §6]

- [x] **2.1** Create `app/db/base.py` — SQLAlchemy async engine + session factory
- [x] **2.2** Create `app/db/models/__init__.py` — model registry
- [x] **2.3** Create `app/db/models/user.py` — `User` model: id (UUID PK), email (unique), username (unique, nullable), hashed_password (nullable — null for OAuth-only accounts), is_active, is_verified, created_at, updated_at. Flag-gated columns: email_verified_at, phone_number, phone_verified_at, totp_secret (encrypted), totp_enabled [Spec §6 User]
- [x] **2.4** Create `app/db/models/token.py` — `RefreshToken` model: id (UUID PK), user_id (FK), token_hash (SHA-256), expires_at, revoked, created_at, user_agent, ip_address [Spec §6 RefreshToken]
- [x] **2.5** Create `app/db/models/api_key.py` — `ApiKey` model: id (UUID PK), user_id (FK), name, key_hash (SHA-256), prefix (first 8 chars plaintext), scopes (list[str] array), last_used_at (nullable), expires_at (nullable), revoked, created_at *(complex tier, ENABLE_API_KEY_AUTH)* [Spec §6 ApiKey]
- [x] **2.6** Create `app/db/models/role.py` — `Role` model: id, name (unique), description, permissions (JSONB list[str]); `UserRole` join table: user_id (FK), role_id (FK) — composite PK *(complex tier, ENABLE_RBAC)* [Spec §6 Role/UserRole]
- [x] **2.7** Create `app/db/models/oauth_account.py` — `OAuthAccount` model: id (UUID PK), user_id (FK), provider (enum: google, github), provider_user_id, access_token (encrypted), refresh_token (encrypted, nullable), token_expires_at, created_at *(complex tier, ENABLE_OAUTH2)* [Spec §6 OAuthAccount]
- [x] **2.8** Create `app/db/models/audit_log.py` — `AuditLog` model: id (UUID PK), user_id (FK, nullable), event_type (enum, 20+ values), ip_address, user_agent, metadata (JSONB), created_at *(complex tier, ENABLE_AUDIT_LOGGING)* [Spec §6 AuditLog]
- [x] **2.9** Create `app/db/repositories/__init__.py`
- [x] **2.10** Create `app/db/repositories/user_repo.py` — CRUD for User
- [x] **2.11** Create `app/db/repositories/token_repo.py` — CRUD for RefreshToken
- [x] **2.12** Create `migrations/env.py` — Alembic async migration environment
- [ ] **2.13** Generate initial Alembic migration *(deferred — requires running DB)*

## Phase 3: Schemas (Pydantic v2) [Spec §2]

- [x] **3.1** Create `app/schemas/auth.py` — RegisterRequest, LoginRequest, TokenResponse, RefreshRequest, PasswordResetRequest, PasswordResetConfirm
- [x] **3.2** Create `app/schemas/user.py` — UserResponse, UserUpdate
- [x] **3.3** Create `app/schemas/token.py` — token-related schemas
- [x] **3.4** Create `app/schemas/api_key.py` — ApiKeyCreate, ApiKeyResponse *(complex tier, ENABLE_API_KEY_AUTH)*

## Phase 4: Core Security & Utilities [Spec §3, §8]

- [x] **4.1** Create `app/core/security.py` — password hashing (bcrypt 12 rounds), JWT creation/verification (HS256), token comparison with `hmac.compare_digest` (constant-time) [Spec §8]
- [x] **4.2** Create `app/core/email.py` — async email sending via aiosmtplib + jinja2 HTML templates [Spec §3]
- [x] **4.3** Create `app/core/rate_limit.py` — slowapi limiter configuration [Spec §3]
- [x] **4.4** Create custom exception classes: `AuthError`, `NotFoundError`, `PermissionError`, `ValidationError` — all return RFC 7807 Problem JSON [Spec §4 Basic, §8]

## Phase 5: Services (Business Logic) [Spec §2, §4]

- [x] **5.1** Create `app/services/auth_service.py` — register, login (with account lockout after 5 failed attempts in 10-min window), refresh (token rotation), logout, logout-all, password-reset-request (1hr signed link, single-use), password-reset-confirm (invalidates all refresh tokens) [Spec §4 Basic]
- [x] **5.2** Create `app/services/user_service.py` — get profile, update profile (username/display name)

## Phase 6: API Routes — BASIC Tier [Spec §4 Basic, §7 Core Auth, §8]

- [x] **6.1** Create `app/api/v1/auth/dependencies.py` — `get_current_user`, `require_role`, `require_scope` [Spec §2]
- [x] **6.2** Create `app/api/v1/auth/__init__.py`
- [x] **6.3** Create `app/api/v1/auth/router.py` — all basic auth endpoints [Spec §7 Core Auth]:
  - `POST /auth/register` — email + password (or username + password), returns 201 with user
  - `POST /auth/login` — returns {access_token, refresh_token, token_type}, lockout after 5 failures/10 min
  - `POST /auth/refresh` — validate refresh token hash, rotate tokens (old invalidated)
  - `POST /auth/logout` — revoke current refresh token
  - `POST /auth/logout-all` — revoke all refresh tokens for user
  - `POST /auth/password-reset/request` — send reset link via email (1hr token, single-use)
  - `POST /auth/password-reset/confirm` — validate token, update password, invalidate all refresh tokens
- [x] **6.4** Create `app/api/v1/users/__init__.py`
- [x] **6.5** Create `app/api/v1/users/router.py` — `GET /users/me`, `PATCH /users/me` [Spec §7 Core Auth]
- [x] **6.6** Create `app/api/__init__.py`
- [x] **6.7** Create `app/api/router.py` — aggregate all v1 routers
- [x] **6.8** Create `app/main.py` — FastAPI app factory, CORS (from CORS_ORIGINS), security headers middleware (X-Frame-Options: DENY, X-Content-Type-Options: nosniff, HSTS), global exception handler (RFC 7807 Problem JSON: {type, title, status, detail, instance}), rate limiting, router inclusion [Spec §8]
- [x] **6.9** Rate limits: 10 req/min on `/auth/login`, 5 req/min on `/auth/register`, 3 req/min on `/auth/password-reset/request` [Spec §4 Basic]
- [x] **6.10** HTTP-only cookie option for refresh token (configurable) [Spec §4 Basic]
- [x] **6.11** Identical error message for "user not found" vs "wrong password" on login (prevent user enumeration) [Spec §8]

## Phase 7: STANDARD Tier Features (skip if AUTH_TIER=basic) [Spec §4 Standard, §5, §7]

### Email Verification (if ENABLE_EMAIL_VERIFICATION=true) [Spec §4 Standard, §7 Email Verification]
- [x] **7.1** Add `email_verified_at` (nullable datetime) to `User` model (flag-gated column) [Spec §6 User]
- [x] **7.2** `POST /auth/email/send-verification` — sends signed verification link (valid 24h) [Spec §7]
- [x] **7.3** `GET /auth/email/verify?token=...` — marks email verified [Spec §7]
- [x] **7.4** `require_verified_email` dependency — raises 403 if unverified, apply to sensitive routes [Spec §4 Standard]
- [x] **7.5** Resend throttle: max 3 resends per hour per user [Spec §4 Standard]

### Phone Verification (if ENABLE_PHONE_VERIFICATION=true) [Spec §4 Standard, §7 Phone/SMS OTP]
- [x] **7.6** Create `app/core/sms.py` — Twilio SMS sending [Spec §3]
- [x] **7.7** Add `phone_number` (unique, nullable), `phone_verified_at` (nullable datetime) to `User` model (flag-gated) [Spec §6 User]
- [x] **7.8** `POST /auth/phone/send-otp` — sends 6-digit OTP via Twilio, store hashed OTP + expiry (10 min) [Spec §7]
- [x] **7.9** `POST /auth/phone/verify-otp` — validates OTP, marks phone verified, OTP single-use [Spec §7]
- [x] **7.10** Rate limit: max 3 OTP sends per hour per phone number [Spec §4 Standard]

### TOTP 2FA (if ENABLE_TOTP_2FA=true) [Spec §4 Standard, §7 TOTP 2FA]
- [x] **7.11** Create `app/core/totp.py` — TOTP helpers using pyotp, Google Authenticator compatible [Spec §3]
- [x] **7.12** Add `totp_secret` (encrypted at rest), `totp_enabled` (bool) to `User` model (flag-gated) [Spec §6 User, §8]
- [x] **7.13** `POST /auth/totp/setup` — generates secret, returns {secret, otpauth_url, qr_code_data_uri} + 8 backup codes [Spec §7]
- [x] **7.14** `POST /auth/totp/enable` — verifies first TOTP code, activates 2FA [Spec §7]
- [x] **7.15** `POST /auth/totp/disable` — requires current password + valid TOTP code [Spec §4 Standard, §7]
- [x] **7.16** `POST /auth/totp/verify` — exchange session_token + TOTP code for final tokens (used during login as second factor) [Spec §7]
- [x] **7.17** Two-step login flow: if `totp_enabled=true`, `/auth/login` returns `{requires_totp: true, session_token: "..."}`, client calls `/auth/totp/verify` with session_token + totp_code to get final tokens [Spec §4 Standard]
- [x] **7.18** Generate 8 single-use backup codes on TOTP setup, store hashed [Spec §4 Standard]

## Phase 8: COMPLEX Tier Features (skip if AUTH_TIER=basic or standard) [Spec §4 Complex, §5, §7]

### API Key Auth (if ENABLE_API_KEY_AUTH=true) [Spec §4 Complex, §7 API Keys]
- [x] **8.1** Wire `ApiKey` model from Phase 2.5 into routes [Spec §6 ApiKey]
- [x] **8.2** `POST /users/me/api-keys` — generates new API key, return raw key ONCE on creation, store only SHA-256 hash [Spec §7, §8]
- [x] **8.3** `GET /users/me/api-keys` — list keys (prefix + metadata only, never raw key) [Spec §7]
- [x] **8.4** `DELETE /users/me/api-keys/{key_id}` — revoke key [Spec §7]
- [x] **8.5** Update `get_current_user` dependency: detect `Authorization: ApiKey <key>` header, lookup by hash, validate scopes, update `last_used_at` [Spec §4 Complex]
- [x] **8.6** `require_scope("read:profile")` dependency for protected routes [Spec §4 Complex]

### RBAC (if ENABLE_RBAC=true) [Spec §4 Complex, §7 Admin]
- [x] **8.7** Wire `Role`/`UserRole` models from Phase 2.6 into routes [Spec §6 Role/UserRole]
- [x] **8.8** Seed default roles: super_admin, admin, user [Spec §6 Role/UserRole]
- [x] **8.9** `require_role("admin")` dependency — raises 403 if user lacks role [Spec §4 Complex]
- [x] **8.10** `require_permission("users:delete")` dependency [Spec §4 Complex]
- [x] **8.11** `GET /admin/users` — list all users, paginated (admin only) [Spec §7 Admin]
- [x] **8.12** `POST /admin/users/{user_id}/roles` — assign role (super_admin only) [Spec §7 Admin]
- [x] **8.13** `DELETE /admin/users/{user_id}/roles/{role_id}` — remove role (super_admin only) [Spec §7 Admin]
- [x] **8.14** `POST /admin/users/{user_id}/ban` — set is_active=false, revoke all tokens [Spec §7 Admin]
- [x] **8.15** `POST /admin/users/{user_id}/unban` — reactivate account [Spec §7 Admin]
- [x] **8.16** Create `app/scripts/seed_roles.py` for `make seed` [Spec §11]

### OAuth2 (if ENABLE_OAUTH2=true) [Spec §4 Complex, §7 OAuth2]
- [x] **8.17** Create `app/core/oauth2.py` — OAuth2 flows for Google + GitHub with PKCE, encrypted token storage [Spec §4 Complex, §8]
- [x] **8.18** Wire `OAuthAccount` model from Phase 2.7 into routes [Spec §6 OAuthAccount]
- [x] **8.19** `GET /auth/oauth/{provider}` — redirects to provider's OAuth consent screen with PKCE state [Spec §7]
- [x] **8.20** `GET /auth/oauth/{provider}/callback` — handles callback, exchanges code for user info, creates or links user account [Spec §7]
- [x] **8.21** Account linking: if email exists link to existing user; if not create new user (hashed_password=null) [Spec §4 Complex]
- [x] **8.22** `GET /users/me/connected-accounts` — list linked OAuth providers [Spec §7]
- [x] **8.23** `DELETE /users/me/connected-accounts/{provider}` — unlink guard: cannot remove last login method (must have password set or another provider linked) [Spec §4 Complex]

### Audit Logging (if ENABLE_AUDIT_LOGGING=true) [Spec §4 Complex, §7 Admin]
- [x] **8.24** Create `app/core/audit.py` — non-blocking fire-and-forget audit log writer using `asyncio.create_task` + structlog [Spec §3, §4 Complex]
- [x] **8.25** Wire `AuditLog` model from Phase 2.8 into routes [Spec §6 AuditLog]
- [x] **8.26** Event types (20+): register, login_success, login_failed, logout, logout_all, password_reset_request, password_reset_confirm, email_verification_sent, email_verified, phone_otp_sent, phone_verified, totp_enabled, totp_disabled, totp_failed, api_key_created, api_key_revoked, oauth_login, role_assigned, role_removed, user_banned, token_refreshed [Spec §4 Complex]
- [x] **8.27** Instrument all auth endpoints with audit logging calls
- [x] **8.28** `GET /admin/audit-logs` — paginated, filterable by user_id, event_type, date range (admin only) [Spec §7 Admin]

## Phase 9: Testing [Spec §10]

- [x] **9.1** Create `tests/conftest.py` — async test client (pytest-asyncio + httpx.AsyncClient), test DB lifecycle, user fixtures for each tier [Spec §10]
- [x] **9.2** Create `tests/test_auth_basic.py` — register, login, refresh, logout, logout-all, password reset, account lockout [Spec §10]
- [x] **9.3** Create `tests/test_email_verification.py` *(if ENABLE_EMAIL_VERIFICATION)* — send link, verify, expired link, resend throttle, route guard (require_verified_email) [Spec §10]
- [x] **9.4** Create `tests/test_phone_otp.py` *(if ENABLE_PHONE_VERIFICATION)* — send OTP, verify OTP, expired OTP, reuse rejection, rate limit [Spec §10]
- [x] **9.5** Create `tests/test_totp.py` *(if ENABLE_TOTP_2FA)* — setup, enable, two-step login, backup code use, disable [Spec §10]
- [x] **9.6** Create `tests/test_api_keys.py` *(if ENABLE_API_KEY_AUTH)* — create, list, authenticate via ApiKey header, scope rejection, revoke [Spec §10]
- [x] **9.7** Create `tests/test_rbac.py` *(if ENABLE_RBAC)* — role assignment, permission enforcement, admin routes, ban/unban [Spec §10]
- [x] **9.8** Create `tests/test_audit.py` *(if ENABLE_AUDIT_LOGGING)* — verify correct event type logged after each auth action [Spec §10]
- [x] **9.9** Mock Twilio and SMTP in tests using `unittest.mock.patch` [Spec §10]

## Phase 10: Documentation & Final Wiring [Spec §8, §12]

- [x] **10.1** Add `tags`, `summary`, and `description` to every router endpoint
- [x] **10.2** Create `docs/AUTH_FLOWS.md` — login flows for each tier with ASCII sequence diagrams
- [x] **10.3** Security hardening review against Spec §8 checklist:
  - All token comparisons use `hmac.compare_digest` (constant-time) ✓
  - Passwords never logged, never returned in any response body ✓
  - Identical error for "user not found" vs "wrong password" (no user enumeration) ✓
  - Refresh tokens stored as SHA-256 hash only; raw never persisted ✓
  - UUIDs for all primary keys (no sequential integers) ✓
  - All queries use SQLAlchemy ORM parameterized statements (no string interpolation) ✓
  - Security headers: X-Frame-Options: DENY, X-Content-Type-Options: nosniff, HSTS ✓
  - totp_secret and OAuth tokens stored encrypted at rest ✓
  - Emails lowercased and stripped on all input paths ✓
  - Global exception handler strips internal detail; RFC 7807 only ✓
  - `.env.example` contains all variables, no real secrets ✓
