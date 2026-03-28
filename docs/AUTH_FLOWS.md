# Authentication Flows

> Reference: `docs/auth_scaffold_spec.pdf` (Technical Specification v1.0)

## Tier Overview

| Tier | Features |
|------|----------|
| **Basic** | Register, login, refresh, logout, password reset, account lockout |
| **Standard** | + Email verification, phone OTP, TOTP 2FA |
| **Complex** | + API keys, RBAC, OAuth2 (Google/GitHub), audit logging |

---

## Basic Tier Flows

### Registration

```
Client                          Server
  |                               |
  |  POST /auth/register          |
  |  {email, password, username?} |
  |------------------------------>|
  |                               |  Validate input
  |                               |  Check duplicate email/username
  |                               |  Hash password (bcrypt, 12 rounds)
  |                               |  Create user (UUID PK)
  |  201 UserResponse             |
  |<------------------------------|
```

### Login (Password)

```
Client                          Server
  |                               |
  |  POST /auth/login             |
  |  {email, password}            |
  |------------------------------>|
  |                               |  Lowercase + strip email
  |                               |  Check lockout (5 fails / 10 min)
  |                               |  Lookup user by email
  |                               |  Verify password (bcrypt)
  |                               |  Issue JWT access token (HS256)
  |                               |  Generate refresh token (opaque)
  |                               |  Store SHA-256 hash of refresh token
  |  200 {access_token,           |
  |       refresh_token,          |
  |       token_type: "bearer"}   |
  |<------------------------------|
```

**Lockout:** After 5 failed attempts within 10 minutes, returns 429 until window expires.

**Enumeration prevention:** Both "user not found" and "wrong password" return identical `401 Invalid email or password`.

### Token Refresh (Rotation)

```
Client                          Server
  |                               |
  |  POST /auth/refresh           |
  |  {refresh_token}              |
  |------------------------------>|
  |                               |  Hash incoming token (SHA-256)
  |                               |  Lookup by hash, check not revoked
  |                               |  Revoke old refresh token
  |                               |  Issue new access + refresh tokens
  |  200 {access_token,           |
  |       refresh_token}          |
  |<------------------------------|
```

Old refresh token is invalidated after each use (rotation).

### Logout

```
Client                          Server
  |                               |
  |  POST /auth/logout            |
  |  {refresh_token}              |
  |------------------------------>|
  |                               |  Revoke refresh token
  |  204 No Content               |
  |<------------------------------|

  |  POST /auth/logout-all        |
  |  Authorization: Bearer <JWT>  |
  |------------------------------>|
  |                               |  Revoke ALL refresh tokens for user
  |  204 No Content               |
  |<------------------------------|
```

### Password Reset

```
Client                          Server                        Email
  |                               |                             |
  |  POST /password-reset/request |                             |
  |  {email}                      |                             |
  |------------------------------>|                             |
  |                               |  Lookup user (silent fail)  |
  |                               |  Create signed token (1hr)  |
  |                               |  Send reset email --------->|
  |  204 (always, even if         |                             |
  |       email not found)        |                             |
  |<------------------------------|                             |
  |                                                             |
  |  POST /password-reset/confirm                               |
  |  {token, new_password}        |                             |
  |------------------------------>|                             |
  |                               |  Decode + verify token      |
  |                               |  Update password hash       |
  |                               |  Revoke all refresh tokens  |
  |  204 No Content               |                             |
  |<------------------------------|                             |
```

---

## Standard Tier Flows

### Email Verification

```
Client                          Server                        Email
  |                               |                             |
  |  POST /email/send-verification|                             |
  |  Authorization: Bearer <JWT>  |                             |
  |------------------------------>|                             |
  |                               |  Check resend throttle      |
  |                               |  (max 3/hour)               |
  |                               |  Create signed token (24hr) |
  |                               |  Send verification email -->|
  |  204 No Content               |                             |
  |<------------------------------|                             |
  |                                                             |
  |  GET /email/verify?token=...  |                             |
  |------------------------------>|                             |
  |                               |  Decode signed token        |
  |                               |  Set email_verified_at      |
  |  200 {detail: "verified"}     |                             |
  |<------------------------------|                             |
```

### Phone OTP Verification

```
Client                          Server                        Twilio
  |                               |                             |
  |  POST /phone/send-otp         |                             |
  |  {phone_number}               |                             |
  |------------------------------>|                             |
  |                               |  Check throttle (3/hr/num)  |
  |                               |  Generate 6-digit OTP       |
  |                               |  Store hashed OTP (10 min)  |
  |                               |  Send SMS ----------------->|
  |  204 No Content               |                             |
  |<------------------------------|                             |
  |                                                             |
  |  POST /phone/verify-otp       |                             |
  |  {otp_code}                   |                             |
  |------------------------------>|                             |
  |                               |  Verify OTP (constant-time) |
  |                               |  Single-use: delete on read |
  |                               |  Set phone_verified_at      |
  |  200 {detail: "verified"}     |                             |
  |<------------------------------|                             |
```

### TOTP 2FA (Two-Step Login)

**Setup:**
```
Client                          Server
  |                               |
  |  POST /totp/setup             |
  |  Authorization: Bearer <JWT>  |
  |------------------------------>|
  |                               |  Generate TOTP secret
  |                               |  Generate 8 backup codes
  |  200 {secret, otpauth_url,    |
  |       qr_code_data_uri,       |
  |       backup_codes[8]}        |
  |<------------------------------|
  |                               |
  |  POST /totp/enable            |
  |  {totp_code}                  |
  |------------------------------>|
  |                               |  Verify code against secret
  |                               |  Persist secret, enable flag
  |  204 No Content               |
  |<------------------------------|
```

**Two-Step Login:**
```
Client                          Server
  |                               |
  |  POST /auth/login             |
  |  {email, password}            |
  |------------------------------>|
  |                               |  Validate credentials
  |                               |  Detect TOTP enabled
  |                               |  Revoke pre-issued tokens
  |                               |  Create session token (5min)
  |  200 {requires_totp: true,    |
  |       session_token}          |
  |<------------------------------|
  |                               |
  |  POST /totp/verify            |
  |  {session_token, totp_code}   |
  |------------------------------>|
  |                               |  Verify session token
  |                               |  Verify TOTP or backup code
  |                               |  Issue access + refresh tokens
  |  200 {access_token,           |
  |       refresh_token}          |
  |<------------------------------|
```

Backup codes are single-use and accepted in place of TOTP codes.

---

## Complex Tier Flows

### API Key Authentication

```
Client                          Server
  |                               |
  |  POST /users/me/api-keys      |
  |  {name, scopes, expires_at?}  |
  |------------------------------>|
  |                               |  Generate raw key
  |                               |  Store SHA-256 hash + prefix
  |  201 {raw_key, prefix, ...}   |  (raw_key shown ONCE)
  |<------------------------------|
  |                               |
  |  GET /any-endpoint            |
  |  Authorization: ApiKey <key>  |
  |------------------------------>|
  |                               |  Hash key, lookup by hash
  |                               |  Check not revoked/expired
  |                               |  Resolve user, check scopes
  |  200 Response                 |
  |<------------------------------|
```

### OAuth2 (Google / GitHub with PKCE)

```
Client                          Server                        Provider
  |                               |                             |
  |  GET /auth/oauth/{provider}   |                             |
  |------------------------------>|                             |
  |                               |  Generate PKCE state        |
  |                               |  Build consent URL          |
  |  302 Redirect to provider ----|----------------------------->|
  |                               |                             |
  |  User authorizes              |                             |
  |                               |                             |
  |  GET /auth/oauth/{provider}/callback?code=...&state=...     |
  |<------------------------------ redirect --------------------|
  |------------------------------>|                             |
  |                               |  Verify PKCE state          |
  |                               |  Exchange code for tokens ->|
  |                               |  Get user info <------------|
  |                               |  Link or create user:       |
  |                               |    - Email match: link      |
  |                               |    - New: create (no pw)    |
  |                               |  Issue access + refresh     |
  |  200 {access_token,           |                             |
  |       refresh_token}          |                             |
  |<------------------------------|                             |
```

**Unlink guard:** Cannot remove last login method (must have password or another provider linked).

### RBAC (Role-Based Access Control)

```
Roles: super_admin > admin > user

Endpoint                              Required Role
-------                               -------------
GET    /admin/users                   admin
POST   /admin/users/{id}/roles        super_admin
DELETE /admin/users/{id}/roles/{rid}  super_admin
POST   /admin/users/{id}/ban          admin
POST   /admin/users/{id}/unban        admin
GET    /admin/audit-logs              admin
```

`super_admin` inherits all `admin` permissions.

### Audit Logging

All auth events are logged asynchronously (fire-and-forget via `asyncio.create_task`):

| Event | Trigger |
|-------|---------|
| `register` | New user registration |
| `login_success` | Successful password login |
| `login_failed` | Failed login attempt |
| `logout` | Single session logout |
| `logout_all` | All sessions revoked |
| `token_refreshed` | Token rotation |
| `password_reset_request` | Reset email sent |
| `password_reset_confirm` | Password changed |
| `email_verification_sent` | Verification email sent |
| `email_verified` | Email confirmed |
| `phone_otp_sent` | SMS OTP sent |
| `phone_verified` | Phone confirmed |
| `totp_enabled` | 2FA activated |
| `totp_disabled` | 2FA deactivated |
| `totp_failed` | Invalid TOTP code |
| `api_key_created` | New API key generated |
| `api_key_revoked` | API key revoked |
| `oauth_login` | OAuth provider login |
| `role_assigned` | Role granted to user |
| `role_removed` | Role revoked from user |
| `user_banned` | Account deactivated |

Query via `GET /admin/audit-logs` with filters: `user_id`, `event_type`, `start_date`, `end_date`.

---

## Security Summary

- **Passwords:** bcrypt (12 rounds), never logged or returned
- **JWT:** HS256, configurable expiry (default 15 min)
- **Refresh tokens:** Opaque, SHA-256 hashed storage, rotation on use
- **Token comparison:** `hmac.compare_digest` (constant-time)
- **User enumeration:** Identical errors on login and password reset
- **Account lockout:** 5 failures in 10-minute sliding window
- **Primary keys:** UUIDs (no sequential integers)
- **Queries:** SQLAlchemy ORM parameterized (no string interpolation)
- **Headers:** X-Frame-Options: DENY, X-Content-Type-Options: nosniff, HSTS
- **Errors:** RFC 7807 Problem JSON, internal details stripped
