import hashlib
import secrets
from urllib.parse import urlencode

import httpx

from app.core.config import settings

# PKCE helpers
def _generate_code_verifier() -> str:
    return secrets.token_urlsafe(64)


def _generate_code_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    import base64
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


# In-memory state store: {state: (provider, code_verifier)}
_oauth_states: dict[str, tuple[str, str]] = {}


# --- Google ---

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"


def get_google_auth_url() -> tuple[str, str]:
    """Returns (authorization_url, state)."""
    state = secrets.token_urlsafe(32)
    verifier = _generate_code_verifier()
    challenge = _generate_code_challenge(verifier)
    _oauth_states[state] = ("google", verifier)

    params = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": f"{settings.OAUTH2_REDIRECT_BASE_URL}/api/v1/auth/oauth/google/callback",
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return f"{GOOGLE_AUTH_URL}?{urlencode(params)}", state


async def exchange_google_code(code: str, state: str) -> dict:
    """Exchange authorization code for user info. Returns {email, provider_user_id, access_token, refresh_token, expires_at}."""
    entry = _oauth_states.pop(state, None)
    if not entry or entry[0] != "google":
        raise ValueError("Invalid OAuth state")

    _, verifier = entry

    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            GOOGLE_TOKEN_URL,
            data={
                "client_id": settings.GOOGLE_CLIENT_ID,
                "client_secret": settings.GOOGLE_CLIENT_SECRET,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": f"{settings.OAUTH2_REDIRECT_BASE_URL}/api/v1/auth/oauth/google/callback",
                "code_verifier": verifier,
            },
        )
        token_resp.raise_for_status()
        tokens = token_resp.json()

        userinfo_resp = await client.get(
            GOOGLE_USERINFO_URL,
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )
        userinfo_resp.raise_for_status()
        userinfo = userinfo_resp.json()

    from datetime import datetime, timedelta, timezone
    return {
        "email": userinfo["email"],
        "provider_user_id": userinfo["id"],
        "access_token": tokens["access_token"],
        "refresh_token": tokens.get("refresh_token"),
        "expires_at": datetime.now(timezone.utc) + timedelta(seconds=tokens.get("expires_in", 3600)),
    }


# --- GitHub ---

GITHUB_AUTH_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_URL = "https://api.github.com/user"
GITHUB_EMAILS_URL = "https://api.github.com/user/emails"


def get_github_auth_url() -> tuple[str, str]:
    """Returns (authorization_url, state)."""
    state = secrets.token_urlsafe(32)
    verifier = _generate_code_verifier()
    _oauth_states[state] = ("github", verifier)

    params = {
        "client_id": settings.GITHUB_CLIENT_ID,
        "redirect_uri": f"{settings.OAUTH2_REDIRECT_BASE_URL}/api/v1/auth/oauth/github/callback",
        "scope": "user:email",
        "state": state,
    }
    return f"{GITHUB_AUTH_URL}?{urlencode(params)}", state


async def exchange_github_code(code: str, state: str) -> dict:
    """Exchange authorization code for user info."""
    entry = _oauth_states.pop(state, None)
    if not entry or entry[0] != "github":
        raise ValueError("Invalid OAuth state")

    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            GITHUB_TOKEN_URL,
            data={
                "client_id": settings.GITHUB_CLIENT_ID,
                "client_secret": settings.GITHUB_CLIENT_SECRET,
                "code": code,
            },
            headers={"Accept": "application/json"},
        )
        token_resp.raise_for_status()
        tokens = token_resp.json()

        access_token = tokens["access_token"]
        headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}

        user_resp = await client.get(GITHUB_USER_URL, headers=headers)
        user_resp.raise_for_status()
        user_data = user_resp.json()

        # Get primary email
        emails_resp = await client.get(GITHUB_EMAILS_URL, headers=headers)
        emails_resp.raise_for_status()
        emails = emails_resp.json()
        primary_email = next((e["email"] for e in emails if e["primary"] and e["verified"]), None)

    from datetime import datetime, timezone
    return {
        "email": primary_email or user_data.get("email"),
        "provider_user_id": str(user_data["id"]),
        "access_token": access_token,
        "refresh_token": None,
        "expires_at": datetime.now(timezone.utc),  # GitHub tokens don't expire by default
    }
