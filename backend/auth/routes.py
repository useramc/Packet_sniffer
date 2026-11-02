"""
Auth routes and the reusable auth dependency.

Implements:
  PPS-F-021  Require authentication before dashboard / capture-control access
  PPS-SR-001 Salted, industry-standard password hashing (bcrypt)
  PPS-SR-004 Forced admin credential creation on first run; no hardcoded secrets

Endpoint contracts match SAD Section 4.3 (POST /api/auth/login).
POST /api/auth/setup is the first-run addition referenced by PPS-SR-004 and
is intentionally only enabled while no user yet exists.
"""
import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from . import security, store

router = APIRouter(prefix="/api/auth", tags=["auth"])
_bearer = HTTPBearer(auto_error=False)


class SetupRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    token: str
    expiresAt: str


@router.post("/setup", response_model=TokenResponse, status_code=201)
def setup_admin(body: SetupRequest):
    """
    First-run only: create the initial administrator account.
    Refuses once any user already exists (PPS-SR-004) — re-running setup
    is not a way to reset credentials; that needs a separate, audited flow.
    """
    if store.has_any_user():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Setup already completed. An administrator account already exists.",
        )
    password_hash = security.hash_password(body.password)
    store.create_user(body.username, password_hash)
    token, expires_at = security.create_access_token(body.username)
    return TokenResponse(token=token, expiresAt=expires_at.isoformat())


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest):
    user = store.get_user(body.username)
    # Constant-shape failure: same error whether username is unknown or
    # password is wrong, so the endpoint doesn't leak which one was wrong.
    if user is None or not security.verify_password(body.password, user["password_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    token, expires_at = security.create_access_token(body.username)
    return TokenResponse(token=token, expiresAt=expires_at.isoformat())


def get_current_user(creds: HTTPAuthorizationCredentials = Depends(_bearer)) -> str:  # noqa: B008 (standard FastAPI DI pattern)
    """
    FastAPI dependency: attach to any protected route with
    `username: str = Depends(get_current_user)`.
    Returns the authenticated username, or raises 401 (satisfies
    AC-PPS-F-021: unauthenticated access to protected routes -> HTTP 401).
    """
    if creds is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    try:
        return security.decode_access_token(creds.credentials)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired") from None
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from None
