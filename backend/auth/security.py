"""
Password hashing and JWT helpers.

PPS-SR-001: credentials shall be stored using a salted, industry-standard
hash (bcrypt). Plaintext passwords are never persisted or logged.
"""
import datetime

import bcrypt
import jwt

from . import config


def hash_password(plain_password: str) -> str:
    """Return a bcrypt hash (salt embedded) for storage. Never log the input."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(plain_password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, stored_hash: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), stored_hash.encode("utf-8"))
    except (ValueError, TypeError):
        # malformed hash in storage - fail closed, not open
        return False


def create_access_token(username: str) -> tuple[str, datetime.datetime]:
    expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
        minutes=config.JWT_EXPIRY_MINUTES
    )
    payload = {"sub": username, "exp": expires_at}
    token = jwt.encode(payload, config.JWT_SECRET, algorithm=config.JWT_ALGORITHM)
    return token, expires_at


def decode_access_token(token: str) -> str:
    """Return the username (sub) if the token is valid. Raises jwt exceptions otherwise."""
    payload = jwt.decode(token, config.JWT_SECRET, algorithms=[config.JWT_ALGORITHM])
    return payload["sub"]
