"""Password + JWT helpers.

Kept free of FastAPI / DB concerns so they are trivially testable.
"""
from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import Final

import jwt
from passlib.context import CryptContext  # type: ignore[import-untyped]

# bcrypt only uses the first 72 bytes of a password; truncate explicitly so
# two inputs differing only past that boundary can never silently collide.
BCRYPT_MAX_PASSWORD_BYTES: Final[int] = 72

_pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12,
)


_raw_secret = os.getenv("DEVFLOW_JWT_SECRET")
if _raw_secret is None or not _raw_secret.strip():
    raise RuntimeError(
        "DEVFLOW_JWT_SECRET is required and must be at least 32 bytes"
    )
if len(_raw_secret.encode("utf-8")) < 32:
    raise RuntimeError("DEVFLOW_JWT_SECRET must be at least 32 bytes")
JWT_SECRET: Final[str] = _raw_secret
JWT_ALGORITHM: Final[str] = "HS256"
ACCESS_TOKEN_MINUTES: Final[int] = 30


class TokenError(ValueError):
    """Raised when a token cannot be validated."""


def hash_password(raw: str) -> str:
    """Hash ``raw`` with bcrypt (cost 12), truncating at 72 bytes explicitly."""
    truncated = raw.encode("utf-8")[:BCRYPT_MAX_PASSWORD_BYTES]
    return str(_pwd_context.hash(truncated))


def verify_password(raw: str, stored: str) -> bool:
    """Verify ``raw`` against a bcrypt ``stored`` hash."""
    if not raw or not stored:
        return False
    try:
        truncated = raw.encode("utf-8")[:BCRYPT_MAX_PASSWORD_BYTES]
        return bool(_pwd_context.verify(truncated, stored))
    except Exception:
        return False


def create_access_token(subject: str, minutes: int = ACCESS_TOKEN_MINUTES) -> str:
    if not subject:
        raise ValueError("subject is required")
    now = datetime.now(UTC)
    payload = {
        "sub": subject,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=minutes)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> dict[str, str]:
    try:
        raw = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return {str(k): str(v) for k, v in raw.items()}
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("token expired") from exc
    except jwt.InvalidTokenError as exc:
        raise TokenError("token invalid") from exc
