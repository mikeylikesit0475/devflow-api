"""Password + JWT helpers.

Kept free of FastAPI / DB concerns so they are trivially testable.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from datetime import UTC, datetime, timedelta
from typing import Final

import jwt

# Demo secret — never use a hard-coded secret in production. In real code this
# would come from settings / env.
DEFAULT_DEMO_SECRET: Final[str] = "devflow-demo-secret-change-me-change-this-in-production-env"
_raw_secret = os.getenv("DEVFLOW_JWT_SECRET")


def _validate_secret(raw: str | None) -> str:
    if raw:
        if len(raw.encode()) < 32:
            raise RuntimeError("DEVFLOW_JWT_SECRET must be at least 32 bytes")
        return raw
    return DEFAULT_DEMO_SECRET


JWT_SECRET = _validate_secret(_raw_secret)
JWT_ALGORITHM: Final[str] = "HS256"
ACCESS_TOKEN_MINUTES: Final[int] = 30


class TokenError(ValueError):
    """Raised when a token cannot be validated."""


def hash_password(raw: str) -> str:
    salt = secrets.token_hex(8)
    digest = hashlib.sha256((salt + raw).encode()).hexdigest()
    return f"{salt}${digest}"


def verify_password(raw: str, stored: str) -> bool:
    try:
        salt, digest = stored.split("$", 1)
    except ValueError:
        return False
    computed = hashlib.sha256((salt + raw).encode()).hexdigest()
    return hmac.compare_digest(computed, digest)


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
    except jwt.ExpiredSignatureError as exc:  # pragma: no cover - deterministic by tests
        raise TokenError("token expired") from exc
    except jwt.InvalidTokenError as exc:
        raise TokenError("token invalid") from exc
