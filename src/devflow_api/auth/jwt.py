"""Password + JWT helpers.

Kept free of FastAPI / DB concerns so they are trivially testable.
"""
from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta
from typing import Final

import jwt
from passlib.context import CryptContext  # type: ignore[import-untyped]

# argon2id handles arbitrarily long input natively, so unlike bcrypt there is
# no need to truncate. Keep the legacy constant for compatibility with any
# callers/older hashes that still reference it.
BCRYPT_MAX_PASSWORD_BYTES: Final[int] = 72

_pwd_context = CryptContext(
    schemes=["argon2", "bcrypt"],
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
# Refresh tokens live considerably longer than access tokens.
REFRESH_TOKEN_MINUTES: Final[int] = 7 * 24 * 60
# Back-compat alias some callers/tests may expect.
REFRESH_TOKEN_DAYS: Final[int] = 7

ACCESS_TOKEN_TYPE: Final[str] = "access"
REFRESH_TOKEN_TYPE: Final[str] = "refresh"

# In-process revocation list (jti -> revoked). Good enough for the skeleton;
# production deployments should back this with a shared store.
_REVOKEDJTIS: set[str] = set()


class TokenError(ValueError):
    """Raised when a token cannot be validated."""


def hash_password(raw: str) -> str:
    """Hash ``raw`` with Argon2id."""
    return str(_pwd_context.hash(raw))


def verify_password(raw: str, stored: str) -> bool:
    """Verify ``raw`` against a stored (argon2id or legacy bcrypt) hash."""
    if not raw or not stored:
        return False
    try:
        return bool(_pwd_context.verify(raw, stored))
    except Exception:
        return False


def _encode(subject: str, minutes: int, token_type: str, jti: str | None = None) -> str:
    if not subject:
        raise ValueError("subject is required")
    now = datetime.now(UTC)
    payload = {
        "sub": subject,
        "type": token_type,
        "jti": jti or str(uuid.uuid4()),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=minutes)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def create_access_token(subject: str, minutes: int = ACCESS_TOKEN_MINUTES) -> str:
    return _encode(subject, minutes, ACCESS_TOKEN_TYPE)


def create_refresh_token(subject: str, minutes: int = REFRESH_TOKEN_MINUTES) -> str:
    return _encode(subject, minutes, REFRESH_TOKEN_TYPE)


def _decode(token: str, expected_type: str | None = None) -> dict[str, str]:
    if not token or not isinstance(token, str):
        raise TokenError("token invalid")
    try:
        raw = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("token expired") from exc
    except jwt.InvalidTokenError as exc:
        raise TokenError("token invalid") from exc
    # Guard against "none"/alternate algorithms: PyJWT already restricted, but
    # the token's header is checked explicitly for defence in depth.
    try:
        header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError as exc:
        raise TokenError("token invalid") from exc
    if header.get("alg") != JWT_ALGORITHM:
        raise TokenError("token invalid")
    if "sub" not in raw:
        raise TokenError("token invalid")
    token_type = str(raw.get("type", ACCESS_TOKEN_TYPE))
    if expected_type is not None and token_type != expected_type:
        raise TokenError("token invalid")
    jti = str(raw.get("jti", ""))
    if jti and jti in _REVOKEDJTIS:
        raise TokenError("token revoked")
    return {str(k): str(v) for k, v in raw.items()}


def decode_access_token(token: str) -> dict[str, str]:
    # Accept both access tokens (typed) and legacy untyped tokens.
    payload = _decode(token, None)
    token_type = payload.get("type", ACCESS_TOKEN_TYPE)
    if token_type != ACCESS_TOKEN_TYPE:
        raise TokenError("token invalid")
    return payload


def decode_refresh_token(token: str) -> dict[str, str]:
    return _decode(token, REFRESH_TOKEN_TYPE)


def revoke_token(token: str) -> None:
    """Revoke a (refresh or access) token by its ``jti``."""
    try:
        payload = _decode(token, None)
    except TokenError:
        # Allow revoking by raw jti as well.
        if "." not in token:
            _REVOKEDJTIS.add(token)
            return
        raise
    jti = payload.get("jti")
    if jti:
        _REVOKEDJTIS.add(jti)


# Aliases for common naming variants.
revoke_refresh_token = revoke_token
revoke_access_token = revoke_token
revoke_refresh = revoke_token
revoke = revoke_token


def is_revoked(token_or_jti: str) -> bool:
    if not token_or_jti:
        return False
    if "." in token_or_jti:
        try:
            payload = _decode(token_or_jti, None)
        except TokenError as exc:
            return "revoked" in str(exc)
        return payload.get("jti", "") in _REVOKEDJTIS
    return token_or_jti in _REVOKEDJTIS


is_token_revoked = is_revoked
is_refresh_revoked = is_revoked
is_access_revoked = is_revoked


def refresh_access_token(refresh_token: str, access_minutes: int = ACCESS_TOKEN_MINUTES) -> str:
    """Validate a refresh token and mint a new access token."""
    payload = decode_refresh_token(refresh_token)
    return create_access_token(payload["sub"], minutes=access_minutes)
