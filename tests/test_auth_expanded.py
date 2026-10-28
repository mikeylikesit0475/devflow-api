"""Expanded coverage for JWT auth skeleton (reviewer scenarios)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import importlib
import json
import os
import sys
import time

import jwt
import pytest
from fastapi.testclient import TestClient

from devflow_api.auth import jwt as auth_jwt
from devflow_api.auth.jwt import (
    TokenError,
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)
from devflow_api.main import create_app


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------


def test_verify_password_malformed_empty() -> None:
    assert not verify_password("raw", "")


def test_verify_password_malformed_no_dollar() -> None:
    assert not verify_password("raw", "not-a-stored-hash")


def test_verify_password_empty_salt_is_false() -> None:
    assert not verify_password("raw", "$" + "a" * 64)


def test_verify_password_empty_digest_is_false() -> None:
    assert not verify_password("raw", "salt$")


def test_hash_password_output_format() -> None:
    raw = "correct-horse-battery-staple"
    stored = hash_password(raw)
    assert stored.startswith("$2b$")
    assert verify_password(raw, stored)
    assert not verify_password("wrong", stored)


def test_hash_password_unique_salts() -> None:
    salts = {hash_password("same-input") for _ in range(5)}
    assert len(salts) == 5


def test_verify_password_tampered_digest_is_false() -> None:
    stored = hash_password("raw")
    tampered = stored[:-1] + ("0" if stored[-1] != "0" else "1")
    assert not verify_password("raw", tampered)


def test_hash_password_truncates_at_72_bytes() -> None:
    raw = "a" * 100
    stored = hash_password(raw)
    assert verify_password(raw, stored)
    assert verify_password("a" * 72, stored)
    assert not verify_password("a" * 71 + "b", stored)


# ---------------------------------------------------------------------------
# JWT creation / decoding
# ---------------------------------------------------------------------------


def test_create_access_token_rejects_empty_subject() -> None:
    with pytest.raises(ValueError, match="subject is required"):
        create_access_token("")


def test_decode_expired_token_raises_token_expired() -> None:
    token = create_access_token("alice", minutes=-1)
    with pytest.raises(TokenError) as exc_info:
        decode_access_token(token)
    assert str(exc_info.value) == "token expired"


def test_decode_tampered_signature_raises_token_invalid() -> None:
    token = create_access_token("alice")
    with pytest.raises(TokenError) as exc_info:
        decode_access_token(token + "tampered")
    assert str(exc_info.value) == "token invalid"


def test_decode_wrong_secret_raises_token_invalid() -> None:
    token = jwt.encode(
        {"sub": "alice", "exp": int(time.time()) + 3600},
        "b" * 40,
        algorithm="HS256",
    )
    with pytest.raises(TokenError) as exc_info:
        decode_access_token(token)
    assert str(exc_info.value) == "token invalid"


def test_decode_rejects_none_algorithm_header() -> None:
    future = int(time.time()) + 3600
    header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({"sub": "alice", "exp": future}).encode())
    token = f"{header}.{payload}."
    with pytest.raises(TokenError) as exc_info:
        decode_access_token(token)
    assert str(exc_info.value) == "token invalid"


def test_decode_rejects_hs384_algorithm_header() -> None:
    token = jwt.encode(
        {"sub": "alice", "exp": int(time.time()) + 3600},
        auth_jwt.JWT_SECRET,
        algorithm="HS384",
    )
    with pytest.raises(TokenError) as exc_info:
        decode_access_token(token)
    assert str(exc_info.value) == "token invalid"


@pytest.mark.parametrize(
    "token",
    ["", "a", "a.b", "a.b.c", "!!!!", "nope.nope.nope.extra"],
)
def test_decode_malformed_tokens_raise(token: str) -> None:
    with pytest.raises(TokenError):
        decode_access_token(token)


def test_decode_non_json_payload_raises() -> None:
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url(b"not-json-at-all")
    message = f"{header}.{payload}".encode("ascii")
    signature = hmac.new(auth_jwt.JWT_SECRET.encode(), message, hashlib.sha256).digest()
    token = f"{header}.{payload}.{_b64url(signature)}"
    with pytest.raises(TokenError) as exc_info:
        decode_access_token(token)
    assert str(exc_info.value) == "token invalid"


def test_decode_returns_sub_with_extra_claims() -> None:
    token = jwt.encode(
        {"sub": "alice", "role": "admin", "count": 7},
        auth_jwt.JWT_SECRET,
        algorithm="HS256",
    )
    payload = decode_access_token(token)
    assert payload["sub"] == "alice"
    assert payload.get("role") == "admin"


# ---------------------------------------------------------------------------
# Protected route
# ---------------------------------------------------------------------------


def test_me_expired_token_returns_401_token_expired() -> None:
    client = TestClient(create_app())
    token = create_access_token("alice", minutes=-1)
    response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
    assert response.json()["detail"] == "token expired"


def test_me_tampered_token_returns_401_token_invalid() -> None:
    client = TestClient(create_app())
    token = create_access_token("alice")
    response = client.get("/me", headers={"Authorization": f"Bearer {token}tampered"})
    assert response.status_code == 401
    assert response.json()["detail"] == "token invalid"


def test_me_missing_token_returns_401_missing_bearer_token() -> None:
    client = TestClient(create_app())
    response = client.get("/me")
    assert response.status_code == 401
    assert response.json()["detail"] == "missing bearer token"


# ---------------------------------------------------------------------------
# Import-time secret handling
# ---------------------------------------------------------------------------


def test_jwt_secret_too_short_raises_on_import(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEVFLOW_JWT_SECRET", "short")
    sys.modules.pop("devflow_api.auth.jwt", None)
    try:
        with pytest.raises(RuntimeError, match="at least 32 bytes"):
            importlib.import_module("devflow_api.auth.jwt")
    finally:
        monkeypatch.delenv("DEVFLOW_JWT_SECRET", raising=False)
        sys.modules.pop("devflow_api.auth.jwt", None)
        os.environ["DEVFLOW_JWT_SECRET"] = "x" * 64
        importlib.import_module("devflow_api.auth.jwt")


def test_jwt_secret_long_enough_imports(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEVFLOW_JWT_SECRET", "a" * 32)
    sys.modules.pop("devflow_api.auth.jwt", None)
    try:
        module = importlib.import_module("devflow_api.auth.jwt")
        assert len(module.JWT_SECRET.encode()) >= 32
    finally:
        monkeypatch.delenv("DEVFLOW_JWT_SECRET", raising=False)
        sys.modules.pop("devflow_api.auth.jwt", None)
        os.environ["DEVFLOW_JWT_SECRET"] = "x" * 64
        importlib.import_module("devflow_api.auth.jwt")


def test_jwt_secret_unset_raises_on_import(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEVFLOW_JWT_SECRET", raising=False)
    sys.modules.pop("devflow_api.auth.jwt", None)
    try:
        with pytest.raises(RuntimeError):
            importlib.import_module("devflow_api.auth.jwt")
    finally:
        sys.modules.pop("devflow_api.auth.jwt", None)
        os.environ.setdefault("DEVFLOW_JWT_SECRET", "x" * 64)
        importlib.import_module("devflow_api.auth.jwt")
