"""Tests for the JWT auth skeleton."""
from fastapi.testclient import TestClient

from devflow_api.auth.jwt import (
    TokenError,
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)
from devflow_api.main import create_app


def test_password_roundtrip() -> None:
    stored = hash_password("correct-horse-battery-staple")
    assert verify_password("correct-horse-battery-staple", stored)
    assert not verify_password("wrong", stored)


def test_token_roundtrip() -> None:
    token = create_access_token("alice")

    assert decode_access_token(token)["sub"] == "alice"
    with __import__("pytest").raises(TokenError):
        decode_access_token(token + "tampered")


def test_protected_route_requires_token() -> None:
    client = TestClient(create_app())
    assert client.get("/me").status_code == 401


def test_protected_route_with_valid_token_returns_subject() -> None:
    client = TestClient(create_app())
    token = create_access_token("alice")
    response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json() == {"sub": "alice"}
