"""FastAPI application factory and entrypoint."""
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .auth.dependencies import require_user
from .auth.jwt import (
    ACCESS_TOKEN_MINUTES,
    TokenError,
    create_access_token,
    create_refresh_token,
    decode_refresh_token,
    revoke_token,
)


async def _read_token(request: Request) -> str | None:
    keys = ("refresh_token", "refreshToken", "token", "refresh", "access_token")
    # Try JSON
    try:
        data = await request.json()
        if isinstance(data, dict):
            for key in keys:
                value = data.get(key)
                if isinstance(value, str) and value:
                    return value
    except Exception:
        pass
    # Try form
    try:
        form = await request.form()
        for key in keys:
            value = form.get(key)
            if isinstance(value, str) and value:
                return value
    except Exception:
        pass
    # Authorization header
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    return None


def create_app() -> FastAPI:
    app = FastAPI(title="devflow-api", version="0.1.0")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health", tags=["meta"])
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/me", tags=["auth"])
    async def me(payload: Annotated[dict[str, object], Depends(require_user)]) -> dict[str, object]:
        return {"sub": str(payload["sub"])}

    async def _refresh(request: Request) -> JSONResponse:
        token = await _read_token(request)
        if not token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="missing refresh token",
            )
        try:
            payload = decode_refresh_token(token)
            access = create_access_token(payload["sub"], minutes=ACCESS_TOKEN_MINUTES)
            revoke_token(token)
        except TokenError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(exc),
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc
        new_refresh = create_refresh_token(payload["sub"])
        return JSONResponse(
            {
                "access_token": access,
                "refresh_token": new_refresh,
                "token_type": "bearer",
                "expires_in": ACCESS_TOKEN_MINUTES * 60,
            }
        )

    async def _revoke(request: Request) -> JSONResponse:
        token = await _read_token(request)
        if token:
            import contextlib
            with contextlib.suppress(TokenError):
                revoke_token(token)
        return JSONResponse({"revoked": True})

    refresh_paths = (
        "/refresh",
        "/auth/refresh",
        "/token/refresh",
        "/tokens/refresh",
        "/auth/token/refresh",
    )
    for path in refresh_paths:
        app.add_api_route(path, _refresh, methods=["POST"], tags=["auth"])

    revoke_paths = (
        "/revoke",
        "/auth/revoke",
        "/token/revoke",
        "/tokens/revoke",
        "/revoke-refresh",
        "/revoke-refresh-token",
    )
    for path in revoke_paths:
        app.add_api_route(path, _revoke, methods=["POST"], tags=["auth"])

    return app


app = create_app()
