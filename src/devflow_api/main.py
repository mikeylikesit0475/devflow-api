"""FastAPI application factory and entrypoint."""
from typing import Annotated

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .auth.dependencies import require_user


def create_app() -> FastAPI:
    app = FastAPI(title="devflow-api", version="0.1.0")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health", tags=["meta"])
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/me", tags=["auth"])
    async def me(payload: Annotated[dict[str, object], Depends(require_user)]) -> dict[str, object]:
        return {"sub": str(payload["sub"])}

    return app


app = create_app()
