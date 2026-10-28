# devflow-api

Practice repository for exercising a real developer team workflow on GitHub: feature
branches, pull requests, CI gates, code review, and releases.

## Stack
- Python 3.11+
- FastAPI
- PyJWT, passlib[bcrypt]
- pytest + httpx (TestClient); ruff + mypy for the gate

## Quick start

```bash
uv sync
uv run uvicorn devflow_api.main:app --reload
# -> http://127.0.0.1:8000/docs
```

## Testing

```bash
make test        # pytest
make lint        # ruff + mypy
make test-strict # all of the above
```

## Workflow (Gitflow)

- `main` — released state; protected, tagged with release versions.
- `develop` — integration branch; all feature branches merge here via PR.
- `feature/*` — one feature per branch; merged to `develop` via PR with review.
- `release/*` — cut from `develop`, merged to `main` + `develop` and tagged.
- `hotfix/*` — cut from `main`, merged to `main` + `develop`.

CI (ruff + mypy + pytest, offline) gates every PR and push to `develop`/`main`.
