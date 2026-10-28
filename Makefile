.PHONY: test lint test-strict sync run
sync:
	uv sync
test:
	uv run pytest
lint:
	uv run ruff check src tests
	uv run mypy src
test-strict: lint test
run:
	uv run uvicorn devflow_api.main:app --reload
