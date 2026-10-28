"""Test environment defaults (not shipped in production code)."""
import os

# JWT verification requires a secret of at least 32 bytes. Provide a test-only
# default so modules importing ``devflow_api.auth.jwt`` succeed under pytest.
os.environ.setdefault("DEVFLOW_JWT_SECRET", "x" * 64)
