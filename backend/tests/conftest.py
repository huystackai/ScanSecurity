"""Tests for Phase 1: SSRF/NetGuard, ScopePolicy, SafeHttpClient, auth/CSRF, and target verification."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _test_env(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setenv("VIBESCAN_ENVIRONMENT", "test")
    monkeypatch.setenv("VIBESCAN_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path}/test.db")
    monkeypatch.setenv("VIBESCAN_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("VIBESCAN_SECRET_KEY", "test-secret-key-for-unit-tests-0123456789abcdef")
    from app.api.auth import reset_login_limiter
    from app.config import get_settings

    get_settings.cache_clear()
    reset_login_limiter()
