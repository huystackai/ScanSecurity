"""FastAPI application entrypoint, security middleware, and bootstrap operator initialization."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from sqlalchemy import func, select

from app import __version__
from app.api.auth import router as auth_router
from app.api.scans import router as scans_router
from app.api.targets import router as targets_router
from app.config import get_settings
from app.core.security import hash_password
from app.db.models import Operator, OperatorRole
from app.db.session import configure_engine, dispose_engine, get_sessionmaker, init_db
from app.worker import wait_for_inline_tasks

log = logging.getLogger("vibescan")


async def bootstrap_admin_if_needed() -> None:
    settings = get_settings()
    async with get_sessionmaker()() as db:
        count = (await db.execute(select(func.count()).select_from(Operator))).scalar_one()
        if count > 0:
            return
        email = (settings.bootstrap_admin_email or "").strip().lower()
        password = settings.bootstrap_admin_password or ""
        if not email or not password:
            if settings.environment == "development":
                email = "admin@vibescan.local"
                password = "VibeScan-Dev-Admin!2026"  # noqa: S105
                log.warning("Bootstrapping default development admin account %s", email)
            else:
                return
        admin = Operator(
            email=email,
            display_name="Platform Administrator",
            password_hash=hash_password(password),
            role=OperatorRole.admin.value,
            is_active=True,
        )
        db.add(admin)
        await db.commit()


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.uploads_dir.mkdir(parents=True, exist_ok=True)
    settings.reports_dir.mkdir(parents=True, exist_ok=True)
    configure_engine(settings)
    await init_db()
    await bootstrap_admin_if_needed()
    try:
        yield
    finally:
        await wait_for_inline_tasks()
        await dispose_engine()


def create_app() -> FastAPI:
    app = FastAPI(
        title="VibeScan Security Auditing API",
        version=__version__,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )

    @app.middleware("http")
    async def security_headers_middleware(request: Request, call_next) -> Response:  # type: ignore[no-untyped-def]
        response: Response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    app.include_router(auth_router, prefix="/api/v1", tags=["auth"])
    app.include_router(targets_router, prefix="/api/v1", tags=["targets"])
    app.include_router(scans_router, prefix="/api/v1", tags=["scans"])
    return app


app = create_app()
