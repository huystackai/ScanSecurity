"""Operator authentication and operator management endpoints."""

from __future__ import annotations

import datetime as dt
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    CSRF_COOKIE,
    SESSION_COOKIE,
    get_current_session,
    require_admin,
)
from app.api.schemas import (
    AuthSessionOut,
    LoginRequest,
    OperatorCreateRequest,
    OperatorOut,
    OperatorUpdateRequest,
)
from app.config import get_settings
from app.core.audit import client_ip, record_audit
from app.core.ratelimit import SlidingWindowLimiter
from app.core.security import (
    hash_password,
    hash_token,
    new_csrf_token,
    new_session_token,
    verify_password,
)
from app.db.base import utcnow
from app.db.models import Operator, Session
from app.db.session import get_db

router = APIRouter()

_login_limiter: SlidingWindowLimiter | None = None


def get_login_limiter() -> SlidingWindowLimiter:
    global _login_limiter
    if _login_limiter is None:
        s = get_settings()
        _login_limiter = SlidingWindowLimiter(s.login_max_attempts, s.login_window_seconds)
    return _login_limiter


def reset_login_limiter() -> None:
    global _login_limiter
    _login_limiter = None


@router.post("/auth/login", response_model=AuthSessionOut)
async def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> AuthSessionOut:
    settings = get_settings()
    limiter = get_login_limiter()
    ip = client_ip(request) or "unknown"
    email_norm = payload.email.lower().strip()
    rate_key = f"{ip}:{email_norm}"
    if limiter.is_limited(rate_key) or limiter.is_limited(ip):
        await record_audit(
            db, "auth.login_rate_limited", request=request, details={"email": email_norm}
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts; please wait before retrying",
            headers={"Retry-After": str(max(limiter.retry_after(rate_key), limiter.retry_after(ip)))},
        )

    stmt = select(Operator).where(func.lower(Operator.email) == email_norm)
    operator = (await db.execute(stmt)).scalar_one_or_none()
    ok = verify_password(operator.password_hash if operator else None, payload.password)
    if not ok or operator is None or not operator.is_active:
        limiter.hit(rate_key)
        limiter.hit(ip)
        await record_audit(
            db, "auth.login_failed", request=request, details={"email": email_norm}
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    limiter.reset(rate_key)
    raw_token = new_session_token()
    csrf_token = new_csrf_token()
    now = utcnow()
    expires_at = now + dt.timedelta(hours=settings.session_ttl_hours)
    sess = Session(
        operator_id=operator.id,
        token_hash=hash_token(raw_token),
        csrf_token=csrf_token,
        expires_at=expires_at,
        ip=ip,
        user_agent=(request.headers.get("user-agent") or "")[:400],
    )
    operator.last_login_at = now
    db.add(sess)
    await record_audit(db, "auth.login_succeeded", operator=operator, request=request, commit=True)

    max_age = settings.session_ttl_hours * 3600
    response.set_cookie(
        key=SESSION_COOKIE,
        value=raw_token,
        max_age=max_age,
        httponly=True,
        secure=settings.secure_cookies,
        samesite="lax",
        path="/",
    )
    response.set_cookie(
        key=CSRF_COOKIE,
        value=csrf_token,
        max_age=max_age,
        httponly=False,
        secure=settings.secure_cookies,
        samesite="lax",
        path="/",
    )
    return AuthSessionOut(operator=OperatorOut.model_validate(operator), csrf_token=csrf_token)


@router.post("/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    response: Response,
    sess: Session = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
) -> Response:
    sess.revoked_at = utcnow()
    await record_audit(db, "auth.logout", operator=sess.operator, request=request, commit=True)
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.get("/auth/me", response_model=AuthSessionOut)
async def me(sess: Session = Depends(get_current_session)) -> AuthSessionOut:
    return AuthSessionOut(operator=OperatorOut.model_validate(sess.operator), csrf_token=sess.csrf_token)


@router.get("/operators")
async def list_operators(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    _admin: Operator = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    total = (await db.execute(select(func.count()).select_from(Operator))).scalar_one()
    rows = (
        await db.execute(select(Operator).order_by(Operator.created_at.desc()).limit(limit).offset(offset))
    ).scalars().all()
    return {"items": [OperatorOut.model_validate(r) for r in rows], "total": total}


@router.post("/operators", response_model=OperatorOut, status_code=status.HTTP_201_CREATED)
async def create_operator(
    payload: OperatorCreateRequest,
    request: Request,
    admin: Operator = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> OperatorOut:
    email_norm = payload.email.lower().strip()
    existing = (
        await db.execute(select(Operator).where(func.lower(Operator.email) == email_norm))
    ).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Operator with this email already exists")
    try:
        pw_hash = hash_password(payload.password)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    op = Operator(
        email=email_norm,
        display_name=payload.display_name or email_norm.split("@")[0],
        password_hash=pw_hash,
        role=payload.role.value,
        is_active=True,
    )
    db.add(op)
    await db.flush()
    await record_audit(
        db,
        "operator.created",
        operator=admin,
        request=request,
        details={"new_operator_id": str(op.id), "email": op.email, "role": op.role},
    )
    return OperatorOut.model_validate(op)


@router.patch("/operators/{operator_id}", response_model=OperatorOut)
async def update_operator(
    operator_id: uuid.UUID,
    payload: OperatorUpdateRequest,
    request: Request,
    admin: Operator = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> OperatorOut:
    op = await db.get(Operator, operator_id)
    if not op:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Operator not found")
    if payload.display_name is not None:
        op.display_name = payload.display_name
    if payload.role is not None:
        op.role = payload.role.value
    if payload.is_active is not None:
        if op.id == admin.id and not payload.is_active:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot deactivate your own account")
        op.is_active = payload.is_active
    if payload.password is not None:
        try:
            op.password_hash = hash_password(payload.password)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    await record_audit(
        db,
        "operator.updated",
        operator=admin,
        request=request,
        details={"updated_operator_id": str(op.id), "role": op.role, "is_active": op.is_active},
    )
    return OperatorOut.model_validate(op)
