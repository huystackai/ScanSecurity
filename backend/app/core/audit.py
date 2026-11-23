"""Audit logging: every security-relevant operator action is attributable."""

from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AuditLog, Operator

log = logging.getLogger("vibescan.audit")


def client_ip(request: Request | None) -> str | None:
    if request is None or request.client is None:
        return None
    return request.client.host


async def record_audit(
    db: AsyncSession,
    action: str,
    *,
    operator: Operator | None = None,
    request: Request | None = None,
    target_id: uuid.UUID | None = None,
    scan_id: uuid.UUID | None = None,
    details: dict[str, Any] | None = None,
    commit: bool = True,
) -> AuditLog:
    entry = AuditLog(
        operator_id=operator.id if operator else None,
        operator_email=operator.email if operator else None,
        action=action,
        target_id=target_id,
        scan_id=scan_id,
        ip=client_ip(request),
        details=details or {},
    )
    db.add(entry)
    if commit:
        await db.commit()
    log.info(
        "audit action=%s operator=%s target=%s scan=%s",
        action,
        operator.email if operator else None,
        target_id,
        scan_id,
    )
    return entry
