"""Target registry, ownership verification, lab attestation, and encrypted test credentials."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_operator, require_admin, require_operator_or_admin
from app.api.schemas import (
    AttestTargetRequest,
    CredentialCreateRequest,
    CredentialOut,
    TargetCreateRequest,
    TargetOut,
    TargetUpdateRequest,
    VerifyTargetRequest,
    VerifyTargetResponse,
)
from app.config import get_settings
from app.core.audit import record_audit
from app.core.crypto import encrypt_secret
from app.core.security import new_verification_token
from app.db.base import utcnow
from app.db.models import AuthorizationStatus, Operator, Target, TargetCredential, VerificationMethod
from app.db.session import get_db
from app.scanner.netguard import NetworkPolicy
from app.scanner.scope import ScopeConfig, ScopePolicy, normalize_target_url
from app.scanner.verification import (
    perform_target_verification,
    verification_expires_at,
    verification_instructions,
)

router = APIRouter()


def _serialize_target(target: Target) -> TargetOut:
    integrations_raw = dict(target.integrations or {})
    supa = dict(integrations_raw.get("supabase") or {})
    safe_integrations = {
        "supabase": {
            "enabled": bool(supa.get("enabled", False)),
            "project_url": supa.get("project_url"),
            "anon_key_set": bool(supa.get("encrypted_anon_key")),
        }
    }
    roles = [c.role_name for c in (target.credentials or [])]
    return TargetOut(
        id=target.id,
        name=target.name,
        base_url=target.base_url,
        primary_host=target.primary_host,
        allowed_hosts=list(target.allowed_hosts or [target.primary_host]),
        scope_config=ScopeConfig.from_dict(target.scope_config).to_dict(),
        access_tests=list(target.access_tests or []),
        integrations=safe_integrations,
        authorization_status=AuthorizationStatus(target.authorization_status),
        verification_method=target.verification_method,
        verification_token=target.verification_token,
        verified_at=target.verified_at,
        verification_expires_at=verification_expires_at(target),
        attestation=target.attestation,
        owner_operator_id=target.owner_operator_id,
        created_at=target.created_at,
        last_scan_at=target.last_scan_at,
        credential_roles=roles,
    )


def _validate_target_hosts(base_url: str, allowed_hosts: list[str] | None) -> ScopePolicy:
    settings = get_settings()
    net_policy = NetworkPolicy(
        allow_private=settings.allow_private_targets, private_allowlist=settings.private_networks
    )
    try:
        scope = ScopePolicy(base_url, allowed_hosts)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    for h in scope.allowed_hosts:
        ok, reason = net_policy.check_hostname(h)
        if not ok:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Disallowed target host {h!r}: {reason}",
            )
        try:
            # If the host is an IP literal, validate it immediately against the IP policy.
            import ipaddress

            ip = ipaddress.ip_address(h.strip("[]"))
        except ValueError:
            ip = None
        if ip is not None:
            ok_ip, reason_ip = net_policy.check_ip(ip)
            if not ok_ip:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Disallowed target IP {h!r}: {reason_ip}",
                )
    return scope


@router.get("/targets")
async def list_targets(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    _operator: Operator = Depends(get_current_operator),
    db: AsyncSession = Depends(get_db),
) -> dict:
    base_stmt = select(Target).where(Target.archived.is_(False))
    total = (await db.execute(select(func.count()).select_from(base_stmt.subquery()))).scalar_one()
    rows = (
        await db.execute(base_stmt.order_by(Target.created_at.desc()).limit(limit).offset(offset))
    ).scalars().all()
    return {"items": [_serialize_target(t) for t in rows], "total": total}


@router.post("/targets", response_model=TargetOut, status_code=status.HTTP_201_CREATED)
async def create_target(
    payload: TargetCreateRequest,
    request: Request,
    operator: Operator = Depends(require_operator_or_admin),
    db: AsyncSession = Depends(get_db),
) -> TargetOut:
    scope = _validate_target_hosts(payload.base_url, payload.allowed_hosts)
    cfg = ScopeConfig.from_dict(payload.scope_config.model_dump() if payload.scope_config else None)
    access_tests = [item.model_dump() for item in (payload.access_tests or [])]
    for item in access_tests:
        if not scope.is_in_scope(item["url"]):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Access test URL {item['url']!r} is outside target scope",
            )
    settings = get_settings()
    auto_verify = settings.auto_verify_targets or settings.environment == "development"
    now = utcnow()
    target = Target(
        name=payload.name.strip(),
        base_url=scope.base_url,
        primary_host=scope.primary_host,
        allowed_hosts=sorted(scope.allowed_hosts),
        scope_config=cfg.to_dict(),
        access_tests=access_tests,
        integrations={"supabase": {"enabled": False, "project_url": None}},
        authorization_status=AuthorizationStatus.verified.value if auto_verify else AuthorizationStatus.pending.value,
        verification_method=VerificationMethod.attestation.value if auto_verify else None,
        verified_at=now if auto_verify else None,
        verification_token=new_verification_token(),
        owner_operator_id=operator.id,
    )
    db.add(target)
    await db.flush()
    await record_audit(
        db,
        "target.created",
        operator=operator,
        request=request,
        target_id=target.id,
        details={"name": target.name, "base_url": target.base_url, "allowed_hosts": target.allowed_hosts},
    )
    await db.refresh(target)
    return _serialize_target(target)


async def _get_active_target(db: AsyncSession, target_id: uuid.UUID) -> Target:
    target = await db.get(Target, target_id)
    if not target or target.archived:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")
    return target


@router.get("/targets/{target_id}", response_model=TargetOut)
async def get_target(
    target_id: uuid.UUID,
    _operator: Operator = Depends(get_current_operator),
    db: AsyncSession = Depends(get_db),
) -> TargetOut:
    target = await _get_active_target(db, target_id)
    return _serialize_target(target)


@router.patch("/targets/{target_id}", response_model=TargetOut)
async def update_target(
    target_id: uuid.UUID,
    payload: TargetUpdateRequest,
    request: Request,
    operator: Operator = Depends(require_operator_or_admin),
    db: AsyncSession = Depends(get_db),
) -> TargetOut:
    target = await _get_active_target(db, target_id)
    if payload.name is not None:
        target.name = payload.name.strip()
    if payload.allowed_hosts is not None:
        scope = _validate_target_hosts(target.base_url, payload.allowed_hosts)
        if set(scope.allowed_hosts) != set(target.allowed_hosts or []):
            # Changing hosts invalidates prior verification so an operator cannot add an unverified domain.
            target.allowed_hosts = sorted(scope.allowed_hosts)
            target.authorization_status = AuthorizationStatus.pending.value
            target.verified_at = None
    scope = ScopePolicy(target.base_url, target.allowed_hosts, target.scope_config)
    if payload.scope_config is not None:
        target.scope_config = ScopeConfig.from_dict(payload.scope_config.model_dump()).to_dict()
        scope = ScopePolicy(target.base_url, target.allowed_hosts, target.scope_config)
    if payload.access_tests is not None:
        items = [i.model_dump() for i in payload.access_tests]
        for item in items:
            if not scope.is_in_scope(item["url"]):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Access test URL {item['url']!r} is outside target scope",
                )
        target.access_tests = items
    if payload.integrations is not None and payload.integrations.supabase is not None:
        supa_in = payload.integrations.supabase
        existing_integrations = dict(target.integrations or {})
        existing_supa = dict(existing_integrations.get("supabase") or {})
        if supa_in.project_url:
            norm_url, _, _ = normalize_target_url(supa_in.project_url)
            existing_supa["project_url"] = norm_url
        elif supa_in.project_url == "":
            existing_supa["project_url"] = None
        existing_supa["enabled"] = supa_in.enabled
        if supa_in.anon_key:
            existing_supa["encrypted_anon_key"] = encrypt_secret(supa_in.anon_key)
        existing_integrations["supabase"] = existing_supa
        target.integrations = existing_integrations
    await record_audit(
        db,
        "target.updated",
        operator=operator,
        request=request,
        target_id=target.id,
        details={"name": target.name, "allowed_hosts": target.allowed_hosts},
    )
    await db.refresh(target)
    return _serialize_target(target)


@router.delete("/targets/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_target(
    target_id: uuid.UUID,
    request: Request,
    operator: Operator = Depends(require_operator_or_admin),
    db: AsyncSession = Depends(get_db),
) -> Response:
    target = await _get_active_target(db, target_id)
    target.archived = True
    target.authorization_status = AuthorizationStatus.revoked.value
    await record_audit(db, "target.archived", operator=operator, request=request, target_id=target.id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/targets/{target_id}/verification")
async def get_target_verification(
    target_id: uuid.UUID,
    _operator: Operator = Depends(get_current_operator),
    db: AsyncSession = Depends(get_db),
) -> dict:
    target = await _get_active_target(db, target_id)
    return verification_instructions(target)


@router.post("/targets/{target_id}/verify", response_model=VerifyTargetResponse)
async def verify_target(
    target_id: uuid.UUID,
    payload: VerifyTargetRequest,
    request: Request,
    operator: Operator = Depends(require_operator_or_admin),
    db: AsyncSession = Depends(get_db),
) -> VerifyTargetResponse:
    target = await _get_active_target(db, target_id)
    ok, detail = await perform_target_verification(target, payload.method)
    await record_audit(
        db,
        "target.verified" if ok else "target.verification_failed",
        operator=operator,
        request=request,
        target_id=target.id,
        details={"method": payload.method, "verified": ok, "detail": detail},
    )
    await db.refresh(target)
    return VerifyTargetResponse(verified=ok, detail=detail, target=_serialize_target(target))


@router.post("/targets/{target_id}/attest", response_model=TargetOut)
async def attest_target(
    target_id: uuid.UUID,
    payload: AttestTargetRequest,
    request: Request,
    admin: Operator = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> TargetOut:
    settings = get_settings()
    if not settings.attestation_allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Attestation-only authorization is disabled; verify via DNS TXT, well-known file, or meta tag",
        )
    if not payload.confirm:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Confirmation is required")
    target = await _get_active_target(db, target_id)
    now = utcnow()
    target.authorization_status = AuthorizationStatus.attested.value
    target.verification_method = VerificationMethod.attestation.value
    target.verified_at = now
    target.attestation = {
        "operator_id": str(admin.id),
        "operator_email": admin.email,
        "statement": payload.statement.strip(),
        "attested_at": now.isoformat(),
    }
    await record_audit(
        db,
        "target.attested",
        operator=admin,
        request=request,
        target_id=target.id,
        details={"statement": payload.statement.strip()},
    )
    await db.refresh(target)
    return _serialize_target(target)


@router.get("/targets/{target_id}/credentials")
async def list_credentials(
    target_id: uuid.UUID,
    _operator: Operator = Depends(get_current_operator),
    db: AsyncSession = Depends(get_db),
) -> dict:
    target = await _get_active_target(db, target_id)
    return {"items": [CredentialOut.model_validate(c) for c in target.credentials]}


@router.post("/targets/{target_id}/credentials", response_model=CredentialOut, status_code=status.HTTP_201_CREATED)
async def create_credential(
    target_id: uuid.UUID,
    payload: CredentialCreateRequest,
    request: Request,
    operator: Operator = Depends(require_operator_or_admin),
    db: AsyncSession = Depends(get_db),
) -> CredentialOut:
    target = await _get_active_target(db, target_id)
    if payload.auth_type == "header" and not payload.header_name:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="header_name is required for header auth")
    for existing in list(target.credentials):
        if existing.role_name.lower() == payload.role_name.lower():
            await db.delete(existing)
    cred = TargetCredential(
        target_id=target.id,
        role_name=payload.role_name,
        auth_type=payload.auth_type,
        header_name=payload.header_name,
        encrypted_value=encrypt_secret(payload.value),
        description=payload.description,
    )
    db.add(cred)
    await db.flush()
    await record_audit(
        db,
        "target.credential_saved",
        operator=operator,
        request=request,
        target_id=target.id,
        details={"role_name": cred.role_name, "auth_type": cred.auth_type},
    )
    return CredentialOut.model_validate(cred)


@router.delete("/targets/{target_id}/credentials/{cred_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_credential(
    target_id: uuid.UUID,
    cred_id: uuid.UUID,
    request: Request,
    operator: Operator = Depends(require_operator_or_admin),
    db: AsyncSession = Depends(get_db),
) -> Response:
    await _get_active_target(db, target_id)
    cred = await db.get(TargetCredential, cred_id)
    if not cred or cred.target_id != target_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Credential not found")
    role_name = cred.role_name
    await db.delete(cred)
    await record_audit(
        db,
        "target.credential_deleted",
        operator=operator,
        request=request,
        target_id=target_id,
        details={"role_name": role_name},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
