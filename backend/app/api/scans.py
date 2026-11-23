"""Scans, findings, source uploads, AI analysis, reports, dashboard, settings, and audit log endpoints."""

from __future__ import annotations

import hashlib
import shutil
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile, status
from fastapi.responses import FileResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import __version__
from app.api.deps import get_current_operator, require_admin, require_operator_or_admin
from app.api.schemas import (
    AIAnalysisOut,
    AISettingsOut,
    AISettingsUpdateRequest,
    ApiEndpointOut,
    AssetOut,
    AuditLogOut,
    FindingOut,
    FindingTriageRequest,
    PlatformSettingsOut,
    ReportCreateRequest,
    ReportOut,
    RouteOut,
    ScanCreateRequest,
    ScanOptionsSchema,
    ScanOut,
    SourceUploadOut,
    TechnologyOut,
)
from app.config import get_settings
from app.core.audit import record_audit
from app.core.crypto import encrypt_secret
from app.db.base import utcnow
from app.db.models import (
    AIAnalysis,
    ApiEndpoint,
    AppSetting,
    Asset,
    AuditLog,
    Finding,
    Operator,
    Report,
    Route,
    Scan,
    ScanStatus,
    SourceUpload,
    Target,
    Technology,
)
from app.db.session import get_db
from app.reports.generator import build_report_payload, generate_report_bytes
from app.scanner.engine import get_effective_ai_config
from app.scanner.source_analysis import UnsafeArchiveError, extract_safe_zip_entries
from app.scanner.verification import is_target_authorized
from app.worker import enqueue_analysis_job, enqueue_scan_job

router = APIRouter()


def _serialize_scan(scan: Scan, target: Target | None = None) -> ScanOut:
    tgt = target or scan.target
    default_stats = {
        "pages_crawled": 0,
        "requests_made": 0,
        "routes_discovered": 0,
        "admin_surfaces": 0,
        "api_endpoints": 0,
        "assets_analyzed": 0,
        "findings_total": 0,
        "findings_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "findings_by_status": {"confirmed": 0, "potential": 0, "informational": 0, "false_positive": 0, "not_tested": 0},
    }
    merged_stats = {**default_stats, **(scan.stats or {})}
    return ScanOut(
        id=scan.id,
        target_id=scan.target_id,
        target_name=tgt.name if tgt else "",
        target_url=tgt.base_url if tgt else "",
        operator_id=scan.operator_id,
        status=ScanStatus(scan.status),
        options=dict(scan.options or {}),
        progress=scan.progress,
        current_phase=scan.current_phase,
        phase_log=list(scan.phase_log or []),
        stats=merged_stats,
        created_at=scan.created_at,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        error=scan.error,
        cancel_requested=scan.cancel_requested,
    )


# --- Source Uploads ---


@router.post("/source-uploads", response_model=SourceUploadOut, status_code=status.HTTP_201_CREATED)
async def create_source_upload(
    request: Request,
    target_id: uuid.UUID = Form(...),
    file: UploadFile = File(...),
    operator: Operator = Depends(require_operator_or_admin),
    db: AsyncSession = Depends(get_db),
) -> SourceUploadOut:
    settings = get_settings()
    target = await db.get(Target, target_id)
    if not target or target.archived:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")

    raw_bytes = await file.read(settings.max_upload_bytes + 1)
    if len(raw_bytes) > settings.max_upload_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"ZIP archive exceeds maximum size of {settings.max_upload_bytes} bytes",
        )
    try:
        _entries, file_count = extract_safe_zip_entries(
            raw_bytes,
            max_files=settings.max_archive_files,
            max_total_bytes=settings.max_extracted_bytes,
            max_single_file_bytes=settings.max_source_file_bytes,
        )
    except UnsafeArchiveError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    sha = hashlib.sha256(raw_bytes).hexdigest()
    upload_id = uuid.uuid4()
    settings.uploads_dir.mkdir(parents=True, exist_ok=True)
    storage_path = settings.uploads_dir / f"{upload_id}.zip"
    storage_path.write_bytes(raw_bytes)

    safe_name = Path(file.filename or "source.zip").name[:200]
    rec = SourceUpload(
        id=upload_id,
        target_id=target.id,
        operator_id=operator.id,
        filename=safe_name,
        sha256=sha,
        size_bytes=len(raw_bytes),
        file_count=file_count,
        storage_path=str(storage_path),
        status="ready",
    )
    db.add(rec)
    await db.flush()
    await record_audit(
        db,
        "source_upload.created",
        operator=operator,
        request=request,
        target_id=target.id,
        details={"upload_id": str(rec.id), "filename": safe_name, "sha256": sha, "file_count": file_count},
    )
    return SourceUploadOut.model_validate(rec)


@router.get("/source-uploads")
async def list_source_uploads(
    target_id: uuid.UUID | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    _operator: Operator = Depends(get_current_operator),
    db: AsyncSession = Depends(get_db),
) -> dict:
    stmt = select(SourceUpload)
    if target_id:
        stmt = stmt.where(SourceUpload.target_id == target_id)
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    rows = (
        await db.execute(stmt.order_by(SourceUpload.created_at.desc()).limit(limit).offset(offset))
    ).scalars().all()
    return {"items": [SourceUploadOut.model_validate(r) for r in rows], "total": total}


# --- Scans ---


@router.get("/scans")
async def list_scans(
    target_id: uuid.UUID | None = Query(default=None),
    scan_status: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    _operator: Operator = Depends(get_current_operator),
    db: AsyncSession = Depends(get_db),
) -> dict:
    stmt = select(Scan)
    if target_id:
        stmt = stmt.where(Scan.target_id == target_id)
    if scan_status:
        stmt = stmt.where(Scan.status == scan_status)
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    rows = (await db.execute(stmt.order_by(Scan.created_at.desc()).limit(limit).offset(offset))).scalars().all()
    return {"items": [_serialize_scan(s) for s in rows], "total": total}


@router.post("/scans", response_model=ScanOut, status_code=status.HTTP_202_ACCEPTED)
async def create_scan(
    payload: ScanCreateRequest,
    request: Request,
    operator: Operator = Depends(require_operator_or_admin),
    db: AsyncSession = Depends(get_db),
) -> ScanOut:
    if not payload.authorization_confirmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Explicit target authorization confirmation is required before starting a scan",
        )
    target = await db.get(Target, payload.target_id)
    if not target or target.archived:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")

    ok, reason = is_target_authorized(target)
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot start scan: {reason}. Complete target verification first.",
        )

    opts = (payload.options or ScanOptionsSchema()).model_dump(mode="json")
    source_upload_id: uuid.UUID | None = None
    if payload.options and payload.options.source_upload_id:
        su = await db.get(SourceUpload, payload.options.source_upload_id)
        if not su or su.target_id != target.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="source_upload_id does not belong to this target",
            )
        source_upload_id = su.id

    now = utcnow()
    scan = Scan(
        target_id=target.id,
        operator_id=operator.id,
        status=ScanStatus.queued.value,
        options=opts,
        authorization={
            "confirmed": True,
            "statement": payload.authorization_statement.strip(),
            "operator_id": str(operator.id),
            "operator_email": operator.email,
            "target_verification_method": target.verification_method,
            "confirmed_at": now.isoformat(),
        },
        progress=0,
        current_phase="queued",
        phase_log=[
            {
                "phase": "queued",
                "status": "completed",
                "started_at": now.isoformat(),
                "finished_at": now.isoformat(),
                "message": "Scan authorized and queued for execution",
            }
        ],
        source_upload_id=source_upload_id,
    )
    db.add(scan)
    await db.flush()
    await record_audit(
        db,
        "scan.created",
        operator=operator,
        request=request,
        target_id=target.id,
        scan_id=scan.id,
        details={
            "target_url": target.base_url,
            "authorization_statement": payload.authorization_statement.strip(),
            "options": opts,
        },
    )
    await db.refresh(scan)
    await enqueue_scan_job(scan.id)
    return _serialize_scan(scan, target)


async def _get_scan_or_404(db: AsyncSession, scan_id: uuid.UUID) -> Scan:
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return scan


@router.get("/scans/{scan_id}", response_model=ScanOut)
async def get_scan(
    scan_id: uuid.UUID,
    _operator: Operator = Depends(get_current_operator),
    db: AsyncSession = Depends(get_db),
) -> ScanOut:
    scan = await _get_scan_or_404(db, scan_id)
    return _serialize_scan(scan)


@router.post("/scans/{scan_id}/cancel", response_model=ScanOut)
async def cancel_scan(
    scan_id: uuid.UUID,
    request: Request,
    operator: Operator = Depends(require_operator_or_admin),
    db: AsyncSession = Depends(get_db),
) -> ScanOut:
    scan = await _get_scan_or_404(db, scan_id)
    scan.cancel_requested = True
    if scan.status == ScanStatus.queued.value:
        scan.status = ScanStatus.cancelled.value
        scan.finished_at = utcnow()
    await record_audit(
        db, "scan.cancel_requested", operator=operator, request=request, target_id=scan.target_id, scan_id=scan.id
    )
    await db.refresh(scan)
    return _serialize_scan(scan)


@router.get("/scans/{scan_id}/technologies")
async def list_scan_technologies(
    scan_id: uuid.UUID,
    _operator: Operator = Depends(get_current_operator),
    db: AsyncSession = Depends(get_db),
) -> dict:
    await _get_scan_or_404(db, scan_id)
    rows = (
        await db.execute(
            select(Technology).where(Technology.scan_id == scan_id).order_by(Technology.confidence.desc())
        )
    ).scalars().all()
    return {"items": [TechnologyOut.model_validate(r) for r in rows]}


@router.get("/scans/{scan_id}/routes")
async def list_scan_routes(
    scan_id: uuid.UUID,
    admin_only: bool = Query(default=False),
    category: str | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    _operator: Operator = Depends(get_current_operator),
    db: AsyncSession = Depends(get_db),
) -> dict:
    await _get_scan_or_404(db, scan_id)
    stmt = select(Route).where(Route.scan_id == scan_id)
    if admin_only:
        stmt = stmt.where(Route.is_admin_surface.is_(True))
    if category:
        stmt = stmt.where(Route.admin_category == category)
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    rows = (
        await db.execute(stmt.order_by(Route.is_admin_surface.desc(), Route.path.asc()).limit(limit).offset(offset))
    ).scalars().all()
    return {"items": [RouteOut.model_validate(r) for r in rows], "total": total}


@router.get("/scans/{scan_id}/routes/{route_id}", response_model=RouteOut)
async def get_scan_route(
    scan_id: uuid.UUID,
    route_id: uuid.UUID,
    _operator: Operator = Depends(get_current_operator),
    db: AsyncSession = Depends(get_db),
) -> RouteOut:
    route = await db.get(Route, route_id)
    if not route or route.scan_id != scan_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Route not found")
    return RouteOut.model_validate(route)


@router.get("/scans/{scan_id}/endpoints")
async def list_scan_endpoints(
    scan_id: uuid.UUID,
    category: str | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    _operator: Operator = Depends(get_current_operator),
    db: AsyncSession = Depends(get_db),
) -> dict:
    await _get_scan_or_404(db, scan_id)
    stmt = select(ApiEndpoint).where(ApiEndpoint.scan_id == scan_id)
    if category:
        stmt = stmt.where(ApiEndpoint.category == category)
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    rows = (
        await db.execute(stmt.order_by(ApiEndpoint.path_template.asc()).limit(limit).offset(offset))
    ).scalars().all()
    return {"items": [ApiEndpointOut.model_validate(r) for r in rows], "total": total}


@router.get("/scans/{scan_id}/assets")
async def list_scan_assets(
    scan_id: uuid.UUID,
    limit: int = Query(default=200, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    _operator: Operator = Depends(get_current_operator),
    db: AsyncSession = Depends(get_db),
) -> dict:
    await _get_scan_or_404(db, scan_id)
    stmt = select(Asset).where(Asset.scan_id == scan_id)
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    rows = (await db.execute(stmt.order_by(Asset.url.asc()).limit(limit).offset(offset))).scalars().all()
    return {"items": [AssetOut.model_validate(r) for r in rows], "total": total}


@router.get("/scans/{scan_id}/findings")
async def list_scan_findings(
    scan_id: uuid.UUID,
    category: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    finding_status: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=200, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    _operator: Operator = Depends(get_current_operator),
    db: AsyncSession = Depends(get_db),
) -> dict:
    await _get_scan_or_404(db, scan_id)
    stmt = select(Finding).where(Finding.scan_id == scan_id)
    if category:
        cats = [c.strip() for c in category.split(",") if c.strip()]
        stmt = stmt.where(Finding.category.in_(cats))
    if severity:
        sevs = [s.strip() for s in severity.split(",") if s.strip()]
        stmt = stmt.where(Finding.severity.in_(sevs))
    if finding_status:
        sts = [s.strip() for s in finding_status.split(",") if s.strip()]
        stmt = stmt.where(Finding.status.in_(sts))
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    rows = (await db.execute(stmt.order_by(Finding.created_at.asc()).limit(limit).offset(offset))).scalars().all()
    return {"items": [FindingOut.model_validate(r) for r in rows], "total": total}


@router.get("/findings/{finding_id}", response_model=FindingOut)
async def get_finding(
    finding_id: uuid.UUID,
    _operator: Operator = Depends(get_current_operator),
    db: AsyncSession = Depends(get_db),
) -> FindingOut:
    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return FindingOut.model_validate(finding)


@router.patch("/findings/{finding_id}", response_model=FindingOut)
async def triage_finding(
    finding_id: uuid.UUID,
    payload: FindingTriageRequest,
    request: Request,
    operator: Operator = Depends(require_operator_or_admin),
    db: AsyncSession = Depends(get_db),
) -> FindingOut:
    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    finding.verification_status = payload.verification_status.value
    if payload.operator_note is not None:
        finding.operator_note = payload.operator_note
    if payload.verification_status.value == "false_positive":
        finding.status = "false_positive"
    await record_audit(
        db,
        "finding.triaged",
        operator=operator,
        request=request,
        scan_id=finding.scan_id,
        details={
            "finding_id": str(finding.id),
            "finding_key": finding.finding_key,
            "verification_status": finding.verification_status,
        },
    )
    return FindingOut.model_validate(finding)


# --- AI Analysis ---


@router.post("/scans/{scan_id}/analysis", response_model=AIAnalysisOut, status_code=status.HTTP_202_ACCEPTED)
async def trigger_scan_analysis(
    scan_id: uuid.UUID,
    request: Request,
    operator: Operator = Depends(require_operator_or_admin),
    db: AsyncSession = Depends(get_db),
) -> AIAnalysisOut:
    scan = await _get_scan_or_404(db, scan_id)
    ai_cfg = await get_effective_ai_config(db)
    record = AIAnalysis(
        scan_id=scan.id,
        provider=ai_cfg["provider"] if ai_cfg["provider"] == "openai" and ai_cfg["api_key"] else "deterministic",
        model=ai_cfg["model"],
        status="pending",
    )
    db.add(record)
    await db.flush()
    await record_audit(
        db,
        "analysis.triggered",
        operator=operator,
        request=request,
        target_id=scan.target_id,
        scan_id=scan.id,
        details={"analysis_id": str(record.id)},
    )
    await db.refresh(record)
    await enqueue_analysis_job(scan.id, record.id)
    return AIAnalysisOut.model_validate(record)


@router.get("/scans/{scan_id}/analysis", response_model=AIAnalysisOut)
async def get_scan_analysis(
    scan_id: uuid.UUID,
    _operator: Operator = Depends(get_current_operator),
    db: AsyncSession = Depends(get_db),
) -> AIAnalysisOut:
    await _get_scan_or_404(db, scan_id)
    stmt = select(AIAnalysis).where(AIAnalysis.scan_id == scan_id).order_by(AIAnalysis.created_at.desc()).limit(1)
    rec = (await db.execute(stmt)).scalar_one_or_none()
    if not rec:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No AI analysis generated for this scan yet")
    return AIAnalysisOut.model_validate(rec)


# --- Reports ---


@router.post("/scans/{scan_id}/reports", response_model=ReportOut, status_code=status.HTTP_201_CREATED)
async def create_scan_report(
    scan_id: uuid.UUID,
    payload: ReportCreateRequest,
    request: Request,
    operator: Operator = Depends(require_operator_or_admin),
    db: AsyncSession = Depends(get_db),
) -> ReportOut:
    settings = get_settings()
    scan = await _get_scan_or_404(db, scan_id)
    target = await db.get(Target, scan.target_id)
    assert target is not None

    tech_rows = (await db.execute(select(Technology).where(Technology.scan_id == scan_id))).scalars().all()
    route_rows = (await db.execute(select(Route).where(Route.scan_id == scan_id))).scalars().all()
    ep_rows = (await db.execute(select(ApiEndpoint).where(ApiEndpoint.scan_id == scan_id))).scalars().all()
    finding_rows = (await db.execute(select(Finding).where(Finding.scan_id == scan_id))).scalars().all()
    analysis_row = (
        await db.execute(
            select(AIAnalysis)
            .where(AIAnalysis.scan_id == scan_id, AIAnalysis.status == "completed")
            .order_by(AIAnalysis.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()

    report_payload = build_report_payload(
        target={
            "id": str(target.id),
            "name": target.name,
            "base_url": target.base_url,
            "primary_host": target.primary_host,
            "allowed_hosts": target.allowed_hosts,
            "authorization_status": target.authorization_status,
            "verification_method": target.verification_method,
        },
        scan=_serialize_scan(scan, target).model_dump(mode="json"),
        technologies=[TechnologyOut.model_validate(t).model_dump(mode="json") for t in tech_rows],
        routes=[RouteOut.model_validate(r).model_dump(mode="json") for r in route_rows],
        endpoints=[ApiEndpointOut.model_validate(e).model_dump(mode="json") for e in ep_rows],
        findings=[FindingOut.model_validate(f).model_dump(mode="json") for f in finding_rows],
        analysis=AIAnalysisOut.model_validate(analysis_row).model_dump(mode="json") if analysis_row else None,
    )

    content_bytes, sha = generate_report_bytes(payload.format, report_payload)
    report_id = uuid.uuid4()
    settings.reports_dir.mkdir(parents=True, exist_ok=True)
    file_path = settings.reports_dir / f"vibescan-report-{scan_id}-{report_id}.{payload.format}"
    file_path.write_bytes(content_bytes)

    rep = Report(
        id=report_id,
        scan_id=scan.id,
        operator_id=operator.id,
        format=payload.format,
        path=str(file_path),
        size_bytes=len(content_bytes),
        sha256=sha,
    )
    db.add(rep)
    await db.flush()
    await record_audit(
        db,
        "report.generated",
        operator=operator,
        request=request,
        target_id=target.id,
        scan_id=scan.id,
        details={"report_id": str(rep.id), "format": rep.format, "sha256": rep.sha256},
    )
    return ReportOut.model_validate(rep)


@router.get("/scans/{scan_id}/reports")
async def list_scan_reports(
    scan_id: uuid.UUID,
    _operator: Operator = Depends(get_current_operator),
    db: AsyncSession = Depends(get_db),
) -> dict:
    await _get_scan_or_404(db, scan_id)
    rows = (
        await db.execute(select(Report).where(Report.scan_id == scan_id).order_by(Report.created_at.desc()))
    ).scalars().all()
    return {"items": [ReportOut.model_validate(r) for r in rows], "total": len(rows)}


@router.get("/reports/{report_id}/download")
async def download_report(
    report_id: uuid.UUID,
    _operator: Operator = Depends(get_current_operator),
    db: AsyncSession = Depends(get_db),
) -> FileResponse:
    rep = await db.get(Report, report_id)
    if not rep or not Path(rep.path).is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report file not found")
    media_types = {
        "html": "text/html; charset=utf-8",
        "json": "application/json; charset=utf-8",
        "pdf": "application/pdf",
    }
    return FileResponse(
        path=rep.path,
        media_type=media_types.get(rep.format, "application/octet-stream"),
        filename=f"vibescan-report-{rep.scan_id}.{rep.format}",
    )


# --- Dashboard Summary ---


@router.get("/dashboard/summary")
async def dashboard_summary(
    _operator: Operator = Depends(get_current_operator),
    db: AsyncSession = Depends(get_db),
) -> dict:
    total_targets = (
        await db.execute(select(func.count()).select_from(Target).where(Target.archived.is_(False)))
    ).scalar_one()
    verified_targets = (
        await db.execute(
            select(func.count())
            .select_from(Target)
            .where(Target.archived.is_(False), Target.authorization_status.in_(["verified", "attested"]))
        )
    ).scalar_one()
    total_scans = (await db.execute(select(func.count()).select_from(Scan))).scalar_one()
    running_scans = (
        await db.execute(select(func.count()).select_from(Scan).where(Scan.status.in_(["queued", "running"])))
    ).scalar_one()
    total_routes = (await db.execute(select(func.count()).select_from(Route))).scalar_one()
    admin_surfaces = (
        await db.execute(select(func.count()).select_from(Route).where(Route.is_admin_surface.is_(True)))
    ).scalar_one()

    all_findings = (
        await db.execute(select(Finding).where(Finding.status != "false_positive"))
    ).scalars().all()

    by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    by_cat: dict[str, int] = {}
    exposed_cfg = 0
    ac_count = 0
    for f in all_findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        by_cat[f.category] = by_cat.get(f.category, 0) + 1
        if f.category in ("configuration_exposure", "secret_exposure", "database_policy"):
            exposed_cfg += 1
        if f.category == "access_control":
            ac_count += 1

    recent_scan_rows = (
        await db.execute(select(Scan).order_by(Scan.created_at.desc()).limit(10))
    ).scalars().all()
    recent_scans = [_serialize_scan(s) for s in recent_scan_rows]

    trend = []
    for s in reversed(recent_scan_rows):
        f_sev = (s.stats or {}).get("findings_by_severity") or {}
        trend.append(
            {
                "scan_id": str(s.id),
                "date": s.created_at.isoformat(),
                "target_name": s.target.name if s.target else "",
                "critical": int(f_sev.get("critical", 0)),
                "high": int(f_sev.get("high", 0)),
                "medium": int(f_sev.get("medium", 0)),
                "low": int(f_sev.get("low", 0)),
                "info": int(f_sev.get("info", 0)),
            }
        )

    return {
        "total_targets": total_targets,
        "verified_targets": verified_targets,
        "total_scans": total_scans,
        "running_scans": running_scans,
        "total_routes_scanned": total_routes,
        "admin_surfaces": admin_surfaces,
        "exposed_configurations": exposed_cfg,
        "access_control_findings": ac_count,
        "critical_high_findings": by_sev["critical"] + by_sev["high"],
        "findings_by_severity": by_sev,
        "findings_by_category": by_cat,
        "severity_trend": trend,
        "recent_scans": recent_scans,
    }


# --- Settings & Audit Logs ---


@router.get("/settings/ai", response_model=AISettingsOut)
async def get_ai_settings(
    _admin: Operator = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> AISettingsOut:
    cfg = await get_effective_ai_config(db)
    return AISettingsOut(
        provider=cfg["provider"],
        model=cfg["model"],
        base_url=cfg["base_url"],
        api_key_set=bool(cfg["api_key"]),
        auto_analyze=cfg["auto_analyze"],
    )


@router.put("/settings/ai", response_model=AISettingsOut)
async def update_ai_settings(
    payload: AISettingsUpdateRequest,
    request: Request,
    admin: Operator = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> AISettingsOut:
    row = await db.get(AppSetting, "ai_config")
    current = dict(row.value) if row and row.value else {}
    current["provider"] = payload.provider
    current["model"] = payload.model.strip()
    current["base_url"] = payload.base_url.strip()
    current["auto_analyze"] = payload.auto_analyze
    if payload.api_key:
        current["encrypted_api_key"] = encrypt_secret(payload.api_key)
    if row is None:
        row = AppSetting(key="ai_config", value=current)
        db.add(row)
    else:
        row.value = current
    await record_audit(
        db,
        "settings.ai_updated",
        operator=admin,
        request=request,
        details={"provider": payload.provider, "model": payload.model, "auto_analyze": payload.auto_analyze},
    )
    cfg = await get_effective_ai_config(db)
    return AISettingsOut(
        provider=cfg["provider"],
        model=cfg["model"],
        base_url=cfg["base_url"],
        api_key_set=bool(cfg["api_key"]),
        auto_analyze=cfg["auto_analyze"],
    )


@router.get("/settings/platform", response_model=PlatformSettingsOut)
async def get_platform_settings(
    _operator: Operator = Depends(get_current_operator),
) -> PlatformSettingsOut:
    s = get_settings()
    try:
        import playwright  # noqa: F401

        pw_avail = True
    except ImportError:
        pw_avail = False
    return PlatformSettingsOut(
        lab_mode=s.lab_mode,
        allow_attestation_only=s.attestation_allowed,
        allow_private_targets=s.allow_private_targets,
        max_scan_timeout_seconds=s.max_scan_timeout_seconds,
        semgrep_available=shutil.which(s.semgrep_binary) is not None,
        playwright_available=pw_avail,
        version=__version__,
    )


@router.get("/audit-logs")
async def list_audit_logs(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    _admin: Operator = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    total = (await db.execute(select(func.count()).select_from(AuditLog))).scalar_one()
    rows = (
        await db.execute(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit).offset(offset))
    ).scalars().all()
    return {"items": [AuditLogOut.model_validate(r) for r in rows], "total": total}
