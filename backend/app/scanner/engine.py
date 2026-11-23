"""Scan orchestrator engine: runs Phases 1–11 with progress tracking, timeout, and cooperative cancellation."""

from __future__ import annotations

import asyncio
import logging
import uuid
from pathlib import Path

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.crypto import decrypt_secret
from app.db.base import utcnow
from app.db.models import (
    AIAnalysis,
    ApiEndpoint,
    AppSetting,
    Asset,
    Finding,
    Route,
    Scan,
    ScanStatus,
    SourceUpload,
    Target,
    Technology,
)
from app.db.session import get_sessionmaker
from app.scanner.access_control import SuppliedCredential, run_access_control_audit
from app.scanner.admin_surface import DiscoveredRoute, discover_routes_and_admin_surfaces
from app.scanner.ai_analyst import run_ai_security_analysis
from app.scanner.api_discovery import ApiDiscoveryOutcome, run_api_discovery
from app.scanner.baseline import build_baseline
from app.scanner.config_exposure import ConfigExposureOutcome, run_config_exposure_audit
from app.scanner.crawler import CrawlOutcome, run_crawler
from app.scanner.findings import FindingDraft, deduplicate_findings
from app.scanner.fingerprint import fingerprint_application
from app.scanner.http import (
    BlockedDestinationError,
    SafeHttpClient,
    ScanCancelledError,
    build_netguard_from_settings,
)
from app.scanner.netguard import NetGuard
from app.scanner.pentest_checks import run_pentest_checks
from app.scanner.scope import ScopePolicy
from app.scanner.sensitive_data import run_sensitive_data_scan
from app.scanner.source_analysis import (
    analyze_source_entries,
    extract_safe_zip_entries,
    recovered_sourcemaps_to_entries,
)
from app.scanner.verification import is_target_authorized

log = logging.getLogger("vibescan.engine")


async def get_effective_ai_config(db: AsyncSession) -> dict:
    s = get_settings()
    row = await db.get(AppSetting, "ai_config")
    stored = dict(row.value) if row and row.value else {}
    api_key = s.openai_api_key
    if stored.get("encrypted_api_key"):
        try:
            api_key = decrypt_secret(stored["encrypted_api_key"])
        except Exception:
            pass
    return {
        "provider": stored.get("provider", s.ai_provider),
        "model": stored.get("model", s.ai_model),
        "base_url": stored.get("base_url", s.ai_base_url),
        "api_key": api_key,
        "auto_analyze": bool(stored.get("auto_analyze", s.ai_auto_analyze)),
    }


async def execute_scan(
    scan_id: uuid.UUID,
    *,
    guard: NetGuard | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> None:
    """Run the full scan pipeline for ``scan_id`` and persist all telemetry and findings."""
    settings = get_settings()
    session_factory = get_sessionmaker()

    async with session_factory() as db:
        scan = await db.get(Scan, scan_id)
        if scan is None or ScanStatus(scan.status).is_terminal:
            return
        target = await db.get(Target, scan.target_id)
        if target is None:
            scan.status = ScanStatus.failed.value
            scan.error = "Target not found"
            await db.commit()
            return

        options = dict(scan.options or {})
        timeout_sec = min(
            int(options.get("timeout_seconds") or settings.default_scan_timeout_seconds),
            settings.max_scan_timeout_seconds,
        )
        scan.status = ScanStatus.running.value
        scan.started_at = utcnow()
        target.last_scan_at = scan.started_at
        await db.commit()

    try:
        await asyncio.wait_for(
            _run_pipeline(scan_id, guard=guard, transport=transport),
            timeout=timeout_sec,
        )
    except TimeoutError:
        async with session_factory() as db:
            scan = await db.get(Scan, scan_id)
            if scan and not ScanStatus(scan.status).is_terminal:
                scan.status = ScanStatus.timed_out.value
                scan.finished_at = utcnow()
                scan.error = f"Scan exceeded timeout ({timeout_sec}s); partial results preserved"
                await db.commit()
    except ScanCancelledError:
        async with session_factory() as db:
            scan = await db.get(Scan, scan_id)
            if scan:
                scan.status = ScanStatus.cancelled.value
                scan.finished_at = utcnow()
                await db.commit()
    except Exception as exc:
        log.exception("Scan %s failed", scan_id)
        async with session_factory() as db:
            scan = await db.get(Scan, scan_id)
            if scan and not ScanStatus(scan.status).is_terminal:
                scan.status = ScanStatus.failed.value
                scan.finished_at = utcnow()
                scan.error = str(exc)[:1000]
                await db.commit()


async def _run_pipeline(
    scan_id: uuid.UUID,
    *,
    guard: NetGuard | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> None:
    settings = get_settings()
    session_factory = get_sessionmaker()

    async def check_cancelled() -> bool:
        async with session_factory() as s_db:
            val = (await s_db.execute(select(Scan.cancel_requested).where(Scan.id == scan_id))).scalar_one_or_none()
            return bool(val)

    async def set_phase(phase: str, progress: int, message: str, status: str = "completed") -> None:
        async with session_factory() as s_db:
            sc = await s_db.get(Scan, scan_id)
            if not sc:
                return
            if sc.cancel_requested:
                raise ScanCancelledError("Scan cancelled by operator")
            now_iso = utcnow().isoformat()
            log_entries = list(sc.phase_log or [])
            log_entries.append(
                {
                    "phase": phase,
                    "status": status,
                    "started_at": now_iso,
                    "finished_at": now_iso,
                    "message": message,
                }
            )
            sc.current_phase = phase
            sc.progress = progress
            sc.phase_log = log_entries
            await s_db.commit()

    async with session_factory() as db:
        scan = await db.get(Scan, scan_id)
        assert scan is not None
        target = await db.get(Target, scan.target_id)
        assert target is not None
        options = dict(scan.options or {})

        # Phase 1: Preflight authorization & DNS / scope check
        auth_ok, auth_msg = is_target_authorized(target, settings)
        if not auth_ok:
            raise PermissionError(f"Target authorization invalid at scan start: {auth_msg}")
        pentest_profile = str(options.get("pentest_profile") or "standard")
        if pentest_profile not in ("standard", "deep", "enterprise"):
            pentest_profile = "standard"

        eff_scope_cfg = dict(target.scope_config or {})
        if pentest_profile == "deep":
            eff_scope_cfg["concurrency"] = max(int(eff_scope_cfg.get("concurrency", 4)), 12)
            eff_scope_cfg["requests_per_second"] = max(float(eff_scope_cfg.get("requests_per_second", 5.0)), 25.0)
            eff_scope_cfg["max_pages"] = max(int(eff_scope_cfg.get("max_pages", 150)), 500)
            eff_max_requests = min(10000, settings.max_requests_per_scan)
            eff_max_endpoints = 250
        elif pentest_profile == "enterprise":
            eff_scope_cfg["concurrency"] = max(int(eff_scope_cfg.get("concurrency", 4)), 25)
            eff_scope_cfg["requests_per_second"] = max(float(eff_scope_cfg.get("requests_per_second", 5.0)), 60.0)
            eff_scope_cfg["max_pages"] = max(int(eff_scope_cfg.get("max_pages", 150)), 1500)
            eff_max_requests = settings.max_requests_per_scan
            eff_max_endpoints = 500
        else:
            eff_max_requests = min(3000, settings.max_requests_per_scan)
            eff_max_endpoints = 80

        scope = ScopePolicy(target.base_url, target.allowed_hosts, eff_scope_cfg)
        net_guard = guard or build_netguard_from_settings()
        if transport is None:
            for h in scope.allowed_hosts:
                try:
                    await net_guard.resolve(h, scope.primary_port)
                except BlockedDestinationError as exc:
                    raise PermissionError(f"Preflight DNS/SSRF policy check blocked {h}: {exc.reason}") from exc

        # Decrypt owner-supplied credentials and optional Supabase anon key in memory
        supplied_creds: list[SuppliedCredential] = []
        for cred in target.credentials or []:
            try:
                supplied_creds.append(
                    SuppliedCredential(
                        role_name=cred.role_name,
                        auth_type=cred.auth_type,
                        header_name=cred.header_name,
                        value=decrypt_secret(cred.encrypted_value),
                    )
                )
            except Exception:
                continue

        supa_cfg_raw = dict((target.integrations or {}).get("supabase") or {})
        supa_integration: dict | None = None
        if supa_cfg_raw.get("enabled") and supa_cfg_raw.get("project_url") and supa_cfg_raw.get("encrypted_anon_key"):
            try:
                supa_integration = {
                    "enabled": True,
                    "project_url": supa_cfg_raw["project_url"],
                    "anon_key": decrypt_secret(supa_cfg_raw["encrypted_anon_key"]),
                }
            except Exception:
                supa_integration = None

        access_tests = list(target.access_tests or [])
        source_upload_id = scan.source_upload_id or options.get("source_upload_id")
        source_upload: SourceUpload | None = None
        if source_upload_id:
            try:
                source_upload = await db.get(SourceUpload, uuid.UUID(str(source_upload_id)))
            except Exception:
                source_upload = None

    await set_phase("preflight", 10, f"Verified authorization and scope for {scope.base_url}")

    all_drafts: list[FindingDraft] = []
    discovered_routes: list[DiscoveredRoute] = []
    api_out = ApiDiscoveryOutcome()
    cfg_out = ConfigExposureOutcome()
    techs = []

    async with SafeHttpClient(
        scope,
        net_guard,
        user_agent=settings.user_agent,
        max_requests=eff_max_requests,
        max_response_bytes=settings.max_response_bytes,
        cancel_check=check_cancelled,
        transport=transport,
    ) as client:
        # Phase 2 & 3: Crawl + robots.txt + JS bundle harvesting
        if options.get("crawl", True):
            crawl = await run_crawler(
                client,
                scope,
                max_pages_override=options.get("max_pages"),
                render_js=bool(options.get("render_js", scope.config.render_js)),
            )
        else:
            crawl = CrawlOutcome(robots=await run_crawler(client, scope, max_pages_override=1).robots)  # type: ignore[attr-defined]
        await set_phase(
            "crawl",
            28,
            f"Crawled {len(crawl.page_responses)} pages and analyzed {len(crawl.assets)} frontend assets",
        )

        # Baseline profile (SPA shell & soft-404)
        root_resp = crawl.page_responses.get(scope.base_url)
        baseline = await build_baseline(client, scope.base_url, root_resp)
        await set_phase(
            "baseline",
            36,
            f"Fingerprinted baseline response (SPA catch-all={'yes' if baseline.is_spa_catchall else 'no'})",
        )

        # Phase 4: Framework & vibe-coding platform fingerprinting
        techs = fingerprint_application(
            list(crawl.page_responses.values()),
            list(crawl.parsed_pages.values()),
            [(a.url, a.response.text) for a in crawl.assets.values() if a.kind == "js"],
            crawl.js_results,
        )
        await set_phase(
            "fingerprint",
            45,
            f"Identified {len(techs)} technologies/platforms: {', '.join(t.name for t in techs) or 'none'}",
        )

        # Phase 5: Admin Surface Discovery (Module B)
        discovered_routes = await discover_routes_and_admin_surfaces(
            client,
            scope,
            crawl,
            baseline,
            enable_path_probing=bool(options.get("path_probing", True)),
        )
        admin_count = sum(1 for r in discovered_routes if r.is_admin_surface)
        await set_phase(
            "admin_surface",
            58,
            f"Evaluated {len(discovered_routes)} routes ({admin_count} administrative/management surfaces)",
        )

        # Phase 6: Configuration Exposure Detection (Module D)
        if options.get("config_exposure", True):
            cfg_out = await run_config_exposure_audit(
                client,
                scope,
                crawl,
                baseline,
                supabase_integration=supa_integration,
            )
            all_drafts.extend(cfg_out.findings)
            await set_phase(
                "config_exposure",
                70,
                f"Checked configuration artifacts, secrets, and BaaS surface ({len(cfg_out.findings)} findings)",
            )

        # Phase 7: API Security Discovery (Module E)
        if options.get("api_discovery", True):
            api_out = await run_api_discovery(client, scope, crawl, baseline, max_endpoints=eff_max_endpoints)
            all_drafts.extend(api_out.findings)
            await set_phase(
                "api_discovery",
                80,
                f"Discovered and safely inspected {len(api_out.endpoints)} API endpoints",
            )

        # Phase 8: Access Control Audit (Module C)
        if options.get("access_control", True):
            ac_drafts = await run_access_control_audit(
                client,
                scope,
                crawl,
                baseline,
                discovered_routes,
                api_out.endpoints,
                credentials=supplied_creds,
                access_tests=access_tests,
            )
            all_drafts.extend(ac_drafts)
            await set_phase(
                "access_control",
                84,
                f"Completed access-control audit across anonymous and {len(supplied_creds)} supplied test role(s)",
            )

        # Phase 8b: Website Pentest & Administration Hardening Checks (Module G)
        if options.get("pentest_checks", True):
            pt_out = await run_pentest_checks(
                client,
                scope,
                crawl,
                baseline,
                discovered_routes,
                api_out.endpoints,
                profile=pentest_profile,  # type: ignore[arg-type]
            )
            all_drafts.extend(pt_out.findings)
            await set_phase(
                "pentest_checks",
                88,
                f"Completed {pt_out.checks_run} defensive pentest checks [profile={pentest_profile}] ({len(pt_out.findings)} findings)",
            )

        # Phase 8c: Sensitive Data & PII Exposure Scan (Module H)
        if options.get("sensitive_data", True):
            sd_out = run_sensitive_data_scan(
                crawl,
                api_out.endpoints,
                cfg_out.recovered_sources,
            )
            all_drafts.extend(sd_out.findings)
            await set_phase(
                "sensitive_data",
                91,
                f"Scanned {sd_out.sources_scanned} assets/responses for PII & sensitive data ({len(sd_out.findings)} findings)",
            )

        requests_made = client.requests_made

    # Phase 9: Source Code Security Analysis (Module F) — uploaded ZIP + recovered source maps
    if options.get("source_analysis", True):
        source_entries = recovered_sourcemaps_to_entries(cfg_out.recovered_sources)
        if source_upload and Path(source_upload.storage_path).is_file():
            zip_bytes = Path(source_upload.storage_path).read_bytes()
            zip_entries, _ = extract_safe_zip_entries(zip_bytes)
            source_entries.extend(zip_entries)
        if source_entries:
            src_drafts = await analyze_source_entries(source_entries)
            all_drafts.extend(src_drafts)
            await set_phase(
                "source_analysis",
                94,
                f"Analyzed {len(source_entries)} source files ({len(src_drafts)} findings)",
            )

    # Phase 10: Deduplicate findings, compute CVSS 4.0, and persist everything
    final_findings = deduplicate_findings(all_drafts)

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    status_counts = {"confirmed": 0, "potential": 0, "informational": 0, "false_positive": 0, "not_tested": 0}
    for f in final_findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
        status_counts[f["status"]] = status_counts.get(f["status"], 0) + 1

    stats = {
        "pages_crawled": len(crawl.page_responses),
        "requests_made": requests_made,
        "routes_discovered": len(discovered_routes),
        "admin_surfaces": sum(1 for r in discovered_routes if r.is_admin_surface),
        "api_endpoints": len(api_out.endpoints),
        "assets_analyzed": len(crawl.assets),
        "findings_total": len(final_findings),
        "findings_by_severity": sev_counts,
        "findings_by_status": status_counts,
    }

    async with session_factory() as db:
        scan = await db.get(Scan, scan_id)
        assert scan is not None
        scan.baseline = baseline.to_dict()
        scan.stats = stats

        for t in techs:
            db.add(
                Technology(
                    scan_id=scan_id,
                    name=t.name,
                    kind=t.kind,
                    confidence=t.confidence,
                    evidence=[s.to_dict() for s in t.signals],
                )
            )

        for asset_url, asset in crawl.assets.items():
            sm_url = cfg_out.exposed_source_maps.get(asset_url)
            db.add(
                Asset(
                    scan_id=scan_id,
                    url=asset_url,
                    kind=asset.kind,
                    size_bytes=len(asset.response.body),
                    sha256=asset.response.sha256,
                    source_map_url=sm_url,
                    source_map_exposed=sm_url is not None,
                )
            )

        for r in discovered_routes:
            db.add(
                Route(
                    scan_id=scan_id,
                    url=r.url,
                    path=r.path,
                    status_code=r.status_code,
                    title=r.title,
                    content_type=r.content_type,
                    content_hash=r.content_hash,
                    auth_observation=r.auth_observation,
                    redirect_chain=r.redirect_chain,
                    discovery_methods=r.discovery_methods,
                    admin_category=r.admin_category,
                    is_admin_surface=r.is_admin_surface,
                    confidence=r.confidence,
                    risk_level=r.risk_level,
                    evidence=r.evidence,
                )
            )

        for ep in api_out.endpoints:
            db.add(
                ApiEndpoint(
                    scan_id=scan_id,
                    url=ep.url,
                    path_template=ep.path_template,
                    methods=ep.methods,
                    category=ep.category,
                    sources=ep.sources,
                    status_code=ep.status_code,
                    auth_observation=ep.auth_observation,
                    content_type=ep.content_type,
                    cors=ep.cors,
                    tested=ep.tested,
                    test_note=ep.test_note,
                    evidence=ep.evidence,
                )
            )

        for f in final_findings:
            db.add(Finding(scan_id=scan_id, **f))

        await db.commit()

        ai_cfg = await get_effective_ai_config(db)
        should_analyze = bool(options.get("ai_analysis")) or ai_cfg["auto_analyze"]

    if should_analyze:
        await run_and_persist_ai_analysis(scan_id)

    await set_phase("completed", 100, f"Scan completed with {len(final_findings)} findings")
    async with session_factory() as db:
        scan = await db.get(Scan, scan_id)
        if scan:
            scan.status = ScanStatus.completed.value
            scan.progress = 100
            scan.finished_at = utcnow()
            await db.commit()


async def run_and_persist_ai_analysis(
    scan_id: uuid.UUID,
    *,
    analysis_id: uuid.UUID | None = None,
    http_transport: httpx.AsyncBaseTransport | None = None,
) -> AIAnalysis:
    session_factory = get_sessionmaker()
    async with session_factory() as db:
        scan = await db.get(Scan, scan_id)
        if scan is None:
            raise ValueError("Scan not found")
        target = await db.get(Target, scan.target_id)
        assert target is not None
        ai_cfg = await get_effective_ai_config(db)

        if analysis_id is not None:
            record = await db.get(AIAnalysis, analysis_id)
            assert record is not None
        else:
            record = AIAnalysis(
                scan_id=scan_id,
                provider=ai_cfg["provider"],
                model=ai_cfg["model"],
                status="pending",
            )
            db.add(record)
            await db.commit()
            await db.refresh(record)

        tech_rows = (await db.execute(select(Technology).where(Technology.scan_id == scan_id))).scalars().all()
        route_rows = (await db.execute(select(Route).where(Route.scan_id == scan_id))).scalars().all()
        ep_rows = (await db.execute(select(ApiEndpoint).where(ApiEndpoint.scan_id == scan_id))).scalars().all()
        finding_rows = (await db.execute(select(Finding).where(Finding.scan_id == scan_id))).scalars().all()

        techs = [{"name": t.name, "kind": t.kind, "confidence": t.confidence} for t in tech_rows]
        routes = [{"path": r.path, "is_admin_surface": r.is_admin_surface, "admin_category": r.admin_category} for r in route_rows]
        eps = [{"path_template": e.path_template, "category": e.category} for e in ep_rows]
        findings = [
            {
                "finding_key": f.finding_key,
                "rule_id": f.rule_id,
                "title": f.title,
                "category": f.category,
                "severity": f.severity,
                "status": f.status,
                "confidence": f.confidence,
                "affected": f.affected,
                "cvss_score": f.cvss_score,
                "evidence": f.evidence,
                "impact": f.impact,
                "remediation": f.remediation,
            }
            for f in finding_rows
        ]

    provider_used, model_used, output, grounding = await run_ai_security_analysis(
        target_name=target.name,
        target_url=target.base_url,
        technologies=techs,
        routes=routes,
        endpoints=eps,
        findings=findings,
        provider=ai_cfg["provider"],
        model=ai_cfg["model"],
        base_url=ai_cfg["base_url"],
        api_key=ai_cfg["api_key"],
        http_transport=http_transport,
    )

    async with session_factory() as db:
        rec = await db.get(AIAnalysis, record.id)
        assert rec is not None
        rec.provider = provider_used
        rec.model = model_used
        rec.status = "completed"
        rec.output = output
        rec.grounding = grounding
        await db.commit()
        await db.refresh(rec)
        return rec
