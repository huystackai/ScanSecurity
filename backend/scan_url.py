#!/usr/bin/env python3
"""Quick CLI scanner for VibeScan: pass a target URL and run a full non-destructive scan directly.

Usage:
    cd backend
    .venv/bin/python scan_url.py https://your-app.com
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from sqlalchemy import select

from app.config import get_settings
from app.core.security import hash_password, new_verification_token
from app.db.base import utcnow
from app.db.models import (
    ApiEndpoint,
    AuthorizationStatus,
    Finding,
    Operator,
    OperatorRole,
    Route,
    Scan,
    ScanStatus,
    Target,
    Technology,
    VerificationMethod,
)
from app.db.session import configure_engine, dispose_engine, get_sessionmaker, init_db
from app.reports.generator import build_report_payload, generate_report_bytes
from app.scanner.engine import execute_scan
from app.scanner.scope import ScopePolicy


async def run_cli_scan(raw_url: str, max_pages: int, allow_private: bool) -> int:
    import os

    if allow_private:
        os.environ["VIBESCAN_LAB_MODE"] = "true"
        os.environ["VIBESCAN_ALLOW_PRIVATE_TARGETS"] = "true"
        os.environ.setdefault("VIBESCAN_PRIVATE_TARGET_ALLOWLIST", "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,::1/128")
        get_settings.cache_clear()

    settings = get_settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.reports_dir.mkdir(parents=True, exist_ok=True)
    configure_engine(settings)
    await init_db()

    url = raw_url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    scope = ScopePolicy(url)
    print(f"[*] Target URL     : {scope.base_url}")
    print(f"[*] Allowed Hosts  : {', '.join(sorted(scope.allowed_hosts))}")

    try:
        async with get_sessionmaker()() as db:
            op = (await db.execute(select(Operator).limit(1))).scalar_one_or_none()
            if op is None:
                op = Operator(
                    email="admin@vibescan.local",
                    display_name="CLI Operator",
                    password_hash=hash_password("VibeScan-Dev-Admin!2026"),
                    role=OperatorRole.admin.value,
                    is_active=True,
                )
                db.add(op)
                await db.flush()

            target = (
                await db.execute(
                    select(Target).where(Target.base_url == scope.base_url, Target.archived.is_(False)).limit(1)
                )
            ).scalar_one_or_none()
            now = utcnow()
            if target is None:
                target = Target(
                    name=scope.primary_host,
                    base_url=scope.base_url,
                    primary_host=scope.primary_host,
                    allowed_hosts=sorted(scope.allowed_hosts),
                    scope_config=scope.config.to_dict(),
                    authorization_status=AuthorizationStatus.verified.value,
                    verification_method=VerificationMethod.attestation.value,
                    verified_at=now,
                    verification_token=new_verification_token(),
                    owner_operator_id=op.id,
                )
                db.add(target)
                await db.flush()
            else:
                target.authorization_status = AuthorizationStatus.verified.value
                target.verified_at = now

            scan = Scan(
                target_id=target.id,
                operator_id=op.id,
                status=ScanStatus.queued.value,
                options={
                    "crawl": True,
                    "path_probing": True,
                    "access_control": True,
                    "config_exposure": True,
                    "api_discovery": True,
                    "source_analysis": True,
                    "ai_analysis": True,
                    "max_pages": max_pages,
                    "timeout_seconds": 600,
                },
                authorization={"confirmed": True, "statement": "Direct CLI scan"},
            )
            db.add(scan)
            await db.commit()
            scan_id = scan.id

        print(f"[*] Starting scan {scan_id} ...")
        await execute_scan(scan_id)

        async with get_sessionmaker()() as db:
            sc = await db.get(Scan, scan_id)
            assert sc is not None
            tgt = await db.get(Target, sc.target_id)
            assert tgt is not None
            techs = (await db.execute(select(Technology).where(Technology.scan_id == scan_id))).scalars().all()
            routes = (await db.execute(select(Route).where(Route.scan_id == scan_id))).scalars().all()
            eps = (await db.execute(select(ApiEndpoint).where(ApiEndpoint.scan_id == scan_id))).scalars().all()
            findings = (await db.execute(select(Finding).where(Finding.scan_id == scan_id))).scalars().all()

            print(f"\n=== SCAN RESULT ({sc.status.upper()}) ===")
            if sc.error:
                print(f"[!] Error: {sc.error}")
            print(f"Technologies : {', '.join(f'{t.name} ({int(t.confidence * 100)}%)' for t in techs) or 'none'}")
            print(f"Routes       : {len(routes)} total ({sum(1 for r in routes if r.is_admin_surface)} admin/management surfaces)")
            print(f"API Endpoints: {len(eps)}")
            print(f"Findings     : {len(findings)}")
            for f in findings:
                print(f"  - [{f.severity.upper():8s} | {f.status:13s}] {f.finding_key} ({f.rule_id}): {f.title} -> {f.affected}")

            payload = build_report_payload(
                target={
                    "id": str(tgt.id),
                    "name": tgt.name,
                    "base_url": tgt.base_url,
                    "primary_host": tgt.primary_host,
                    "allowed_hosts": tgt.allowed_hosts,
                    "authorization_status": tgt.authorization_status,
                },
                scan={"id": str(sc.id), "status": sc.status, "stats": sc.stats, "created_at": str(sc.created_at), "finished_at": str(sc.finished_at)},
                technologies=[{"name": t.name, "kind": t.kind, "confidence": t.confidence, "evidence": t.evidence} for t in techs],
                routes=[
                    {
                        "url": r.url,
                        "path": r.path,
                        "status_code": r.status_code,
                        "auth_observation": r.auth_observation,
                        "admin_category": r.admin_category,
                        "is_admin_surface": r.is_admin_surface,
                        "risk_level": r.risk_level,
                        "discovery_methods": r.discovery_methods,
                        "evidence": r.evidence,
                    }
                    for r in routes
                ],
                endpoints=[
                    {
                        "url": e.url,
                        "path_template": e.path_template,
                        "methods": e.methods,
                        "category": e.category,
                        "status_code": e.status_code,
                        "auth_observation": e.auth_observation,
                    }
                    for e in eps
                ],
                findings=[
                    {
                        "finding_key": f.finding_key,
                        "rule_id": f.rule_id,
                        "title": f.title,
                        "category": f.category,
                        "severity": f.severity,
                        "status": f.status,
                        "confidence": f.confidence,
                        "affected": f.affected,
                        "evidence": f.evidence,
                        "detection_method": f.detection_method,
                        "impact": f.impact,
                        "reproduction": f.reproduction,
                        "remediation": f.remediation,
                        "references": f.references,
                        "cvss_score": f.cvss_score,
                        "verification_status": f.verification_status,
                    }
                    for f in findings
                ],
                analysis=None,
            )
            html_bytes, _ = generate_report_bytes("html", payload)
            out_file = Path(settings.reports_dir) / f"cli-report-{scan_id}.html"
            out_file.write_bytes(html_bytes)
            print(f"\n[+] HTML Report saved to: {out_file.resolve()}")
        return 0
    finally:
        await dispose_engine()


def main() -> int:
    parser = argparse.ArgumentParser(description="VibeScan direct URL scanner")
    parser.add_argument("url", help="Target URL to scan (e.g. https://example.com)")
    parser.add_argument("--max-pages", type=int, default=40, help="Maximum pages to crawl (default: 40)")
    parser.add_argument("--allow-private", action="store_true", help="Allow scanning localhost/private lab URLs")
    args = parser.parse_args()
    return asyncio.run(run_cli_scan(args.url, args.max_pages, args.allow_private))


if __name__ == "__main__":
    sys.exit(main())
