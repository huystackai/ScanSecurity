"""Phase 7 Integration & Lab Validation Tests:

1. End-to-end live local HTTP server testing against two realistic full-stack applications:
   - App A ("VibeShop Vulnerable Lab" — modeled on OWASP Juice Shop / vulnerable Lovable+Supabase
     vibe-coded patterns): exposed ``/administration`` panel, ``/ftp``/``.env`` config leak,
     OpenAPI spec, unauthenticated ``/api/Users`` user dump, credentialed CORS reflection,
     client-side-only ``localStorage.getItem('isAdmin')`` check, broken function-level authorization
     on ``/api/admin/feature-flags``, and horizontal IDOR on ``/api/BasketItems/basket-user-a``.
   - App B ("VibeShop Hardened"): SPA that serves ``index.html`` catch-all for ``/admin``, ``/settings``,
     ``/dashboard``, ``/management``, returns 401/403 on all ``/api/admin/*`` routes, has strict
     security headers, only embeds a public Supabase anon key (no secrets), and blocks dotfiles.
2. Validates false-positive suppression: App B must produce ZERO confirmed or potential high/critical
   vulnerabilities despite having ``/admin``, ``/dashboard``, ``/settings``, and ``/management`` routes.
3. Validates live TCP-level SSRF protection and DNS-pinning via ``SafeNetworkBackend`` against an
   ephemeral local asyncio server.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json

import pytest
from sqlalchemy import select

from app.config import get_settings
from app.db.models import AuthorizationStatus, Finding, Operator, Scan, ScanStatus, Target
from app.db.session import configure_engine, dispose_engine, get_sessionmaker, init_db
from app.scanner.engine import execute_scan
from app.scanner.http import BlockedDestinationError, SafeHttpClient
from app.scanner.netguard import NetGuard, NetworkPolicy
from app.scanner.scope import ScopeConfig, ScopePolicy


async def _start_asgi_server(app_fn) -> tuple[asyncio.AbstractServer, int]:  # type: ignore[no-untyped-def]
    """Minimal asyncio HTTP/1.1 server so live socket/TCP tests run without third-party servers."""

    async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            raw_head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5.0)
        except Exception:
            writer.close()
            return
        lines = raw_head.decode("latin-1").split("\r\n")
        req_line = lines[0].split(" ")
        method = req_line[0] if req_line else "GET"
        target = req_line[1] if len(req_line) > 1 else "/"
        path = target.split("?", 1)[0]
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        status, resp_headers, body = app_fn(method, path, headers)
        body_bytes = body.encode("utf-8") if isinstance(body, str) else body
        resp_headers = {"Content-Length": str(len(body_bytes)), "Connection": "close", **resp_headers}
        head_str = f"HTTP/1.1 {status} OK\r\n" + "".join(f"{k}: {v}\r\n" for k, v in resp_headers.items()) + "\r\n"
        writer.write(head_str.encode("latin-1") + (b"" if method == "HEAD" else body_bytes))
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


def _vulnerable_juice_vibe_app(method: str, path: str, headers: dict[str, str]) -> tuple[int, dict[str, str], str]:
    auth = headers.get("authorization", "")
    origin = headers.get("origin", "")
    if path == "/":
        return (
            200,
            {"Content-Type": "text/html"},
            """<!doctype html><html><head><title>OWASP Juice-Vibe Shop</title>
            <meta name="author" content="Lovable" />
            <script src="/assets/index-9f8e7d6c.js"></script></head>
            <body><div id="root" data-lov-id="App.tsx:1"></div>
            <a href="/administration">Administration</a>
            <a href="/score-board">Score Board</a>
            <script src="https://cdn.gpteng.co/gptengineer.js"></script></body></html>""",
        )
    if path == "/assets/index-9f8e7d6c.js":
        return (
            200,
            {"Content-Type": "application/javascript"},
            """
            import { createRoot } from 'react-dom/client';
            import { createBrowserRouter } from 'react-router-dom';
            const router = createBrowserRouter([
              { path: "/administration", element: null },
              { path: "/score-board", element: null },
              { path: "/admin/users", element: null },
            ]);
            async function loadAdmin() {
              if (localStorage.getItem("isAdmin") === "true") {
                await fetch("/api/Users");
                await fetch("/api/admin/feature-flags");
              }
            }
            """,
        )
    if path in ("/administration", "/admin"):
        return (
            200,
            {"Content-Type": "text/html"},
            """<!doctype html><html><head><title>Admin Dashboard - Juice-Vibe</title></head>
            <body><h1>Admin Dashboard</h1><div>User Management &amp; Role Management</div>
            <div>System Settings &amp; Audit Logs</div></body></html>""",
        )
    if path == "/.env":
        return (
            200,
            {"Content-Type": "text/plain"},
            "JWT_SECRET=super_secret_juice_jwt_signing_key_998877\nDATABASE_URL=postgresql://juice:juicesecret123@db.internal:5432/juiceshop\n",
        )
    if path == "/api/Users":
        resp_hdrs = {"Content-Type": "application/json"}
        if origin:
            resp_hdrs["Access-Control-Allow-Origin"] = origin
            resp_hdrs["Access-Control-Allow-Credentials"] = "true"
        return (
            200,
            resp_hdrs,
            json.dumps(
                [
                    {"id": 1, "email": "admin@juice-sh.op", "role": "admin", "password_hash": "$2b$10$abcdef1234567890"},
                    {"id": 2, "email": "bjoern@juice-sh.op", "role": "customer"},
                ]
            ),
        )
    if path == "/api/admin/feature-flags":
        if not auth:
            return (401, {"Content-Type": "application/json"}, '{"error":"Unauthorized"}')
        return (200, {"Content-Type": "application/json"}, '{"flags":{"challengeScoreBoard":true}}')
    if path == "/api/BasketItems/basket-user-a":
        if not auth:
            return (401, {"Content-Type": "application/json"}, '{"error":"Unauthorized"}')
        return (200, {"Content-Type": "application/json"}, '{"basketId":"basket-user-a","owner":"user_a","items":["Apple Juice"]}')
    return (404, {"Content-Type": "text/plain"}, "Not Found")


HARDENED_SPA_SHELL = """<!doctype html>
<html>
  <head><title>Hardened Enterprise App</title><script src="/assets/index-hardened12.js"></script></head>
  <body><div id="root">Loading application...</div></body>
</html>"""

HARDENED_SECURITY_HEADERS = {
    "Content-Type": "text/html",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "Referrer-Policy": "strict-origin-when-cross-origin",
}


def _hardened_spa_app(method: str, path: str, headers: dict[str, str]) -> tuple[int, dict[str, str], str]:
    if path == "/robots.txt":
        return (200, {"Content-Type": "text/plain"}, "User-agent: *\nAllow: /\n")
    if path == "/assets/index-hardened12.js":
        return (
            200,
            {**HARDENED_SECURITY_HEADERS, "Content-Type": "application/javascript"},
            """
            import { createRoot } from 'react-dom/client';
            import { createBrowserRouter } from 'react-router-dom';
            const pubKey = "pk_live_51HardenedPublishableKey1234567890";
            const router = createBrowserRouter([
              { path: "/admin", element: null },
              { path: "/dashboard", element: null },
              { path: "/settings", element: null },
              { path: "/management", element: null },
            ]);
            async function load() {
              await fetch("/api/admin/users");
              await fetch("/api/admin/settings");
            }
            """,
        )
    if path.startswith("/api/"):
        return (401, {"Content-Type": "application/json"}, '{"detail":"Authentication required"}')
    if path.startswith("/.") or path.endswith(".map") or path in ("/firebase.json", "/firestore.rules", "/debug"):
        return (404, {"Content-Type": "text/plain"}, "Not Found")
    # Every frontend route (/admin, /dashboard, /settings, /management, and random baseline probes)
    # returns the exact same SPA catch-all HTML shell with full security headers.
    return (200, HARDENED_SECURITY_HEADERS, HARDENED_SPA_SHELL)


class TestPhase7LiveLabAndFalsePositiveValidation:
    async def test_live_tcp_ssrf_blocks_127_0_0_1_by_default_and_allows_explicit_lab_cidr(self) -> None:
        server, port = await _start_asgi_server(_vulnerable_juice_vibe_app)
        try:
            url = f"http://127.0.0.1:{port}/"
            scope = ScopePolicy(url, config=ScopeConfig(requests_per_second=20.0))

            # 1. Default production NetGuard MUST block 127.0.0.1 before opening a socket
            strict_guard = NetGuard(NetworkPolicy(allow_private=False))
            async with SafeHttpClient(scope, strict_guard) as strict_client:
                with pytest.raises(BlockedDestinationError):
                    await strict_client.get(url)

            # 2. Lab NetGuard with explicit 127.0.0.1/32 allowlist connects via SafeNetworkBackend
            lab_guard = NetGuard(
                NetworkPolicy(allow_private=True, private_allowlist=[ipaddress.ip_network("127.0.0.1/32")])
            )
            async with SafeHttpClient(scope, lab_guard) as lab_client:
                resp = await lab_client.get(url)
                assert resp.status_code == 200
                assert "OWASP Juice-Vibe Shop" in resp.text
        finally:
            server.close()
            await server.wait_closed()

    async def test_live_scan_against_vulnerable_juice_vibe_lab(self, monkeypatch) -> None:
        server, port = await _start_asgi_server(_vulnerable_juice_vibe_app)
        try:
            monkeypatch.setenv("VIBESCAN_LAB_MODE", "true")
            monkeypatch.setenv("VIBESCAN_ALLOW_ATTESTATION_ONLY", "true")
            monkeypatch.setenv("VIBESCAN_ALLOW_PRIVATE_TARGETS", "true")
            monkeypatch.setenv("VIBESCAN_PRIVATE_TARGET_ALLOWLIST", "127.0.0.1/32")
            get_settings.cache_clear()
            configure_engine(get_settings())
            await init_db()

            from app.core.crypto import encrypt_secret
            from app.core.security import hash_password, new_verification_token
            from app.db.models import TargetCredential

            base_url = f"http://127.0.0.1:{port}"
            async with get_sessionmaker()() as db:
                op = Operator(
                    email="researcher@vibescan.org",
                    display_name="Researcher",
                    password_hash=hash_password("ResearcherPass!2026"),
                    role="admin",
                )
                db.add(op)
                await db.flush()
                tgt = Target(
                    name="Local Juice-Vibe Lab",
                    base_url=base_url,
                    primary_host="127.0.0.1",
                    allowed_hosts=["127.0.0.1"],
                    scope_config=ScopeConfig(requests_per_second=20.0, concurrency=4, max_pages=30).to_dict(),
                    access_tests=[
                        {
                            "url": f"{base_url}/api/BasketItems/basket-user-a",
                            "owner_role": "user_a",
                            "description": "Basket owned by customer A",
                        }
                    ],
                    authorization_status=AuthorizationStatus.attested.value,
                    verification_method="attestation",
                    verification_token=new_verification_token(),
                    owner_operator_id=op.id,
                )
                db.add(tgt)
                await db.flush()
                db.add_all(
                    [
                        TargetCredential(
                            target_id=tgt.id,
                            role_name="user_a",
                            auth_type="bearer",
                            encrypted_value=encrypt_secret("customer-a-token"),
                        ),
                        TargetCredential(
                            target_id=tgt.id,
                            role_name="user_b",
                            auth_type="bearer",
                            encrypted_value=encrypt_secret("customer-b-token"),
                        ),
                    ]
                )
                sc = Scan(
                    target_id=tgt.id,
                    operator_id=op.id,
                    status=ScanStatus.queued.value,
                    options={"crawl": True, "path_probing": True, "access_control": True, "config_exposure": True, "api_discovery": True, "ai_analysis": True},
                    authorization={"confirmed": True, "statement": "Isolated local lab"},
                )
                db.add(sc)
                await db.commit()
                scan_id = sc.id

            await execute_scan(scan_id)

            async with get_sessionmaker()() as db:
                sc_done = await db.get(Scan, scan_id)
                assert sc_done is not None and sc_done.status == ScanStatus.completed.value
                findings = (await db.execute(select(Finding).where(Finding.scan_id == scan_id))).scalars().all()
                rule_ids = {f.rule_id for f in findings}
                assert "AC-UNAUTH-ADMIN-PAGE" in rule_ids
                assert "AC-UNAUTH-ADMIN-API" in rule_ids
                assert "API-SENSITIVE-FIELDS-EXPOSED" in rule_ids
                assert "API-CORS-CREDENTIALED-REFLECTION" in rule_ids
                assert "AC-CLIENT-GUARD-UNPROTECTED-API" in rule_ids
                assert "AC-ROLE-BYPASS-ADMIN" in rule_ids
                assert "AC-IDOR-CROSS-TENANT" in rule_ids
                assert "CFG-DOTENV-EXPOSED" in rule_ids
        finally:
            server.close()
            await server.wait_closed()
            await dispose_engine()

    async def test_hardened_spa_produces_zero_false_positive_vulnerabilities(self, monkeypatch) -> None:
        """Rule: Never classify a route as vulnerable merely because it contains words such as
        admin, dashboard, settings, or management."""
        server, port = await _start_asgi_server(_hardened_spa_app)
        try:
            monkeypatch.setenv("VIBESCAN_LAB_MODE", "true")
            monkeypatch.setenv("VIBESCAN_ALLOW_ATTESTATION_ONLY", "true")
            monkeypatch.setenv("VIBESCAN_ALLOW_PRIVATE_TARGETS", "true")
            monkeypatch.setenv("VIBESCAN_PRIVATE_TARGET_ALLOWLIST", "127.0.0.1/32")
            get_settings.cache_clear()
            configure_engine(get_settings())
            await init_db()

            from app.core.security import hash_password, new_verification_token

            base_url = f"http://127.0.0.1:{port}"
            async with get_sessionmaker()() as db:
                op = Operator(
                    email="auditor@vibescan.org",
                    display_name="Auditor",
                    password_hash=hash_password("AuditorPass!2026"),
                    role="admin",
                )
                db.add(op)
                await db.flush()
                tgt = Target(
                    name="Hardened SPA",
                    base_url=base_url,
                    primary_host="127.0.0.1",
                    allowed_hosts=["127.0.0.1"],
                    scope_config=ScopeConfig(requests_per_second=20.0, concurrency=4, max_pages=30).to_dict(),
                    authorization_status=AuthorizationStatus.attested.value,
                    verification_method="attestation",
                    verification_token=new_verification_token(),
                    owner_operator_id=op.id,
                )
                db.add(tgt)
                await db.flush()
                sc = Scan(
                    target_id=tgt.id,
                    operator_id=op.id,
                    status=ScanStatus.queued.value,
                    options={"crawl": True, "path_probing": True, "access_control": True, "config_exposure": True, "api_discovery": True},
                    authorization={"confirmed": True, "statement": "Hardened baseline check"},
                )
                db.add(sc)
                await db.commit()
                scan_id = sc.id

            await execute_scan(scan_id)

            async with get_sessionmaker()() as db:
                findings = (await db.execute(select(Finding).where(Finding.scan_id == scan_id))).scalars().all()
                # Every finding on the hardened SPA must be purely informational (e.g. client-routed SPA shell note or Stripe publishable key)
                non_info = [f for f in findings if f.status in ("confirmed", "potential")]
                assert non_info == [], f"Unexpected false-positive findings on hardened SPA: {[f.rule_id for f in non_info]}"
        finally:
            server.close()
            await server.wait_closed()
            await dispose_engine()
