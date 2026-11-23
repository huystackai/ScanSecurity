"""Unit and integration tests for Phase 2: baseline, crawler, JS analysis, fingerprinting, and admin surface discovery."""

from __future__ import annotations

import httpx

from app.scanner.admin_surface import categorize_route_path, discover_routes_and_admin_surfaces
from app.scanner.baseline import build_baseline
from app.scanner.crawler import run_crawler
from app.scanner.fingerprint import fingerprint_application
from app.scanner.http import SafeHttpClient
from app.scanner.scope import ScopeConfig, ScopePolicy

SPA_SHELL_HTML = """<!doctype html>
<html>
  <head>
    <title>Lovable VibeApp</title>
    <meta name="author" content="Lovable" />
    <script type="module" src="/assets/index-a1b2c3d4.js"></script>
    <link rel="stylesheet" href="/assets/index-a1b2c3d4.css" />
  </head>
  <body>
    <div id="root" data-lov-id="src/App.tsx:1:0"></div>
    <script src="https://cdn.gpteng.co/gptengineer.js"></script>
  </body>
</html>
"""

SPA_BUNDLE_JS = """
import { createRoot } from 'react-dom/client';
import { createBrowserRouter } from 'react-router-dom';
import { createClient } from '@supabase/supabase-js';

const supabase = createClient("https://abcdefghijklmno12345.supabase.co", "sb_publishable_1234567890abcdefghijkl");
const router = createBrowserRouter([
  { path: "/login", element: null },
  { path: "/dashboard", element: null },
  { path: "/admin/users", element: null },
  { path: "/admin/settings", element: null },
  { path: "/workflows", element: null },
]);
async function loadUsers() {
  const isAdmin = localStorage.getItem("isAdmin");
  if (user?.role === "admin") {
    await fetch("/api/admin/users");
    await supabase.from("profiles").select("*");
  }
}
//# sourceMappingURL=index-a1b2c3d4.js.map
"""

EXPOSED_ADMIN_HTML = """<!doctype html>
<html>
  <head><title>Admin Dashboard - Control Panel</title></head>
  <body>
    <h1>Admin Dashboard</h1>
    <section>User Management — 128 active accounts</section>
    <section>Role Management &amp; Permissions Matrix</section>
    <section>System Settings &amp; Feature Flags</section>
  </body>
</html>
"""

LOGIN_HTML = """<!doctype html>
<html>
  <head><title>Sign In - VibeApp</title></head>
  <body>
    <form action="/auth/login" method="post">
      <input type="email" name="email" />
      <input type="password" name="password" />
      <button type="submit">Sign In</button>
    </form>
  </body>
</html>
"""


class TestPhase2CrawlerFingerprintAndAdminSurface:
    async def test_spa_baseline_prevents_false_positive_on_catchall_routes(self) -> None:
        """A Vite/React SPA that returns the generic index.html shell for every path must NOT
        have probed admin paths classified as exposed public content."""

        def handler(req: httpx.Request) -> httpx.Response:
            p = req.url.path
            if p == "/robots.txt":
                return httpx.Response(200, text="User-agent: *\nDisallow: /internal-ops\n", headers={"Content-Type": "text/plain"})
            if p == "/assets/index-a1b2c3d4.js":
                return httpx.Response(200, text=SPA_BUNDLE_JS, headers={"Content-Type": "application/javascript"})
            if p == "/assets/index-a1b2c3d4.css":
                return httpx.Response(200, text="body { margin: 0; }", headers={"Content-Type": "text/css"})
            if p == "/login":
                return httpx.Response(200, text=LOGIN_HTML, headers={"Content-Type": "text/html"})
            if p == "/admin/settings":
                return httpx.Response(302, headers={"Location": "/login"})
            if p == "/superadmin":
                return httpx.Response(403, text="Forbidden", headers={"Content-Type": "text/plain"})
            if p == "/admin/database":
                # Server-rendered exposed admin page distinct from the SPA shell!
                return httpx.Response(200, text=EXPOSED_ADMIN_HTML, headers={"Content-Type": "text/html"})
            # Everything else returns the generic SPA shell (HTTP 200)
            return httpx.Response(200, text=SPA_SHELL_HTML, headers={"Content-Type": "text/html"})

        scope = ScopePolicy(
            "https://vibe.example.com",
            config=ScopeConfig(requests_per_second=20.0, concurrency=4, respect_robots=True),
        )
        transport = httpx.MockTransport(handler)
        async with SafeHttpClient(scope, transport=transport) as client:
            crawl = await run_crawler(client, scope)
            root_resp = crawl.page_responses.get("https://vibe.example.com/")
            baseline = await build_baseline(client, scope.base_url, root_resp)
            assert baseline.is_spa_catchall is True

            routes = await discover_routes_and_admin_surfaces(client, scope, crawl, baseline)
            by_path = {r.path: r for r in routes}

            # 1. /admin/users was in the JS bundle, and returns the generic SPA shell -> public_shell (low risk), NOT high-risk public_content
            assert "/admin/users" in by_path
            assert by_path["/admin/users"].auth_observation == "public_shell"
            assert by_path["/admin/users"].admin_category == "user_management"
            assert by_path["/admin/users"].risk_level == "low"

            # 2. /control-panel was only a path probe and matched the SPA shell -> dropped as soft-404
            assert "/control-panel" not in by_path

            # 3. /admin/settings redirected to /login -> redirect_to_login
            assert by_path["/admin/settings"].auth_observation == "redirect_to_login"
            assert by_path["/admin/settings"].risk_level == "info"

            # 4. /superadmin returned 403 -> forbidden
            assert by_path["/superadmin"].auth_observation == "forbidden"

            # 5. /admin/database returned real distinct admin HTML -> public_content with high risk
            assert by_path["/admin/database"].auth_observation == "public_content"
            assert by_path["/admin/database"].risk_level == "high"
            assert by_path["/admin/database"].admin_category == "backend_management"

            # 6. /internal-ops was Disallowed in robots.txt and respect_robots=True -> recorded as not_tested
            assert "/internal-ops" in by_path
            assert by_path["/internal-ops"].auth_observation == "not_tested"

            # Fingerprinting checks: React, Vite, Supabase, and Lovable (multiple signals)
            techs = fingerprint_application(
                list(crawl.page_responses.values()),
                list(crawl.parsed_pages.values()),
                [(a.url, a.response.text) for a in crawl.assets.values() if a.kind == "js"],
                crawl.js_results,
            )
            tech_map = {t.name: t for t in techs}
            assert "React" in tech_map
            assert "Vite" in tech_map
            assert "Supabase" in tech_map
            assert "Lovable" in tech_map
            assert tech_map["Lovable"].confidence >= 0.7
            assert len(tech_map["Lovable"].signals) >= 2

    def test_single_weak_platform_signal_is_not_reported(self) -> None:
        """Rule: Do not claim that a platform generated an application based on a single ambiguous indicator."""
        from app.scanner.html_parse import parse_html_page
        from app.scanner.http import SafeResponse

        scope = ScopePolicy("https://plain.example.com")
        html = '<html><head><title>Blog</title></head><body><img src="/placeholder.svg?height=100&width=100"></body></html>'
        resp = SafeResponse(
            url="https://plain.example.com/",
            final_url="https://plain.example.com/",
            status_code=200,
            headers={"content-type": "text/html"},
            body=html.encode(),
            content_type="text/html",
        )
        page = parse_html_page(html, "https://plain.example.com/", scope)
        techs = fingerprint_application([resp], [page], [], [])
        names = {t.name for t in techs}
        assert "v0" not in names

    def test_route_categorization_covers_all_six_module_b_categories(self) -> None:
        assert categorize_route_path("/login") == ("authentication", True)
        assert categorize_route_path("/admin/dashboard") == ("admin_interface", True)
        assert categorize_route_path("/admin/users") == ("user_management", True)
        assert categorize_route_path("/admin/feature-flags") == ("system_configuration", True)
        assert categorize_route_path("/admin/workflows") == ("workflow_management", True)
        assert categorize_route_path("/admin/database") == ("backend_management", True)
        assert categorize_route_path("/about") == ("none", False)
