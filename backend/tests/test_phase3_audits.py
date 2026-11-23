"""Tests for Phase 3: Configuration Exposure, API Security Discovery, and Access Control Audit."""

from __future__ import annotations

import json

import httpx

from app.scanner.access_control import SuppliedCredential, run_access_control_audit
from app.scanner.admin_surface import discover_routes_and_admin_surfaces
from app.scanner.api_discovery import run_api_discovery
from app.scanner.baseline import build_baseline
from app.scanner.config_exposure import run_config_exposure_audit
from app.scanner.crawler import run_crawler
from app.scanner.findings import deduplicate_findings
from app.scanner.http import SafeHttpClient
from app.scanner.scope import ScopeConfig, ScopePolicy

VULN_BUNDLE_JS = """
const supabase = createClient("https://xyzproject12345678.supabase.co", "sb_publishable_1234567890abcdefghijkl");
const router = createBrowserRouter([
  { path: "/admin/users", element: null },
]);
async function boot() {
  if (localStorage.getItem("role") === "admin") {
    await fetch("/api/admin/users");
    await axios.post("/api/admin/webhooks", {});
    await axios.delete("/api/admin/users/delete", {});
    await supabase.from("orders").select("*");
  }
}
//# sourceMappingURL=app.js.map
"""

SOURCE_MAP_JSON = json.dumps(
    {
        "version": 3,
        "file": "app.js",
        "sources": ["src/Admin.tsx"],
        "sourcesContent": [
            'export function Admin() { const key = "sk" + "_live_99887766554433221100aabbccdd"; return <div>Admin</div>; }'
        ],
    }
)


class TestPhase3ModulesCDE:
    async def test_vulnerable_vibe_app_triggers_config_api_and_access_control_findings(self) -> None:
        raw_stripe = "sk" + "_live_11223344556677889900aabbccddeeff"

        def handler(req: httpx.Request) -> httpx.Response:
            p = req.url.path
            auth = req.headers.get("authorization", "")
            origin = req.headers.get("origin", "")

            if p == "/":
                return httpx.Response(
                    200,
                    text='<!doctype html><html><head><title>App</title><script src="/assets/app.js"></script></head><body><div id="root"></div></body></html>',
                    headers={"Content-Type": "text/html"},
                )
            if p == "/assets/app.js":
                return httpx.Response(200, text=VULN_BUNDLE_JS, headers={"Content-Type": "application/javascript"})
            if p == "/assets/app.js.map":
                return httpx.Response(200, text=SOURCE_MAP_JSON, headers={"Content-Type": "application/json"})
            if p == "/.env":
                return httpx.Response(
                    200,
                    text=f"STRIPE_SECRET_KEY={raw_stripe}\nDATABASE_URL=postgresql://admin:supersecret99@db.example.com:5432/prod\n",
                    headers={"Content-Type": "text/plain"},
                )
            if p == "/.git/HEAD":
                return httpx.Response(200, text="ref: refs/heads/main\n", headers={"Content-Type": "text/plain"})
            if p == "/openapi.json":
                spec = {
                    "openapi": "3.1.0",
                    "info": {"title": "VibeAPI", "version": "1.0"},
                    "paths": {
                        "/api/admin/users": {"get": {}},
                        "/api/admin/config": {"get": {}},
                    },
                }
                return httpx.Response(200, text=json.dumps(spec), headers={"Content-Type": "application/json"})
            if p == "/api/admin/users":
                # Vulnerable: returns all users + PII without auth AND reflects Origin with credentials!
                headers = {"Content-Type": "application/json"}
                if origin:
                    headers["Access-Control-Allow-Origin"] = origin
                    headers["Access-Control-Allow-Credentials"] = "true"
                return httpx.Response(
                    200,
                    text=json.dumps([{"id": 1, "email": "ceo@example.com", "role": "admin"}]),
                    headers=headers,
                )
            if p == "/api/admin/config":
                # Protected against anonymous (401), but broken function-level auth: allows any logged-in user!
                if not auth:
                    return httpx.Response(401, text='{"detail":"Unauthorized"}', headers={"Content-Type": "application/json"})
                return httpx.Response(
                    200,
                    text='{"feature_flags":{"beta":true},"internal_mode":"enabled"}',
                    headers={"Content-Type": "application/json"},
                )
            if p == "/api/orders/order-user-a":
                # IDOR: returns User A's order to ANY authenticated user!
                if not auth:
                    return httpx.Response(401, text='{"detail":"Unauthorized"}', headers={"Content-Type": "application/json"})
                return httpx.Response(
                    200,
                    text='{"order_id":"order-user-a","owner":"user_a","total":499}',
                    headers={"Content-Type": "application/json"},
                )
            if p == "/rest/v1/orders" and req.method == "HEAD":
                return httpx.Response(200, headers={"Content-Range": "0-0/17", "Content-Type": "application/json"})
            return httpx.Response(404, text="Not Found", headers={"Content-Type": "text/plain"})

        scope = ScopePolicy("https://vuln.example.com", config=ScopeConfig(requests_per_second=20.0))
        transport = httpx.MockTransport(handler)
        async with SafeHttpClient(scope, transport=transport) as client:
            crawl = await run_crawler(client, scope)
            baseline = await build_baseline(client, scope.base_url, crawl.page_responses.get("https://vuln.example.com/"))
            routes = await discover_routes_and_admin_surfaces(client, scope, crawl, baseline, enable_path_probing=False)

            cfg_out = await run_config_exposure_audit(
                client,
                scope,
                crawl,
                baseline,
                supabase_integration={
                    "enabled": True,
                    "project_url": "https://xyzproject12345678.supabase.co",
                    "anon_key": "sb_publishable_1234567890abcdefghijkl",
                },
            )
            api_out = await run_api_discovery(client, scope, crawl, baseline)
            ac_findings = await run_access_control_audit(
                client,
                scope,
                crawl,
                baseline,
                routes,
                api_out.endpoints,
                credentials=[
                    SuppliedCredential(role_name="user_a", auth_type="bearer", value="tok-user-a"),
                    SuppliedCredential(role_name="user_b", auth_type="bearer", value="tok-user-b"),
                ],
                access_tests=[
                    {
                        "url": "https://vuln.example.com/api/orders/order-user-a",
                        "owner_role": "user_a",
                        "description": "Order owned by test user A",
                    }
                ],
            )

            all_findings = deduplicate_findings(cfg_out.findings + api_out.findings + ac_findings)
            rule_ids = {f["rule_id"] for f in all_findings}

            assert "CFG-DOTENV-EXPOSED" in rule_ids
            assert "CFG-GIT-EXPOSED" in rule_ids
            assert "CFG-SOURCEMAP-EXPOSED" in rule_ids
            assert "CFG-SUPABASE-ANON-TABLE-READ" in rule_ids
            assert "API-OPENAPI-EXPOSED" in rule_ids
            assert "API-CORS-CREDENTIALED-REFLECTION" in rule_ids
            assert "AC-UNAUTH-ADMIN-API" in rule_ids
            assert "AC-CLIENT-GUARD-UNPROTECTED-API" in rule_ids
            assert "AC-ROLE-BYPASS-ADMIN" in rule_ids
            assert "AC-IDOR-CROSS-TENANT" in rule_ids

            # Verify mutating and destructive endpoints were NOT called with POST/DELETE
            ep_by_path = {e.path_template: e for e in api_out.endpoints}
            assert ep_by_path["/api/admin/webhooks"].tested is False
            assert ep_by_path["/api/admin/users/delete"].tested is False

            # Verify CVSS 4.0 scores are attached to confirmed findings and secrets are redacted everywhere
            serialized = json.dumps(all_findings)
            assert raw_stripe not in serialized
            assert "supersecret99" not in serialized
            assert "ceo@example.com" not in serialized

            dotenv_finding = next(f for f in all_findings if f["rule_id"] == "CFG-DOTENV-EXPOSED")
            assert dotenv_finding["cvss_score"] is not None and dotenv_finding["cvss_score"] >= 8.0
