"""Admin and system management surface discovery (Module B).

Critical principles enforced here:
1. Never classify a route as vulnerable merely because its path contains ``admin``, ``dashboard``,
   ``settings``, or ``management``.
2. Distinguish clearly between:
   - ``public_content``: HTTP 200 with real page content distinct from the generic SPA shell and not a login form
   - ``public_shell``: HTTP 200 returning the generic unrendered SPA catch-all shell (client router decides)
   - ``login_page``: HTTP 200 that renders a login/sign-in form
   - ``redirect_to_login``: 30x redirect whose destination is an authentication route
   - ``unauthorized`` / ``forbidden``: HTTP 401 / 403 enforced by the server
   - ``not_found``: HTTP 404 (or a path-probe that only matched the generic SPA shell and has no code reference)
3. Route discovery never implies that an administrator account exists or that the route is exploitable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from app.scanner.baseline import BaselineProfile, normalize_html_structure
from app.scanner.crawler import CrawlOutcome
from app.scanner.html_parse import ParsedHtmlPage, parse_html_page
from app.scanner.http import SafeHttpClient, SafeResponse
from app.scanner.scope import ScopePolicy, path_Looks_destructive

# Curated non-destructive candidate paths grouped by Module B's 6 categories.
CURATED_SURFACE_PATHS: dict[str, tuple[str, ...]] = {
    "authentication": (
        "/login",
        "/signin",
        "/sign-in",
        "/auth/login",
        "/auth/signin",
        "/auth/callback",
        "/register",
        "/signup",
        "/sign-up",
        "/forgot-password",
        "/reset-password",
    ),
    "admin_interface": (
        "/admin",
        "/admin/dashboard",
        "/admin/login",
        "/admin-panel",
        "/superadmin",
        "/super-admin",
        "/dashboard/admin",
        "/management",
        "/control-panel",
        "/backoffice",
        "/console",
        "/internal",
    ),
    "user_management": (
        "/admin/users",
        "/admin/roles",
        "/admin/permissions",
        "/users",
        "/dashboard/users",
        "/management/users",
        "/settings/team",
        "/settings/members",
        "/settings/roles",
    ),
    "system_configuration": (
        "/settings",
        "/admin/settings",
        "/admin/config",
        "/system/settings",
        "/system/config",
        "/feature-flags",
        "/admin/feature-flags",
        "/settings/integrations",
        "/settings/environment",
    ),
    "workflow_management": (
        "/workflows",
        "/admin/workflows",
        "/automations",
        "/agents",
        "/admin/agents",
        "/settings/api-keys",
        "/settings/webhooks",
        "/admin/webhooks",
    ),
    "backend_management": (
        "/admin/database",
        "/admin/storage",
        "/admin/logs",
        "/admin/audit-logs",
        "/admin/monitoring",
        "/status",
        "/metrics",
        "/ studio",
    ),
}

CATEGORY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "authentication",
        re.compile(
            r"(?:^|/)(?:login|log-in|signin|sign-in|signup|sign-up|register|auth(?:/callback|/login|/signin|/reset)?|forgot-password|reset-password|sso|oauth)(?:/|$)",
            re.IGNORECASE,
        ),
    ),
    (
        "user_management",
        re.compile(
            r"(?:^|/)(?:admin/users|admin/roles|admin/permissions|user-management|role-management|permissions|members|team-management|accounts-admin|manage-users)(?:/|$)",
            re.IGNORECASE,
        ),
    ),
    (
        "system_configuration",
        re.compile(
            r"(?:^|/)(?:admin/settings|admin/config|system-config|system/settings|system/config|feature-flags|admin/feature-flags|environment|integrations-config|settings/integrations|settings/security|settings/environment)(?:/|$)",
            re.IGNORECASE,
        ),
    ),
    (
        "workflow_management",
        re.compile(
            r"(?:^|/)(?:workflows?|workflow-editor|automations?|agents?|agent-management|api-management|api-keys|webhooks?|admin/webhooks|admin/agents|admin/workflows)(?:/|$)",
            re.IGNORECASE,
        ),
    ),
    (
        "backend_management",
        re.compile(
            r"(?:^|/)(?:admin/database|database-admin|db-admin|storage-admin|admin/storage|admin/logs|audit-logs|monitoring|metrics|telemetry|queue-admin|bull-board|flower|pgadmin|studio|graphql-playground)(?:/|$)",
            re.IGNORECASE,
        ),
    ),
    (
        "admin_interface",
        re.compile(
            r"(?:^|/)(?:admin|superadmin|super-admin|admin-panel|admin-dashboard|control-panel|management|backoffice|internal|staff|moderator|ops-console|cms)(?:/|$)",
            re.IGNORECASE,
        ),
    ),
)

LOGIN_PATH_RE = re.compile(r"(?:^|/)(?:login|log-in|signin|sign-in|auth/login|auth/signin|api/auth/signin)(?:/|\?|$)", re.IGNORECASE)


def categorize_route_path(path: str, title: str = "") -> tuple[str, bool]:
    """Return ``(admin_category, is_admin_surface)``."""
    clean = path.split("?", 1)[0].strip() or "/"
    for category, pattern in CATEGORY_PATTERNS:
        if pattern.search(clean):
            return category, True
    # Check if the route is a sub-path under /admin/... or /management/... or /superadmin/...
    if re.search(r"(?:^|/)(?:admin|superadmin|super-admin|management|backoffice|internal)/", clean, re.IGNORECASE):
        return "admin_interface", True
    if clean in ("/settings", "/dashboard/settings") or clean.startswith("/settings/"):
        return "system_configuration", True
    if title and re.search(r"\b(admin\s*(panel|dashboard|console)|super\s*admin|user\s*management)\b", title, re.IGNORECASE):
        return "admin_interface", True
    return "none", False


@dataclass
class DiscoveredRoute:
    url: str
    path: str
    status_code: int | None
    title: str | None
    content_type: str | None
    content_hash: str | None
    auth_observation: str
    redirect_chain: list[dict] = field(default_factory=list)
    discovery_methods: list[str] = field(default_factory=list)
    admin_category: str = "none"
    is_admin_surface: bool = False
    confidence: float = 0.0
    risk_level: str = "none"
    evidence: list[dict] = field(default_factory=list)
    parsed_page: ParsedHtmlPage | None = None
    response: SafeResponse | None = None


def classify_route_response(
    url: str,
    path: str,
    resp: SafeResponse,
    parsed: ParsedHtmlPage | None,
    baseline: BaselineProfile,
    discovery_methods: set[str],
    admin_category: str,
    is_admin_surface: bool,
) -> tuple[str, float, str, list[dict]]:
    """Determine ``(auth_observation, confidence, risk_level, evidence)`` for a route response."""
    evidence: list[dict] = []
    for dm in sorted(discovery_methods):
        evidence.append({"type": "discovery", "detail": f"Discovered via {dm}", "location": path})

    if resp.redirect_chain:
        first_loc = resp.redirect_chain[-1].location
        dest_path = urlparse(first_loc).path
        evidence.append(
            {
                "type": "redirect",
                "detail": f"Redirected ({resp.redirect_chain[0].status_code}) to {first_loc}",
                "location": url,
            }
        )
        if LOGIN_PATH_RE.search(dest_path) or (parsed and parsed.looks_like_login_page):
            return "redirect_to_login", 0.9, "info" if is_admin_surface else "none", evidence

    status = resp.status_code
    if status == 401:
        evidence.append({"type": "http_status", "detail": "Server enforced HTTP 401 Unauthorized", "location": url})
        return "unauthorized", 0.9, "info" if is_admin_surface else "none", evidence
    if status == 403:
        evidence.append({"type": "http_status", "detail": "Server enforced HTTP 403 Forbidden", "location": url})
        return "forbidden", 0.9, "info" if is_admin_surface else "none", evidence
    if status == 404 or status == 410:
        return "not_found", 0.2, "none", evidence
    if status >= 500:
        evidence.append({"type": "http_status", "detail": f"Server returned HTTP {status}", "location": url})
        return "error", 0.5, "low" if is_admin_surface else "none", evidence

    if resp.blocked_redirect:
        evidence.append({"type": "redirect_blocked", "detail": f"Redirect blocked: {resp.blocked_redirect}", "location": url})
        return "redirect_other", 0.6, "info", evidence

    if status == 200:
        if parsed and parsed.looks_like_login_page:
            evidence.append(
                {
                    "type": "login_form",
                    "detail": f"Page renders an authentication form (title={parsed.title!r})",
                    "location": url,
                }
            )
            return "login_page", 0.9, "info", evidence

        if baseline.matches_spa_shell(resp):
            code_backed = bool(discovery_methods & {"js_bundle", "inline_script", "crawl", "playwright_dom", "robots_txt"})
            if not code_backed:
                # Path probe hit the generic SPA catch-all with no reference in code -> soft-404
                evidence.append(
                    {
                        "type": "spa_baseline_match",
                        "detail": "Response matches generic SPA catch-all shell and route is not referenced in client bundles (soft 404)",
                        "location": url,
                    }
                )
                return "not_found", 0.15, "none", evidence
            evidence.append(
                {
                    "type": "spa_shell",
                    "detail": "Route is registered in client bundle and server returns the generic SPA shell (HTTP 200); authorization depends on client router and backing APIs",
                    "location": url,
                }
            )
            risk = "low" if is_admin_surface and admin_category != "authentication" else "info"
            return "public_shell", 0.75, risk, evidence

        # Distinct HTTP 200 content!
        title_str = parsed.title if parsed else ""
        evidence.append(
            {
                "type": "http_response",
                "detail": f"HTTP 200 with distinct content ({len(resp.body)} bytes, title={title_str!r})",
                "location": url,
            }
        )
        if parsed and parsed.admin_ui_phrases:
            evidence.append(
                {
                    "type": "admin_ui_markers",
                    "detail": f"Administrative UI elements observed in HTML: {', '.join(parsed.admin_ui_phrases[:5])}",
                    "location": url,
                }
            )
        if not is_admin_surface or admin_category == "authentication":
            return "public_content", 0.85, "none", evidence

        has_strong_admin_markers = bool(parsed and parsed.admin_ui_phrases)
        risk = "high" if has_strong_admin_markers else "medium"
        conf = 0.92 if has_strong_admin_markers else 0.75
        return "public_content", conf, risk, evidence

    return "redirect_other", 0.5, "none", evidence


async def discover_routes_and_admin_surfaces(
    client: SafeHttpClient,
    scope: ScopePolicy,
    crawl: CrawlOutcome,
    baseline: BaselineProfile,
    *,
    enable_path_probing: bool = True,
) -> list[DiscoveredRoute]:
    candidate_urls: dict[str, set[str]] = {}

    for url, methods in crawl.discovery_methods.items():
        candidate_urls.setdefault(url, set()).update(methods)

    # Paths from robots.txt Disallow/Allow entries (passive intelligence)
    for r_path in crawl.robots.disallowed_paths + crawl.robots.allowed_paths:
        resolved = scope.resolve_in_scope(r_path, scope.base_url)
        if resolved:
            candidate_urls.setdefault(resolved, set()).add("robots_txt")

    # Curated admin/auth/config path probes (non-destructive GETs only)
    if enable_path_probing and scope.config.enable_path_probing:
        for _cat, paths in CURATED_SURFACE_PATHS.items():
            for p in paths:
                p_clean = p.strip()
                if path_Looks_destructive(p_clean):
                    continue
                resolved = scope.resolve_in_scope(p_clean, scope.base_url)
                if resolved:
                    candidate_urls.setdefault(resolved, set()).add("path_probe")

    routes: list[DiscoveredRoute] = []
    for url, methods in candidate_urls.items():
        parsed_url = urlparse(url)
        path = parsed_url.path or "/"
        if path_Looks_destructive(path):
            continue
        # Skip parameterized route templates that weren't concretized
        if ":" in path or "*" in path or "[" in path:
            cat, is_admin = categorize_route_path(path)
            if is_admin:
                routes.append(
                    DiscoveredRoute(
                        url=url,
                        path=path,
                        status_code=None,
                        title=None,
                        content_type=None,
                        content_hash=None,
                        auth_observation="not_tested",
                        discovery_methods=sorted(methods),
                        admin_category=cat,
                        is_admin_surface=True,
                        confidence=0.65,
                        risk_level="info",
                        evidence=[
                            {
                                "type": "route_template",
                                "detail": f"Parameterized route template {path!r} discovered in bundle (not directly probed without concrete ID)",
                                "location": path,
                            }
                        ],
                    )
                )
            continue

        resp = crawl.page_responses.get(url)
        if resp is None:
            if scope.config.respect_robots and not crawl.robots.can_fetch(client.user_agent, url):
                cat, is_admin = categorize_route_path(path)
                if is_admin or "robots_txt" in methods:
                    routes.append(
                        DiscoveredRoute(
                            url=url,
                            path=path,
                            status_code=None,
                            title=None,
                            content_type=None,
                            content_hash=None,
                            auth_observation="not_tested",
                            discovery_methods=sorted(methods),
                            admin_category=cat,
                            is_admin_surface=is_admin,
                            confidence=0.6 if "robots_txt" in methods else 0.3,
                            risk_level="info",
                            evidence=[
                                {
                                    "type": "robots_disallow",
                                    "detail": "Path is disallowed by robots.txt and was not fetched because respect_robots is enabled",
                                    "location": path,
                                }
                            ],
                        )
                    )
                continue
            try:
                resp = await client.get(url, follow_redirects=True)
            except Exception:
                continue

        parsed_page = crawl.parsed_pages.get(url)
        if parsed_page is None and "html" in (resp.content_type or "").lower():
            parsed_page = parse_html_page(resp.text, resp.final_url, scope)

        title = parsed_page.title if parsed_page else None
        cat, is_admin = categorize_route_path(path, title or "")
        auth_obs, conf, risk, evidence = classify_route_response(
            url, path, resp, parsed_page, baseline, methods, cat, is_admin
        )

        # Drop pure path-probe 404s so the route inventory stays high-signal
        if auth_obs == "not_found" and methods == {"path_probe"}:
            continue

        _, struct_h, _, _ = normalize_html_structure(resp.text) if "html" in (resp.content_type or "").lower() else ("", resp.sha256[:16], "", [])

        routes.append(
            DiscoveredRoute(
                url=url,
                path=path,
                status_code=resp.status_code,
                title=title,
                content_type=resp.content_type,
                content_hash=struct_h,
                auth_observation=auth_obs,
                redirect_chain=[h.to_dict() for h in resp.redirect_chain],
                discovery_methods=sorted(methods),
                admin_category=cat,
                is_admin_surface=is_admin,
                confidence=round(conf, 2),
                risk_level=risk,
                evidence=evidence,
                parsed_page=parsed_page,
                response=resp,
            )
        )

    routes.sort(key=lambda r: (not r.is_admin_surface, r.path))
    return routes
