"""Safe access-control auditing engine (Module C).

Covers:
A. Unauthenticated checks on discovered administrative routes and administrative/user-management APIs
   (distinguishing real content vs SPA shell vs login page vs redirect vs 401/403).
B. Client-side-only access restrictions: correlates client-side role checks / SPA admin shells with
   whether backing APIs actually enforce authentication on the server.
C. Authenticated role comparison: uses explicitly supplied test-account credentials (decrypted in
   memory only for the duration of the check) to test whether a non-admin test role can access
   administrative routes or APIs that were blocked for anonymous requests.
D. Owner-defined cross-account object access tests (IDOR indicators): requests ONLY test-owned
   resource URLs explicitly declared in ``target.access_tests`` across supplied test roles. Never
   enumerates or guesses IDs of real users.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.core.redaction import redact_text
from app.scanner.admin_surface import DiscoveredRoute
from app.scanner.api_discovery import USER_PII_JSON_KEYS_RE, DiscoveredEndpoint
from app.scanner.baseline import BaselineProfile
from app.scanner.crawler import CrawlOutcome
from app.scanner.findings import FindingDraft
from app.scanner.html_parse import parse_html_page
from app.scanner.http import SafeHttpClient
from app.scanner.scope import ScopePolicy, path_Looks_destructive

ADMIN_ROLE_NAMES = frozenset({"admin", "superadmin", "super_admin", "owner", "administrator", " admin_test"})


@dataclass
class SuppliedCredential:
    role_name: str
    auth_type: str  # cookie | bearer | header
    value: str
    header_name: str | None = None

    @property
    def is_admin_role(self) -> bool:
        r = self.role_name.lower()
        return any(tok in r for tok in ("admin", "owner", "super"))

    def to_headers(self) -> dict[str, str]:
        if self.auth_type == "cookie":
            return {"Cookie": self.value}
        if self.auth_type == "bearer":
            val = self.value if self.value.lower().startswith("bearer ") else f"Bearer {self.value}"
            return {"Authorization": val}
        if self.auth_type == "header" and self.header_name:
            return {self.header_name: self.value}
        return {}


async def run_access_control_audit(
    client: SafeHttpClient,
    scope: ScopePolicy,
    crawl: CrawlOutcome,
    baseline: BaselineProfile,
    routes: list[DiscoveredRoute],
    endpoints: list[DiscoveredEndpoint],
    *,
    credentials: list[SuppliedCredential] | None = None,
    access_tests: list[dict] | None = None,
) -> list[FindingDraft]:
    findings: list[FindingDraft] = []
    creds = credentials or []

    # --- A. Unauthenticated access to administrative & management pages ---
    for r in routes:
        if not r.is_admin_surface or r.admin_category == "authentication":
            continue
        if r.auth_observation == "public_content":
            has_admin_markers = bool(r.parsed_page and r.parsed_page.admin_ui_phrases)
            if has_admin_markers:
                findings.append(
                    FindingDraft(
                        rule_id="AC-UNAUTH-ADMIN-PAGE",
                        title=f"Administrative interface at {r.path} is publicly accessible without authentication",
                        category="access_control",
                        severity="high",
                        status="confirmed",
                        confidence=0.92,
                        affected=r.url,
                        evidence=list(r.evidence),
                        detection_method="Unauthenticated GET compared against SPA baseline + administrative UI marker verification",
                        impact="Unauthenticated visitors receive rendered administrative or system management content directly from the server.",
                        reproduction=[f"curl -i -s {r.url} | head -n 30"],
                        remediation="Enforce server-side session authentication and admin role verification in middleware before rendering or serving administrative routes.",
                    )
                )
            else:
                findings.append(
                    FindingDraft(
                        rule_id="AC-POTENTIAL-PUBLIC-ADMIN-ROUTE",
                        title=f"Management route {r.path} returned HTTP 200 distinct from SPA baseline without authentication",
                        category="access_control",
                        severity="medium",
                        status="potential",
                        confidence=0.72,
                        affected=r.url,
                        evidence=list(r.evidence),
                        detection_method="Unauthenticated GET compared against SPA baseline",
                        impact="The route is reachable without authentication and returns distinct HTML; verify whether sensitive management actions or data are exposed.",
                        reproduction=[f"curl -i -s {r.url} | head -n 30"],
                        remediation="Protect management routes with server-side authentication middleware or redirect unauthenticated users to the sign-in flow.",
                    )
                )
        elif r.auth_observation == "public_shell":
            findings.append(
                FindingDraft(
                    rule_id="AC-SPA-ADMIN-SHELL",
                    title=f"Administrative route {r.path} is served via public SPA shell (client-routed)",
                    category="admin_surface",
                    severity="low",
                    status="informational",
                    confidence=0.8,
                    affected=r.url,
                    evidence=list(r.evidence),
                    detection_method="Bundle route extraction + SPA baseline comparison",
                    impact="In single-page applications, serving the HTML shell for /admin is common and not vulnerable by itself, provided all admin data and mutations are enforced by server-side API authorization.",
                    reproduction=[f"curl -i -s {r.url} | head -n 20"],
                    remediation="Ensure every API endpoint and database query used by this view validates the caller's session and administrator role on the server.",
                )
            )

    # --- B. Unauthenticated access to administrative / user-management API endpoints ---
    unprotected_admin_apis: list[DiscoveredEndpoint] = []
    for ep in endpoints:
        if ep.category not in ("administration", "user_management", "configuration", "database"):
            continue
        if ep.auth_observation != "public_content":
            continue
        is_json = "json" in (ep.content_type or "").lower() or ep.sample_body.lstrip().startswith(("{", "["))
        has_pii = bool(USER_PII_JSON_KEYS_RE.search(ep.sample_body))
        if is_json and (ep.category in ("administration", "user_management") or has_pii):
            unprotected_admin_apis.append(ep)
            findings.append(
                FindingDraft(
                    rule_id="AC-UNAUTH-ADMIN-API",
                    title=f"Administrative or user-management API {ep.path_template} returns data without authentication",
                    category="access_control",
                    severity="high" if not has_pii else "critical",
                    status="confirmed",
                    confidence=0.94,
                    affected=ep.url,
                    evidence=list(ep.evidence),
                    detection_method="Unauthenticated GET request with JSON response and schema verification",
                    impact="Unauthenticated callers can query privileged administrative or user-management data directly from the API.",
                    reproduction=[f"curl -i -s -H 'Accept: application/json' {ep.url}"],
                    remediation="Add server-side authentication and role-based authorization middleware to all administrative and user-management API handlers.",
                )
            )

    # --- C. Client-side-only access control correlation ---
    client_patterns = [m for jr in crawl.js_results for m in jr.client_auth_patterns]
    if client_patterns:
        sample = client_patterns[0]
        if unprotected_admin_apis:
            findings.append(
                FindingDraft(
                    rule_id="AC-CLIENT-GUARD-UNPROTECTED-API",
                    title="Frontend relies on client-side role checks while backing administrative API lacks server-side authentication",
                    category="access_control",
                    severity="high",
                    status="confirmed",
                    confidence=0.93,
                    affected=unprotected_admin_apis[0].url,
                    evidence=[
                        {
                            "type": "client_guard",
                            "detail": f"{sample.title} in {sample.source_location}",
                            "location": sample.source_location,
                            "snippet": sample.snippet,
                        },
                        *unprotected_admin_apis[0].evidence,
                    ],
                    detection_method="Correlated frontend JS role-guard patterns with unauthenticated HTTP 200 responses from administrative APIs",
                    impact="Vibe-coded applications frequently hide admin UI behind React state or localStorage checks while leaving the API endpoint open to direct HTTP requests.",
                    reproduction=[
                        f"Inspect client check in {sample.source_location}",
                        f"curl -i -s {unprotected_admin_apis[0].url}",
                    ],
                    remediation="Never trust client-side state or localStorage for authorization. Verify the user's session token and role on the server for every API request.",
                )
            )
        else:
            for pat in client_patterns[:5]:
                 is_storage = pat.rule_id == "CS-LOCALSTORAGE-ROLE"
                 findings.append(
                    FindingDraft(
                        rule_id=pat.rule_id,
                        title=pat.title,
                        category="access_control",
                        severity="medium" if is_storage else "low",
                        status="potential" if is_storage else "informational",
                        confidence=0.78,
                        affected=pat.source_location,
                        discriminator=pat.rule_id,
                        evidence=[
                            {
                                "type": "js_pattern",
                                "detail": pat.title,
                                "location": pat.source_location,
                                "snippet": pat.snippet,
                            }
                        ],
                        detection_method="Static analysis of frontend JavaScript bundle",
                        impact="Any user can modify localStorage/sessionStorage or React state in DevTools to render hidden administrative views; security depends entirely on backend enforcement.",
                        reproduction=[f"Search {pat.source_location} for client-side role checks"],
                        remediation="Derive role claims from a server-verified session or signed token on every backend request, and avoid storing authorization flags in localStorage.",
                    )
                )

    # --- D. Authenticated role-comparison checks (only with owner-supplied test credentials) ---
    low_priv_creds = [c for c in creds if not c.is_admin_role]
    if low_priv_creds:
        await _run_role_comparison_checks(client, scope, baseline, routes, endpoints, low_priv_creds, findings)

    # --- E. Owner-declared test-resource cross-account checks (IDOR / BOLA indicators) ---
    if access_tests and creds:
        await _run_owner_defined_access_tests(client, scope, baseline, creds, access_tests, findings)

    return findings


async def _run_role_comparison_checks(
    client: SafeHttpClient,
    scope: ScopePolicy,
    baseline: BaselineProfile,
    routes: list[DiscoveredRoute],
    endpoints: list[DiscoveredEndpoint],
    low_priv_creds: list[SuppliedCredential],
    findings: list[FindingDraft],
) -> None:
    cred = low_priv_creds[0]
    auth_headers = cred.to_headers()

    # Test administrative APIs that required auth for anonymous requests
    protected_admin_apis = [
        ep
        for ep in endpoints
        if ep.category in ("administration", "user_management", "configuration")
        and ep.auth_observation in ("unauthorized", "forbidden", "redirect_to_login")
        and not path_Looks_destructive(ep.path_template)
    ]
    for ep in protected_admin_apis[:15]:
        try:
            resp = await client.get(
                ep.url,
                headers={**auth_headers, "Accept": "application/json"},
                follow_redirects=False,
                for_asset=True,
                max_bytes=128 * 1024,
            )
        except Exception:
            continue
        if resp.status_code == 200 and not baseline.matches_spa_shell(resp):
            body = resp.text
            if "json" in (resp.content_type or "").lower() or body.lstrip().startswith(("{", "[")):
                findings.append(
                    FindingDraft(
                        rule_id="AC-ROLE-BYPASS-ADMIN",
                        title=f"Administrative API {ep.path_template} is accessible to non-admin test role '{cred.role_name}'",
                        category="access_control",
                        severity="high",
                        status="confirmed",
                        confidence=0.93,
                        affected=ep.url,
                        evidence=[
                            {
                                "type": "role_comparison",
                                "detail": f"Anonymous request received {ep.auth_observation} ({ep.status_code}), but non-admin role '{cred.role_name}' received HTTP 200 ({len(resp.body)} bytes)",
                                "location": ep.url,
                                "snippet": redact_text(body[:300]),
                            }
                        ],
                        detection_method="Authenticated role-comparison check using owner-supplied test account",
                        impact="The endpoint checks that a user is logged in (authentication) but fails to verify that the user holds an administrator role (broken function-level authorization).",
                        reproduction=[f"curl -i -s -H '<{cred.role_name}-session>' {ep.url}"],
                        remediation="Enforce explicit role/permission checks (e.g. requireRole('admin')) in addition to authentication middleware on administrative endpoints.",
                    )
                )

    # Test administrative HTML routes that redirected or returned 401/403 anonymously
    protected_admin_routes = [
        r
        for r in routes
        if r.is_admin_surface
        and r.admin_category != "authentication"
        and r.auth_observation in ("unauthorized", "forbidden", "redirect_to_login")
    ]
    for r in protected_admin_routes[:10]:
        try:
            resp = await client.get(r.url, headers=auth_headers, follow_redirects=False)
        except Exception:
            continue
        if resp.status_code == 200 and not baseline.matches_spa_shell(resp):
            parsed = parse_html_page(resp.text, r.url, scope)
            if not parsed.looks_like_login_page and parsed.admin_ui_phrases:
                findings.append(
                    FindingDraft(
                        rule_id="AC-ROLE-BYPASS-ADMIN",
                        title=f"Administrative page {r.path} renders for non-admin test role '{cred.role_name}'",
                        category="access_control",
                        severity="high",
                        status="confirmed",
                        confidence=0.9,
                        affected=r.url,
                        evidence=[
                            {
                                "type": "role_comparison",
                                "detail": f"Non-admin role '{cred.role_name}' received HTTP 200 with admin UI phrases: {', '.join(parsed.admin_ui_phrases[:4])}",
                                "location": r.url,
                            }
                        ],
                        detection_method="Authenticated role-comparison check using owner-supplied test account",
                        impact="Any authenticated user can access administrative pages intended only for privileged operators.",
                        reproduction=[f"curl -i -s -H '<{cred.role_name}-session>' {r.url}"],
                        remediation="Verify the authenticated user's role on the server before rendering administrative views.",
                    )
                )


async def _run_owner_defined_access_tests(
    client: SafeHttpClient,
    scope: ScopePolicy,
    baseline: BaselineProfile,
    creds: list[SuppliedCredential],
    access_tests: list[dict],
    findings: list[FindingDraft],
) -> None:
    cred_by_role = {c.role_name.lower(): c for c in creds}
    for item in access_tests[:20]:
        url = str(item.get("url") or "").strip()
        owner_role = str(item.get("owner_role") or "").strip()
        desc = str(item.get("description") or "")
        if not url or not owner_role or not scope.is_in_scope(url, for_asset=True):
            continue
        if path_Looks_destructive(url):
            continue
        owner_cred = cred_by_role.get(owner_role.lower())
        if owner_cred is None:
            continue
        try:
            owner_resp = await client.get(url, headers=owner_cred.to_headers(), follow_redirects=False, for_asset=True)
        except Exception:
            continue
        if owner_resp.status_code != 200 or baseline.matches_spa_shell(owner_resp):
            continue

        # Check with other non-admin roles (horizontal access / IDOR) and anonymous
        other_creds = [c for c in creds if c.role_name.lower() != owner_role.lower() and not c.is_admin_role]
        for other in other_creds:
            try:
                other_resp = await client.get(url, headers=other.to_headers(), follow_redirects=False, for_asset=True)
            except Exception:
                continue
            if other_resp.status_code == 200 and len(other_resp.body) > 10 and not baseline.matches_spa_shell(other_resp):
                findings.append(
                    FindingDraft(
                        rule_id="AC-IDOR-CROSS-TENANT",
                        title=f"Test resource owned by '{owner_role}' is accessible to other test role '{other.role_name}' (IDOR / BOLA)",
                        category="access_control",
                        severity="high",
                        status="confirmed",
                        confidence=0.94,
                        affected=url,
                        evidence=[
                            {
                                "type": "cross_account_test",
                                "detail": f"Owner role '{owner_role}' received HTTP 200 ({len(owner_resp.body)} bytes); non-owner role '{other.role_name}' also received HTTP 200 ({len(other_resp.body)} bytes). Resource: {desc}",
                                "location": url,
                                "snippet": redact_text(other_resp.text[:260]),
                            }
                        ],
                        detection_method="Owner-configured cross-account access test on test-owned resource",
                        impact="Users can read records belonging to other accounts by referencing their object identifier (Broken Object Level Authorization / IDOR).",
                        reproduction=[f"curl -i -s -H '<{other.role_name}-session>' {url}"],
                        remediation="Enforce object ownership checks (`WHERE id = :id AND owner_id = :current_user_id`) or Row Level Security on every object lookup.",
                    )
                )
