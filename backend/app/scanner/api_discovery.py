"""API endpoint discovery, categorization, and safe non-destructive checks (Module E).

Rules:
- Only safe methods (GET, HEAD, OPTIONS) are ever sent.
- Endpoints whose path contains destructive tokens (delete, destroy, purge, reset-all, ...) or that
  were only seen with mutating verbs and contain state-changing action words are recorded as
  ``tested=False`` with an explanation rather than requested.
- OpenAPI / Swagger schemas are passively checked at standard locations and their paths imported.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from app.core.redaction import redact_text
from app.scanner.baseline import BaselineProfile
from app.scanner.crawler import CrawlOutcome
from app.scanner.findings import FindingDraft
from app.scanner.http import SafeHttpClient
from app.scanner.scope import ScopePolicy, path_Looks_destructive

OPENAPI_PATHS: tuple[str, ...] = (
    "/openapi.json",
    "/api/openapi.json",
    "/api/docs",
    "/swagger.json",
    "/api-docs",
    "/v1/openapi.json",
)

ENDPOINT_CATEGORIES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("authentication", re.compile(r"(?:^|/)(?:auth|login|signin|signup|register|token|session|oauth|sso|password)(?:/|$)", re.I)),
    ("administration", re.compile(r"(?:^|/)(?:admin|superadmin|super-admin|management|backoffice|control|ops)(?:/|$)", re.I)),
    ("user_management", re.compile(r"(?:^|/)(?:users?|accounts?|profiles?|roles?|permissions?|members?|teams?)(?:/|$)", re.I)),
    ("configuration", re.compile(r"(?:^|/)(?:config|configuration|settings|env|feature-flags|flags|integrations)(?:/|$)", re.I)),
    ("database", re.compile(r"(?:^|/)(?:rest/v1|db|database|graphql|trpc|query|sql|collections|entities)(?:/|$)", re.I)),
    ("file_storage", re.compile(r"(?:^|/)(?:storage|files?|uploads?|media|buckets?|assets|attachments)(?:/|$)", re.I)),
    ("workflow", re.compile(r"(?:^|/)(?:workflows?|automations?|jobs?|pipelines?|tasks?|queues?)(?:/|$)", re.I)),
    ("ai_agents", re.compile(r"(?:^|/)(?:agents?|ai|chat|completions|embeddings|llm|assistants?|prompts?)(?:/|$)", re.I)),
    ("webhooks", re.compile(r"(?:^|/)(?:webhooks?|hooks?|callbacks?|events?)(?:/|$)", re.I)),
    ("internal", re.compile(r"(?:^|/)(?:internal|debug|metrics|health|status|system|diagnostics)(?:/|$)", re.I)),
)

SENSITIVE_JSON_KEYS_RE = re.compile(
    r'"(?:password|password_hash|hashed_password|secret|api_key|apiKey|private_key|access_token|refresh_token|ssn|credit_card|stripe_secret|service_role)"\s*:',
    re.IGNORECASE,
)
USER_PII_JSON_KEYS_RE = re.compile(
    r'"(?:email|role|is_admin|isAdmin|permissions|phone|address|user_id)"\s*:',
    re.IGNORECASE,
)


def categorize_api_path(path: str) -> str:
    for cat, pat in ENDPOINT_CATEGORIES:
        if pat.search(path):
            return cat
    return "other"


@dataclass
class DiscoveredEndpoint:
    url: str
    path_template: str
    methods: list[str] = field(default_factory=list)
    category: str = "other"
    sources: list[str] = field(default_factory=list)
    status_code: int | None = None
    auth_observation: str = "not_tested"
    content_type: str | None = None
    cors: dict = field(default_factory=dict)
    tested: bool = False
    test_note: str | None = None
    evidence: list[dict] = field(default_factory=list)
    sample_body: str = ""


@dataclass
class ApiDiscoveryOutcome:
    endpoints: list[DiscoveredEndpoint] = field(default_factory=list)
    findings: list[FindingDraft] = field(default_factory=list)


async def run_api_discovery(
    client: SafeHttpClient,
    scope: ScopePolicy,
    crawl: CrawlOutcome,
    baseline: BaselineProfile,
    *,
    max_endpoints: int = 80,
) -> ApiDiscoveryOutcome:
    outcome = ApiDiscoveryOutcome()
    by_path: dict[str, DiscoveredEndpoint] = {}

    def register(raw_url_or_path: str, method: str, source: str, detail: str) -> None:
        resolved = scope.resolve_in_scope(raw_url_or_path, scope.base_url, for_asset=True)
        if not resolved:
            return
        parsed = urlparse(resolved)
        path = parsed.path or "/"
        ep = by_path.get(path)
        if ep is None:
            ep = DiscoveredEndpoint(
                url=resolved,
                path_template=path,
                methods=[method.upper()],
                category=categorize_api_path(path),
                sources=[source],
                evidence=[{"type": source, "detail": detail[:240], "location": path}],
            )
            by_path[path] = ep
        else:
            if method.upper() not in ep.methods:
                ep.methods.append(method.upper())
            if source not in ep.sources:
                ep.sources.append(source)

    # 1. Harvest from JS bundle analysis
    for jr in crawl.js_results:
        for ref in jr.api_refs:
            register(ref.path_or_url, ref.method, "js_bundle", f"Referenced in {ref.source_location}: {ref.snippet}")

    # 2. Harvest from HTML forms targeting /api/*
    for page_url, parsed in crawl.parsed_pages.items():
        for form in parsed.forms:
            p = urlparse(form.action).path
            if p.startswith(("/api/", "/v1/", "/v2/", "/auth/", "/graphql", "/trpc")):
                register(form.action, form.method, "html_form", f"Form action on {page_url}")

    # 3. Harvest from optional Playwright network interception
    for method, req_url in crawl.browser_api_requests:
        register(req_url, method, "network_reference", f"Observed browser request {method} {req_url}")

    # 4. Probe standard OpenAPI / Swagger specification paths
    await _discover_openapi_specs(client, scope, baseline, register, outcome)

    # 5. Perform safe, non-destructive checks on discovered endpoints
    for _path, ep in list(by_path.items())[:max_endpoints]:
        await _inspect_endpoint_safely(client, scope, baseline, ep, outcome)
        outcome.endpoints.append(ep)

    outcome.endpoints.sort(key=lambda e: (e.category != "administration", e.path_template))
    return outcome


async def _discover_openapi_specs(
    client: SafeHttpClient,
    scope: ScopePolicy,
    baseline: BaselineProfile,
    register,  # type: ignore[no-untyped-def]
    outcome: ApiDiscoveryOutcome,
) -> None:
    base = scope.base_url.rstrip("/")
    for spec_path in OPENAPI_PATHS:
        url = f"{base}{spec_path}"
        if not scope.is_in_scope(url, for_asset=True):
            continue
        try:
            resp = await client.get(url, follow_redirects=True, for_asset=True, max_bytes=1024 * 1024)
        except Exception:
            continue
        if resp.status_code != 200 or baseline.matches_spa_shell(resp):
            continue
        ct = (resp.content_type or "").lower()
        body = resp.text.lstrip()
        if "json" in ct or body.startswith("{"):
            try:
                spec = json.loads(body)
            except ValueError:
                continue
            if not isinstance(spec, dict) or ("openapi" not in spec and "swagger" not in spec):
                continue
            paths = spec.get("paths") or {}
            if isinstance(paths, dict):
                for p, ops in list(paths.items())[:100]:
                    if isinstance(ops, dict):
                        for verb in ops:
                            if verb.upper() in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
                                register(str(p), verb.upper(), "openapi", f"Declared in OpenAPI schema at {spec_path}")
            outcome.findings.append(
                FindingDraft(
                    rule_id="API-OPENAPI-EXPOSED",
                    title=f"OpenAPI / Swagger specification publicly accessible at {spec_path}",
                    category="api_security",
                    severity="info",
                    status="informational",
                    confidence=0.99,
                    affected=url,
                    evidence=[
                        {
                            "type": "openapi_spec",
                            "detail": f"OpenAPI spec exposes {len(paths) if isinstance(paths, dict) else 0} API paths",
                            "location": url,
                        }
                    ],
                    detection_method="Direct GET request validated against OpenAPI/Swagger JSON schema",
                    impact="Enumerates all backend routes, parameters, and schemas, including administrative or internal endpoints if they share the same router.",
                    reproduction=[f"curl -s {url} | head -c 400"],
                    remediation="Restrict API documentation to authenticated developers or disable it in production if the API is not a public developer platform.",
                )
            )


async def _inspect_endpoint_safely(
    client: SafeHttpClient,
    scope: ScopePolicy,
    baseline: BaselineProfile,
    ep: DiscoveredEndpoint,
    outcome: ApiDiscoveryOutcome,
) -> None:
    path = ep.path_template
    if path_Looks_destructive(path):
        ep.tested = False
        ep.auth_observation = "not_tested"
        ep.test_note = "Skipped: path contains destructive action keyword"
        return
    if any(ch in path for ch in (":", "{", "}", "$", "*", "[")):
        ep.tested = False
        ep.auth_observation = "not_tested"
        ep.test_note = "Skipped: parameterized path template without concrete test identifier"
        return
    if "GET" not in ep.methods and "HEAD" not in ep.methods:
        # Endpoint was only seen with POST/PUT/PATCH/DELETE. Never send a mutating request;
        # at most send an OPTIONS check to observe CORS/Allow headers without side effects.
        try:
            opt_resp = await client.options(
                ep.url,
                headers={"Origin": "https://vibescan-cors-probe.invalid"},
                follow_redirects=False,
                for_asset=True,
            )
            ep.status_code = opt_resp.status_code
            ep.cors = _extract_cors(opt_resp.headers)
        except Exception:
            pass
        ep.tested = False
        ep.auth_observation = "not_tested"
        ep.test_note = f"Mutating endpoint ({', '.join(ep.methods)}); non-destructive policy skips state-changing requests"
        _check_cors_finding(ep, outcome)
        return

    try:
        resp = await client.get(
            ep.url,
            headers={"Origin": "https://vibescan-cors-probe.invalid", "Accept": "application/json"},
            follow_redirects=False,
            for_asset=True,
            max_bytes=256 * 1024,
        )
    except Exception as exc:
        ep.tested = False
        ep.test_note = f"Request failed: {exc}"
        return

    ep.tested = True
    ep.status_code = resp.status_code
    ep.content_type = resp.content_type
    ep.cors = _extract_cors(resp.headers)
    _check_cors_finding(ep, outcome)

    if resp.status_code == 401:
        ep.auth_observation = "unauthorized"
        return
    if resp.status_code == 403:
        ep.auth_observation = "forbidden"
        return
    if resp.status_code in (301, 302, 303, 307, 308):
        loc = resp.header("location") or ""
        ep.auth_observation = "redirect_to_login" if "login" in loc.lower() or "signin" in loc.lower() else "redirect_other"
        return
    if resp.status_code == 404 or baseline.matches_spa_shell(resp):
        ep.auth_observation = "not_found"
        return
    if resp.status_code >= 500:
        ep.auth_observation = "error"
        return

    if resp.status_code == 200:
        body = resp.text
        ep.sample_body = redact_text(body[:400])
        ep.auth_observation = "public_content"
        ep.evidence.append(
            {
                "type": "http_response",
                "detail": f"Unauthenticated GET returned HTTP 200 ({ep.content_type}, {len(resp.body)} bytes)",
                "location": ep.url,
                "snippet": ep.sample_body,
            }
        )

        if SENSITIVE_JSON_KEYS_RE.search(body):
            outcome.findings.append(
                FindingDraft(
                    rule_id="API-SENSITIVE-FIELDS-EXPOSED",
                    title=f"API endpoint {ep.path_template} returns sensitive credential or secret fields without authentication",
                    category="api_security",
                    severity="critical",
                    status="confirmed",
                    confidence=0.95,
                    affected=ep.url,
                    evidence=list(ep.evidence),
                    detection_method="Unauthenticated GET request + JSON field inspection",
                    impact="Exposes credential hashes, tokens, or secret keys directly in an unauthenticated API response.",
                    reproduction=[f"curl -i -s {ep.url}"],
                    remediation="Require authentication and explicitly exclude secret/hash columns via DTOs or select projections before serializing records.",
                )
            )


def _extract_cors(headers: dict[str, str]) -> dict:
    acao = headers.get("access-control-allow-origin")
    acac = headers.get("access-control-allow-credentials", "").lower() == "true"
    reflects = acao == "https://vibescan-cors-probe.invalid"
    return {
        "allow_origin": acao,
        "allow_credentials": acac,
        "reflects_origin": reflects,
    }


def _check_cors_finding(ep: DiscoveredEndpoint, outcome: ApiDiscoveryOutcome) -> None:
    if ep.cors.get("reflects_origin") and ep.cors.get("allow_credentials"):
        outcome.findings.append(
            FindingDraft(
                rule_id="API-CORS-CREDENTIALED-REFLECTION",
                title=f"API endpoint {ep.path_template} reflects arbitrary Origin with Access-Control-Allow-Credentials: true",
                category="api_security",
                severity="high",
                status="confirmed",
                confidence=0.96,
                affected=ep.url,
                evidence=[
                    {
                        "type": "cors_headers",
                        "detail": "Sent Origin: https://vibescan-cors-probe.invalid and received matching Access-Control-Allow-Origin with Access-Control-Allow-Credentials: true",
                        "location": ep.url,
                    }
                ],
                detection_method="Safe GET/OPTIONS request with synthetic Origin header",
                impact="Any malicious website visited by a logged-in user can issue cross-origin credentialed requests and read private API responses.",
                reproduction=[f"curl -i -s -H 'Origin: https://example.org' {ep.url}"],
                remediation="Validate Origin against a strict allowlist of trusted frontend domains instead of reflecting the incoming Origin header.",
            )
        )
