"""Configuration exposure, secret detection, source maps, security headers, and BaaS audits (Module D).

Enforces:
- Public identifiers (Supabase anon key, Stripe publishable key, Firebase project config) are reported
  as ``informational`` (or ``low`` for unrestricted Google API keys), never as leaked secrets.
- Actual secrets (service_role JWT, sk_live_*, OpenAI/Anthropic/AWS/GitHub keys, DB connection strings,
  private keys) are reported as ``confirmed`` with ``critical``/``high`` severity and masked values.
- Probed config files (``.env``, ``.git/HEAD``, ``firebase.json``, ``supabase/config.toml``) are verified
  against content signatures AND the SPA baseline to eliminate SPA soft-404 false positives.
- Optional Supabase anonymous table-read check runs ONLY when the target owner has explicitly enabled
  the Supabase integration on the target, and uses ``HEAD /rest/v1/<table>?select=*&limit=1`` with
  ``Prefer: count=exact`` so zero row data is ever retrieved.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from app.core.redaction import redact_text
from app.scanner.baseline import BaselineProfile
from app.scanner.crawler import CrawlOutcome
from app.scanner.findings import FindingDraft
from app.scanner.http import SafeHttpClient, SafeResponse
from app.scanner.scope import ScopePolicy
from app.scanner.secrets import SecretMatch, detect_secrets

DOTENV_LINE_RE = re.compile(r"^\s*(?:export\s+)?[A-Z][A-Z0-9_]{2,60}\s*=\s*\S+", re.MULTILINE)
INTERNAL_URL_RE = re.compile(
    r"""https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|[a-z0-9-]+\.(?:internal|local|svc\.cluster\.local))(?::\d{2,5})?(?:/[^\s"'`<>)]*)?""",
    re.IGNORECASE,
)
STACK_TRACE_RE = re.compile(
    r"(?:Traceback \(most recent call last\):|ReferenceError:|TypeError:|SyntaxError:|PrismaClientKnownRequestError|PostgresError|SequelizeDatabaseError|at\s+[A-Za-z0-9_.$<>]+\s+\((?:/app/|/var/|/home/|/Users/|webpack-internal:)[^)]+\))",
)


@dataclass
class RecoveredSourceFile:
    virtual_path: str
    content: str
    origin_map_url: str


@dataclass
class ConfigExposureOutcome:
    findings: list[FindingDraft] = field(default_factory=list)
    exposed_source_maps: dict[str, str] = field(default_factory=dict)  # asset_url -> map_url
    recovered_sources: list[RecoveredSourceFile] = field(default_factory=list)


async def run_config_exposure_audit(
    client: SafeHttpClient,
    scope: ScopePolicy,
    crawl: CrawlOutcome,
    baseline: BaselineProfile,
    *,
    supabase_integration: dict | None = None,
) -> ConfigExposureOutcome:
    outcome = ConfigExposureOutcome()

    # 1. Probe sensitive configuration artifacts (strictly validated against content signatures + SPA baseline)
    await _probe_config_files(client, scope, baseline, outcome)

    # 2. Check JavaScript source maps and recover original sources for static analysis
    await _check_source_maps(client, scope, crawl, baseline, outcome)

    # 3. Scan HTML pages and JS bundles for secrets, internal service URLs, and verbose stack traces
    _scan_responses_and_assets_for_secrets(crawl, outcome)

    # 4. Evaluate security headers on the primary HTML entry response
    _evaluate_security_headers(scope, crawl, outcome)

    # 5. Specialized BaaS integrations: Supabase, Firebase, Appwrite
    await _audit_baas_configurations(client, scope, crawl, supabase_integration, outcome)

    return outcome


async def _probe_config_files(
    client: SafeHttpClient,
    scope: ScopePolicy,
    baseline: BaselineProfile,
    outcome: ConfigExposureOutcome,
) -> None:
    base = scope.base_url.rstrip("/")
    probes: tuple[tuple[str, str], ...] = (
        ("/.env", "dotenv"),
        ("/.env.local", "dotenv"),
        ("/.env.production", "dotenv"),
        ("/.git/HEAD", "git_head"),
        ("/firebase.json", "firebase_json"),
        ("/firestore.rules", "firestore_rules"),
        ("/supabase/config.toml", "supabase_toml"),
        ("/debug", "debug_endpoint"),
        ("/api/debug", "debug_endpoint"),
        ("/api/env", "debug_endpoint"),
    )
    for path, kind in probes:
        url = f"{base}{path}"
        if not scope.is_in_scope(url, for_asset=True):
            continue
        try:
            resp = await client.get(url, follow_redirects=False, for_asset=True, max_bytes=256 * 1024)
        except Exception:
            continue
        if resp.status_code != 200 or baseline.matches_spa_shell(resp):
            continue
        ct = (resp.content_type or "").lower()
        body = resp.text

        if kind == "dotenv":
            if "html" in ct or body.lstrip().startswith("<"):
                continue
            matches = DOTENV_LINE_RE.findall(body)
            if len(matches) >= 1:
                keys = [m.split("=", 1)[0].strip() for m in matches[:15]]
                outcome.findings.append(
                    FindingDraft(
                        rule_id="CFG-DOTENV-EXPOSED",
                        title=f"Environment configuration file exposed at {path}",
                        category="configuration_exposure",
                        severity="critical",
                        status="confirmed",
                        confidence=0.98,
                        affected=url,
                        evidence=[
                            {
                                "type": "config_file",
                                "detail": f"HTTP 200 text response defining environment keys: {', '.join(keys)}",
                                "location": url,
                                "snippet": redact_text(body[:400]),
                            }
                        ],
                        detection_method="Direct GET request with content-signature verification against SPA baseline",
                        impact="Attackers can read environment variables, backend URLs, and credentials directly from the web root.",
                        reproduction=[f"curl -i -s {url} | head -n 5"],
                        remediation="Block dotfiles at the web server / CDN layer, remove .env files from public build directories, and rotate all exposed secrets immediately.",
                    )
                )
        elif kind == "git_head":
            if body.startswith("ref: refs/heads/") or re.match(r"^[0-9a-f]{40}\s*$", body):
                outcome.findings.append(
                    FindingDraft(
                        rule_id="CFG-GIT-EXPOSED",
                        title="Git repository metadata (.git/HEAD) is publicly accessible",
                        category="configuration_exposure",
                        severity="high",
                        status="confirmed",
                        confidence=0.99,
                        affected=url,
                        evidence=[
                            {
                                "type": "git_head",
                                "detail": f".git/HEAD returned valid Git ref: {body.strip()[:80]}",
                                "location": url,
                            }
                        ],
                        detection_method="Direct GET request for /.git/HEAD validated against Git reference syntax",
                        impact="Attackers can reconstruct the application's source code and commit history, including previously committed secrets.",
                        reproduction=[f"curl -i -s {url}"],
                        remediation="Deny access to /.git/ in your web server or hosting configuration and redeploy clean build artifacts only.",
                    )
                )
        elif kind == "firestore_rules":
            if "rules_version" in body and "service cloud.firestore" in body:
                permissive = bool(re.search(r"allow\s+read\s*,\s*write\s*:\s*if\s+true\b", body))
                outcome.findings.append(
                    FindingDraft(
                        rule_id="CFG-FIRESTORE-RULES-EXPOSED",
                        title="Firestore security rules file is publicly accessible"
                        + (" and contains permissive allow if true rules" if permissive else ""),
                        category="database_policy" if permissive else "configuration_exposure",
                        severity="high" if permissive else "low",
                        status="confirmed",
                        confidence=0.95,
                        affected=url,
                        evidence=[
                            {
                                "type": "firestore_rules",
                                "detail": "Publicly accessible firestore.rules file",
                                "location": url,
                                "snippet": redact_text(body[:360]),
                            }
                        ],
                        detection_method="GET /firestore.rules + static rule inspection",
                        impact="Exposes database security logic; permissive 'if true' rules allow unauthenticated read/write access to Firestore collections.",
                        reproduction=[f"curl -i -s {url}"],
                        remediation="Remove firestore.rules from public static hosting and enforce request.auth != null and resource ownership checks on every collection.",
                    )
                )
        elif kind == "debug_endpoint":
            if "json" in ct and any(k in body for k in ('"env"', '"NODE_ENV"', '"DATABASE_URL"', '"headers"', '"process"')):
                outcome.findings.append(
                    FindingDraft(
                        rule_id="CFG-DEBUG-ENDPOINT",
                        title=f"Development/debug endpoint exposed at {path}",
                        category="configuration_exposure",
                        severity="high",
                        status="confirmed",
                        confidence=0.9,
                        affected=url,
                        evidence=[
                            {
                                "type": "debug_json",
                                "detail": f"Endpoint returned JSON with runtime/environment fields ({len(resp.body)} bytes)",
                                "location": url,
                                "snippet": redact_text(body[:300]),
                            }
                        ],
                        detection_method="Safe GET request to common debug endpoint path",
                        impact="Exposes server runtime state, environment configuration, or internal diagnostics to unauthenticated users.",
                        reproduction=[f"curl -i -s {url}"],
                        remediation="Disable or remove debug/environment dump routes in production builds.",
                    )
                )


async def _check_source_maps(
    client: SafeHttpClient,
    scope: ScopePolicy,
    crawl: CrawlOutcome,
    baseline: BaselineProfile,
    outcome: ConfigExposureOutcome,
) -> None:
    for asset_url, asset in list(crawl.assets.items()):
        if asset.kind != "js":
            continue
        ref = asset.js_analysis.source_map_ref if asset.js_analysis else None
        if ref and not ref.startswith("data:"):
            map_url = urljoin(asset_url, ref)
        else:
            map_url = f"{asset_url}.map"
        if not scope.is_in_scope(map_url, for_asset=True):
            continue
        try:
            m_resp = await client.get(map_url, follow_redirects=True, for_asset=True, max_bytes=4 * 1024 * 1024)
        except Exception:
            continue
        if m_resp.status_code != 200 or baseline.matches_spa_shell(m_resp):
            continue
        text = m_resp.text.lstrip()
        if not text.startswith("{") or '"sources"' not in text[:2000]:
            continue
        try:
            data = json.loads(text)
        except ValueError:
            continue
        if not isinstance(data, dict) or not isinstance(data.get("sources"), list):
            continue

        outcome.exposed_source_maps[asset_url] = map_url
        raw_sources = [str(s) for s in data.get("sources", [])]
        sources = raw_sources[:200]
        contents = data.get("sourcesContent") or []

        framework_hints = (
            "next/dist/",
            "webpack/runtime/",
            "webpack/bootstrap",
            "react-dom",
            "scheduler/",
            "core-js/",
            "regenerator-runtime",
            "@next/",
            "nuxt/",
            "vite/preload-helper",
        )
        third_party_sources: list[str] = []
        framework_sources: list[str] = []
        application_sources: list[str] = []
        for src in raw_sources:
            lower = src.lower()
            if any(h in lower for h in framework_hints):
                framework_sources.append(src)
            elif "node_modules/" in lower or "node_modules\\" in lower or lower.startswith("webpack://_n_e/node_modules"):
                third_party_sources.append(src)
            else:
                application_sources.append(src)

        embedded_count = sum(1 for c in contents if isinstance(c, str) and c.strip()) if isinstance(contents, list) else 0
        if embedded_count == 0:
            sm_classification = "empty_or_unavailable"
        elif application_sources and (third_party_sources or framework_sources):
            sm_classification = "mixed_application_and_third_party"
        elif application_sources:
            sm_classification = "application_source"
        elif framework_sources and not third_party_sources:
            sm_classification = "framework_only"
        else:
            sm_classification = "third_party_only"

        if isinstance(contents, list):
            for src_path, src_code in zip(sources, contents, strict=False):
                if isinstance(src_code, str) and src_code.strip() and "node_modules" not in src_path:
                    outcome.recovered_sources.append(
                        RecoveredSourceFile(
                            virtual_path=src_path,
                            content=src_code[:512 * 1024],
                            origin_map_url=map_url,
                        )
                    )

        has_app_code = bool(application_sources) and embedded_count > 0
        sm_severity = "medium" if has_app_code else ("info" if sm_classification in ("third_party_only", "framework_only", "empty_or_unavailable") else "low")
        sm_status = "confirmed" if has_app_code else "informational"
        sm_title = (
            "Production JavaScript source map exposes application source code"
            if has_app_code
            else f"Public JavaScript source map accessible ({sm_classification.replace('_', ' ')})"
        )
        sm_impact = (
            f"Exposes {len(application_sources)} application source file(s) with embedded code, allowing reconstruction of unminified business logic, comments, and internal route definitions."
            if has_app_code
            else "Source map is publicly reachable but contains only third-party/framework sources or no embedded sourcesContent; it does not demonstrate full application source disclosure."
        )

        sample_sources = ", ".join(application_sources[:5])[:180] or ", ".join(sources[:5])[:180]
        outcome.findings.append(
            FindingDraft(
                rule_id="CFG-SOURCEMAP-EXPOSED",
                title=sm_title,
                category="configuration_exposure",
                severity=sm_severity,
                status=sm_status,
                confidence=0.98,
                affected=map_url,
                evidence=[
                    {
                        "type": "source_map",
                        "detail": (
                            f"Source map for {asset_url} ({sm_classification}): "
                            f"total={len(raw_sources)}, app={len(application_sources)}, "
                            f"third_party={len(third_party_sources)}, framework={len(framework_sources)}, "
                            f"embedded={embedded_count} (e.g. {sample_sources})"
                        ),
                        "location": map_url,
                        "metadata": {
                            "total_sources": len(raw_sources),
                            "embedded_sources": embedded_count,
                            "application_sources": len(application_sources),
                            "third_party_sources": len(third_party_sources),
                            "framework_sources": len(framework_sources),
                            "source_map_url": map_url,
                            "original_js_url": asset_url,
                            "classification": sm_classification,
                        },
                    }
                ],
                detection_method="Resolved //# sourceMappingURL / .map suffix, validated SourceMap v3 JSON structure, and classified application vs third-party/framework sources",
                impact=sm_impact,
                reproduction=[f"curl -s {map_url} | head -c 300"],
                remediation="Disable public source maps in production builds (e.g. productionBrowserSourceMaps: false in Next.js or build.sourcemap: 'hidden' in Vite) and upload maps privately to your error tracker.",
            )
        )


def _scan_responses_and_assets_for_secrets(crawl: CrawlOutcome, outcome: ConfigExposureOutcome) -> None:
    targets_to_scan: list[tuple[str, str]] = []
    for url, resp in crawl.page_responses.items():
        if "html" in (resp.content_type or "").lower() or "json" in (resp.content_type or "").lower():
            targets_to_scan.append((url, resp.text))
    for url, asset in crawl.assets.items():
        if asset.kind == "js":
            targets_to_scan.append((url, asset.response.text))
    for rec in outcome.recovered_sources[:40]:
        targets_to_scan.append((f"{rec.origin_map_url}::{rec.virtual_path}", rec.content))

    for location, text in targets_to_scan:
        matches: list[SecretMatch] = detect_secrets(text, location)
        for m in matches:
            if m.kind == "public_identifier":
                status = "informational"
                cat = "configuration_exposure"
                rule_id = m.rule_id
            else:
                status = "confirmed" if m.severity in ("critical", "high") else "potential"
                cat = "secret_exposure"
                rule_id = "SEC-CRITICAL-EXPOSED" if m.severity == "critical" else ("SEC-HIGH-EXPOSED" if m.severity == "high" else m.rule_id)

            outcome.findings.append(
                FindingDraft(
                    rule_id=rule_id,
                    title=f"{m.name} detected in frontend asset" if m.kind == "public_identifier" else f"Exposed {m.name} in public frontend content",
                    category=cat,
                    severity=m.severity,
                    status=status,
                    confidence=0.92 if status != "potential" else 0.72,
                    affected=location,
                    discriminator=m.fingerprint,
                    evidence=[
                        {
                            "type": m.kind,
                            "detail": f"{m.name}: {m.masked} (fingerprint sha256:{m.fingerprint})"
                            + (f" — {m.note}" if m.note else ""),
                            "location": f"{location}:{m.line}" if m.line else location,
                            "snippet": m.snippet,
                        }
                    ],
                    detection_method=f"Pattern + entropy/JWT claims classification ({m.rule_id})",
                    impact=m.description + (" " + m.note if m.note else ""),
                    reproduction=[f"curl -s {location.split('::')[0]} | grep -n '<redacted-pattern>'"],
                    remediation=m.remediation,
                )
            )

        # Internal / localhost service URLs leaked into production bundles
        internal_urls = sorted(set(INTERNAL_URL_RE.findall(text)))
        if internal_urls:
            outcome.findings.append(
                FindingDraft(
                    rule_id="CFG-INTERNAL-URL-LEAK",
                    title="Internal or development service URLs referenced in frontend code",
                    category="configuration_exposure",
                    severity="low",
                    status="informational",
                    confidence=0.8,
                    affected=location,
                    evidence=[
                        {
                            "type": "internal_url",
                            "detail": f"Referenced non-public URLs: {', '.join(internal_urls[:5])}",
                            "location": location,
                        }
                    ],
                    detection_method="Static regex scan for RFC1918, loopback, and .internal/.local URLs",
                    impact="Reveals internal network topology or indicates a build misconfiguration where development endpoints were compiled into production bundles.",
                    reproduction=[f"Inspect {location} for internal hostname references"],
                    remediation="Ensure NEXT_PUBLIC_* / VITE_* environment variables point to production origins at build time.",
                )
            )

        # Verbose stack traces in HTML/JSON pages
        if not location.endswith(".js") and "::" not in location:
            st = STACK_TRACE_RE.search(text)
            if st:
                outcome.findings.append(
                    FindingDraft(
                        rule_id="CFG-VERBOSE-ERROR",
                        title="Verbose stack trace or internal file path disclosed in HTTP response",
                        category="information_disclosure",
                        severity="low",
                        status="confirmed",
                        confidence=0.88,
                        affected=location,
                        evidence=[
                            {
                                "type": "stack_trace",
                                "detail": f"Matched error signature {st.group(0)[:80]!r}",
                                "location": location,
                                "snippet": redact_text(text[max(0, st.start() - 40) : min(len(text), st.end() + 140)]),
                            }
                        ],
                        detection_method="Response body inspection for runtime stack trace signatures",
                        impact="Discloses internal filesystem paths, framework versions, and database driver details useful to attackers.",
                        reproduction=[f"curl -i -s {location}"],
                        remediation="Return generic error messages to clients in production and log stack traces server-side only.",
                    )
                )


def _evaluate_security_headers(scope: ScopePolicy, crawl: CrawlOutcome, outcome: ConfigExposureOutcome) -> None:
    root_resp: SafeResponse | None = crawl.page_responses.get(scope.base_url)
    if root_resp is None and crawl.page_responses:
        root_resp = next(iter(crawl.page_responses.values()))
    if root_resp is None:
        return

    missing: list[str] = []
    headers = root_resp.headers
    if "content-security-policy" not in headers:
        missing.append("Content-Security-Policy")
    if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", ""):
        missing.append("X-Frame-Options (or CSP frame-ancestors)")
    if headers.get("x-content-type-options", "").lower() != "nosniff":
        missing.append("X-Content-Type-Options: nosniff")
    if scope.base_url.startswith("https://") and "strict-transport-security" not in headers:
        missing.append("Strict-Transport-Security")
    if "referrer-policy" not in headers:
        missing.append("Referrer-Policy")

    if missing:
        outcome.findings.append(
            FindingDraft(
                rule_id="HDR-MISSING-SECURITY-HEADERS",
                title="Missing defensive HTTP security headers on application entry point",
                category="security_headers",
                severity="low",
                status="informational",
                confidence=0.95,
                affected=root_resp.final_url,
                evidence=[
                    {
                        "type": "headers",
                        "detail": f"Missing headers: {', '.join(missing)}",
                        "location": root_resp.final_url,
                    }
                ],
                detection_method="Passive inspection of HTTP response headers on primary application URL",
                impact="Reduces defense-in-depth against XSS, clickjacking, MIME sniffing, and protocol downgrade attacks.",
                reproduction=[f"curl -I -s {root_resp.final_url}"],
                remediation="Configure Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options: nosniff, X-Frame-Options: DENY, and Referrer-Policy in your framework or CDN headers.",
            )
        )


async def _audit_baas_configurations(
    client: SafeHttpClient,
    scope: ScopePolicy,
    crawl: CrawlOutcome,
    supabase_integration: dict | None,
    outcome: ConfigExposureOutcome,
) -> None:
    supa_urls = sorted({u for jr in crawl.js_results for u in jr.supabase_urls})
    supa_tables = sorted({t for jr in crawl.js_results for t in jr.supabase_tables})
    supa_rpcs = sorted({fn for jr in crawl.js_results for fn in jr.supabase_rpcs})
    fb_projects = sorted({p["project_id"] for jr in crawl.js_results for p in jr.firebase_projects})
    fs_collections = sorted({c for jr in crawl.js_results for c in jr.firestore_collections})
    aw_projects = sorted({p for jr in crawl.js_results for p in crawl.js_results for p in jr.appwrite_projects})
    aw_endpoints = sorted({e for jr in crawl.js_results for e in jr.appwrite_endpoints})

    if supa_urls or supa_tables:
        outcome.findings.append(
            FindingDraft(
                rule_id="CFG-SUPABASE-CLIENT-SURFACE",
                title="Supabase client configuration and direct table queries identified in frontend",
                category="configuration_exposure",
                severity="info",
                status="informational",
                confidence=0.95,
                affected=supa_urls[0] if supa_urls else scope.base_url,
                evidence=[
                    {
                        "type": "supabase_surface",
                        "detail": f"Project URLs: {supa_urls or ['(relative)']}; tables queried via .from(): {supa_tables or ['none']}; RPCs: {supa_rpcs or ['none']}",
                        "location": scope.base_url,
                    }
                ],
                detection_method="Static analysis of frontend JS bundles for Supabase SDK calls",
                impact="Direct browser-to-PostgREST table access is normal for Supabase apps, but every exposed table and RPC relies strictly on PostgreSQL Row Level Security (RLS) policies.",
                reproduction=["Inspect frontend bundle for .from('<table_name>') calls"],
                remediation="Verify that ALTER TABLE ... ENABLE ROW LEVEL SECURITY is enabled on every public table and that policies enforce auth.uid() ownership checks.",
            )
        )

    # Opt-in owner-authorized Supabase anonymous RLS check (HEAD only, zero row data retrieved)
    if supabase_integration and supabase_integration.get("enabled") and supabase_integration.get("project_url") and supabase_integration.get("anon_key") and supa_tables:
        proj_url = str(supabase_integration["project_url"]).rstrip("/")
        anon_key = str(supabase_integration["anon_key"])
        proj_host = urlparse(proj_url).hostname or ""

        def _validate_supa_url(u: str) -> None:
            p = urlparse(u)
            if p.scheme != "https" or (p.hostname or "").lower() != proj_host.lower():
                from app.scanner.scope import OutOfScopeError

                raise OutOfScopeError(u, "URL does not match owner-configured Supabase project host")

        for table in supa_tables[:15]:
            probe_url = f"{proj_url}/rest/v1/{table}?select=*&limit=1"
            try:
                resp = await client.head(
                    probe_url,
                    headers={
                        "apikey": anon_key,
                        "Authorization": f"Bearer {anon_key}",
                        "Prefer": "count=exact",
                    },
                    follow_redirects=False,
                    allow_cross_host_Validate=_validate_supa_url,
                )
            except Exception:
                continue
            content_range = resp.header("content-range") or ""
            # PostgREST Content-Range format: "0-0/42" or "*/0"
            total_rows = 0
            if "/" in content_range:
                tail = content_range.split("/", 1)[1].strip()
                if tail.isdigit():
                    total_rows = int(tail)
            if resp.status_code in (200, 206) and total_rows > 0:
                outcome.findings.append(
                    FindingDraft(
                        rule_id="CFG-SUPABASE-ANON-TABLE-READ",
                        title=f"Supabase table '{table}' allows unauthenticated anonymous read access ({total_rows} rows visible)",
                        category="database_policy",
                        severity="high",
                        status="confirmed",
                        confidence=0.95,
                        affected=f"{proj_url}/rest/v1/{table}",
                        evidence=[
                            {
                                "type": "postgrest_head_count",
                                "detail": f"HEAD /rest/v1/{table} with owner-supplied anon key returned HTTP {resp.status_code} and Content-Range: {content_range} (no row data was downloaded)",
                                "location": f"{proj_url}/rest/v1/{table}",
                            }
                        ],
                        detection_method="Authorized non-destructive HEAD request with Prefer: count=exact against owner-configured Supabase project",
                        impact=f"Any anonymous visitor can read {total_rows} rows from table '{table}' using the public anon key embedded in the frontend.",
                        reproduction=[
                            f"curl -I -s '{proj_url}/rest/v1/{table}?select=*&limit=1' -H 'apikey: <ANON_KEY>' -H 'Prefer: count=exact'"
                        ],
                        remediation=f"Enable Row Level Security (`ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY;`) and restrict SELECT policies to authenticated owners (`USING (auth.uid() = user_id)`).",
                    )
                )

    if fb_projects or fs_collections:
        outcome.findings.append(
            FindingDraft(
                rule_id="CFG-FIREBASE-CLIENT-SURFACE",
                title="Firebase project configuration and Firestore collections detected in frontend",
                category="configuration_exposure",
                severity="info",
                status="informational",
                confidence=0.9,
                affected=scope.base_url,
                evidence=[
                    {
                        "type": "firebase_surface",
                        "detail": f"Firebase projectId(s): {fb_projects}; referenced Firestore collections: {fs_collections or ['none']}",
                        "location": scope.base_url,
                    }
                ],
                detection_method="Static analysis of frontend JS bundles for Firebase config and collection() calls",
                impact="Firebase client configuration is public by design, but security depends completely on Firestore / Storage Security Rules and Firebase App Check.",
                reproduction=["Inspect frontend bundle for firebaseConfig and collection(db, '...') calls"],
                remediation="Audit firestore.rules and storage.rules to ensure no collection allows unauthenticated read/write unless explicitly intended as public.",
            )
        )

    if aw_projects or aw_endpoints:
        outcome.findings.append(
            FindingDraft(
                rule_id="CFG-APPWRITE-CLIENT-SURFACE",
                title="Appwrite client endpoint and project identifier detected in frontend",
                category="configuration_exposure",
                severity="info",
                status="informational",
                confidence=0.9,
                affected=aw_endpoints[0] if aw_endpoints else scope.base_url,
                evidence=[
                    {
                        "type": "appwrite_surface",
                        "detail": f"Appwrite endpoints: {aw_endpoints}; project IDs: {aw_projects}",
                        "location": scope.base_url,
                    }
                ],
                detection_method="Static analysis of frontend JS bundles for Appwrite setEndpoint/setProject calls",
                impact="Appwrite project IDs are public client identifiers; collection and bucket access must be restricted via Appwrite collection/document permissions.",
                reproduction=["Inspect frontend bundle for .setEndpoint(...) and .setProject(...)"],
                remediation="Review Appwrite collection, bucket, and function permissions to ensure 'Role.any()' is not granted read/write access to private data.",
            )
        )
