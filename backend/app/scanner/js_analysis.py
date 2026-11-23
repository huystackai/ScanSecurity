"""Static analysis of frontend JavaScript bundles, inline scripts, and Next.js manifests.

Extracts:
- Client-side route declarations (React Router, Next.js App/Pages router, Vue Router, Nuxt, SvelteKit, TanStack Router)
- Referenced API endpoints (``fetch``, ``axios``, ``useSWR``, ``useQuery``, GraphQL, WebSockets, Next Server Actions)
- Supabase ``.from('table')`` and ``.rpc('fn')`` calls, Supabase project URLs
- Firebase config objects and Appwrite ``setEndpoint`` / ``setProject`` calls
- Client-side-only access control patterns (e.g. ``localStorage.getItem('isAdmin')``, ``user?.role === 'admin'``)
- Source map references (``//# sourceMappingURL=...``)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Client-side route patterns in bundled/unbundled JS
ROUTER_PATH_PATTERNS: tuple[re.Pattern[str], ...] = (
    # React Router / Vue Router / TanStack Router object style: { path: "/admin/users" }
    re.compile(r"""\bpath\s*:\s*["'`](/(?:[A-Za-z0-9_.:*-]+/?){1,8})["'`]"""),
    # JSX <Route path="/admin" />
    re.compile(r"""\bRoute\b[^>]{0,120}?\bpath\s*=\s*["'`](/(?:[A-Za-z0-9_.:*-]+/?){1,8})["'`]"""),
    # Next.js / React Router navigate/push/href literals pointing to app routes
    re.compile(
        r"""\b(?:href|to|pathname|redirect|navigate|router\.push|router\.replace)\s*[:=(]\s*["'`](/(?:admin|dashboard|manage|management|settings|users|roles|permissions|config|system|internal|superadmin|control|console|workflows|agents|webhooks|api-keys|feature-flags|billing|audit|logs|monitoring|database|storage|studio|cms|backoffice|portal|staff|moderator|ops|debug|dev)(?:/[A-Za-z0-9_.:*-]*)*)["'`]""",
        re.IGNORECASE,
    ),
    # Next.js _buildManifest / page maps: "/admin/users": ["static/chunks/..."]
    re.compile(r"""["'`](/(?:[A-Za-z0-9_\[\].-]+/?){1,8})["'`]\s*:\s*\[\s*["'`]static/"""),
)

# API endpoint call patterns
API_CALL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "fetch",
        re.compile(
            r"""\bfetch\s*\(\s*["'`]((?:https?://[A-Za-z0-9._:-]+)?/(?:api|v[1-9]|graphql|trpc|rpc|rest/v1|auth/v1|storage/v1|functions/v1|webhooks?|internal|admin)[A-Za-z0-9_./:${}-]*)["'`]"""
        ),
    ),
    (
        "axios",
        re.compile(
            r"""\b(?:axios|http|api|client)\s*\.\s*(get|post|put|patch|delete|head|options)\s*\(\s*["'`]((?:https?://[A-Za-z0-9._:-]+)?/[A-Za-z0-9_./:${}-]{2,140})["'`]""",
            re.IGNORECASE,
        ),
    ),
    (
        "api_path_literal",
        re.compile(
            r"""["'`](/(?:api|trpc|graphql|rest/v1|functions/v1|webhooks|internal-api)(?:/[A-Za-z0-9_.:${}\[\]-]+){1,8})["'`]"""
        ),
    ),
)

SUPABASE_URL_RE = re.compile(r"""https://([a-z0-9]{15,24})\.supabase\.(?:co|in)""")
SUPABASE_FROM_RE = re.compile(r"""\.from\(\s*["'`]([A-Za-z0-9_]{2,64})["'`]\s*\)""")
SUPABASE_RPC_RE = re.compile(r"""\.rpc\(\s*["'`]([A-Za-z0-9_]{2,64})["'`]""")
SUPABASE_STORAGE_RE = re.compile(r"""\.storage\s*\.\s*from\(\s*["'`]([A-Za-z0-9_.-]{2,64})["'`]\s*\)""")

FIREBASE_CONFIG_RE = re.compile(
    r"""\{[^{}]{0,600}?\bapiKey\s*:\s*["'`](AIza[0-9A-Za-z_-]{35})["'`][^{}]{0,600}?\bprojectId\s*:\s*["'`]([a-z0-9-]{4,40})["'`][^{}]{0,600}?\}""",
    re.DOTALL,
)
FIREBASE_AUTH_DOMAIN_RE = re.compile(r"""\b([a-z0-9-]{4,40})\.firebaseapp\.com\b""")
FIRESTORE_COLLECTION_RE = re.compile(r"""\bcollection\(\s*[^,)]+,\s*["'`]([A-Za-z0-9_-]{2,64})["'`]""")

APPWRITE_ENDPOINT_RE = re.compile(r"""\.setEndpoint\(\s*["'`](https?://[^"'`\s]{4,200})["'`]\s*\)""")
APPWRITE_PROJECT_RE = re.compile(r"""\.setProject\(\s*["'`]([A-Za-z0-9_-]{4,64})["'`]\s*\)""")

SOURCEMAP_RE = re.compile(r"""//[#@]\s*sourceMappingURL\s*=\s*(\S+)""")

# Client-side-only access control / role patterns in JS bundles
CLIENT_AUTH_GUARD_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    (
        "CS-LOCALSTORAGE-ROLE",
        "Role or admin flag read from browser storage",
        re.compile(
            r"""(?:localStorage|sessionStorage)\s*\.\s*getItem\(\s*["'`](?:role|userRole|isAdmin|is_admin|admin|permissions|accessLevel|isSuperAdmin)["'`]\s*\)"""
        ),
    ),
    (
        "CS-CLIENT-ROLE-CHECK",
        "Client-side admin role check guarding UI or route",
        re.compile(
            r"""\b(?:user|profile|session|currentUser|account|claims)\s*(?:\?\.)?\s*(?:role|user_role|isAdmin|is_admin|isSuperAdmin)\s*===\s*["'`](?:admin|superadmin|super_admin|owner|staff)["'`]|\b(?:isAdmin|is_admin|isSuperAdmin)\s*===\s*true"""
        ),
    ),
    (
        "CS-HARDCODED-ADMIN-EMAIL",
        "Hardcoded administrator email check in frontend bundle",
        re.compile(
            r"""\b(?:email|user\.email|session\.user\.email)\s*===\s*["'`][A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}["'`]"""
        ),
    ),
)

IGNORED_ROUTE_PREFIXES = (
    "/static/",
    "/_next/",
    "/_nuxt/",
    "/assets/",
    "/images/",
    "/img/",
    "/fonts/",
    "/favicon",
    "/manifest",
    "/http:",
    "/https:",
    "//",
)
IGNORED_EXTENSIONS = (
    ".js",
    ".mjs",
    ".css",
    ".map",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".webp",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
)


def _is_plausible_route(path: str) -> bool:
    if not path or not path.startswith("/") or len(path) > 160:
        return False
    low = path.lower()
    if any(low.startswith(p) for p in IGNORED_ROUTE_PREFIXES):
        return False
    if any(low.endswith(ext) for ext in IGNORED_EXTENSIONS):
        return False
    if " " in path or "\n" in path or "\t" in path:
        return False
    return True


@dataclass
class DiscoveredApiRef:
    path_or_url: str
    method: str
    source_location: str
    snippet: str


@dataclass
class ClientAuthPatternMatch:
    rule_id: str
    title: str
    source_location: str
    snippet: str


@dataclass
class JsAnalysisResult:
    source_url: str
    routes: list[str] = field(default_factory=list)
    api_refs: list[DiscoveredApiRef] = field(default_factory=list)
    supabase_urls: list[str] = field(default_factory=list)
    supabase_tables: list[str] = field(default_factory=list)
    supabase_rpcs: list[str] = field(default_factory=list)
    supabase_buckets: list[str] = field(default_factory=list)
    firebase_projects: list[dict] = field(default_factory=list)
    firestore_collections: list[str] = field(default_factory=list)
    appwrite_endpoints: list[str] = field(default_factory=list)
    appwrite_projects: list[str] = field(default_factory=list)
    client_auth_patterns: list[ClientAuthPatternMatch] = field(default_factory=list)
    source_map_ref: str | None = None


def analyze_javascript(code: str, source_url: str) -> JsAnalysisResult:
    from app.core.redaction import redact_text

    res = JsAnalysisResult(source_url=source_url)
    if not code:
        return res

    sm = SOURCEMAP_RE.findall(code)
    if sm:
        res.source_map_ref = sm[-1].strip()

    seen_routes: set[str] = set()
    for pat in ROUTER_PATH_PATTERNS:
        for m in pat.finditer(code):
            candidate = m.group(1).strip()
            if _is_plausible_route(candidate) and candidate not in seen_routes:
                seen_routes.add(candidate)
                res.routes.append(candidate)

    seen_apis: set[tuple[str, str]] = set()
    explicit_verb_targets: set[str] = set()
    for kind, pat in API_CALL_PATTERNS:
        for m in pat.finditer(code):
            if kind == "axios":
                method = m.group(1).upper()
                target = m.group(2).strip()
                explicit_verb_targets.add(target)
            elif kind == "fetch":
                target = m.group(1).strip()
                after = code[m.end() : min(len(code), m.end() + 180)]
                m_verb = re.search(r"""\bmethod\s*:\s*["'`](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)["'`]""", after, re.I)
                method = m_verb.group(1).upper() if m_verb else "GET"
                explicit_verb_targets.add(target)
            else:
                target = m.group(1).strip()
                if target in explicit_verb_targets:
                    continue
                method = "GET"
            if not _is_plausible_route(target) and not target.startswith(("http://", "https://")):
                continue
            key = (method, target)
            if key in seen_apis:
                continue
            seen_apis.add(key)
            start, end = m.span()
            snippet = redact_text(code[max(0, start - 30) : min(len(code), end + 30)], max_len=180)
            res.api_refs.append(
                DiscoveredApiRef(path_or_url=target, method=method, source_location=source_url, snippet=snippet)
            )

    for m in SUPABASE_URL_RE.finditer(code):
        u = m.group(0)
        if u not in res.supabase_urls:
            res.supabase_urls.append(u)
    for m in SUPABASE_FROM_RE.finditer(code):
        t = m.group(1)
        if t not in res.supabase_tables:
            res.supabase_tables.append(t)
    for m in SUPABASE_RPC_RE.finditer(code):
        fn = m.group(1)
        if fn not in res.supabase_rpcs:
            res.supabase_rpcs.append(fn)
    for m in SUPABASE_STORAGE_RE.finditer(code):
        b = m.group(1)
        if b not in res.supabase_buckets:
            res.supabase_buckets.append(b)

    seen_fb: set[str] = set()
    for m in FIREBASE_CONFIG_RE.finditer(code):
        proj_id = m.group(2)
        if proj_id not in seen_fb:
            seen_fb.add(proj_id)
            res.firebase_projects.append({"project_id": proj_id, "source": source_url})
    for m in FIREBASE_AUTH_DOMAIN_RE.finditer(code):
        proj_id = m.group(1)
        if proj_id not in seen_fb:
            seen_fb.add(proj_id)
            res.firebase_projects.append({"project_id": proj_id, "source": source_url})
    for m in FIRESTORE_COLLECTION_RE.finditer(code):
        col = m.group(1)
        if col not in res.firestore_collections:
            res.firestore_collections.append(col)

    for m in APPWRITE_ENDPOINT_RE.finditer(code):
        ep = m.group(1)
        if ep not in res.appwrite_endpoints:
            res.appwrite_endpoints.append(ep)
    for m in APPWRITE_PROJECT_RE.finditer(code):
        pid = m.group(1)
        if pid not in res.appwrite_projects:
            res.appwrite_projects.append(pid)

    for rule_id, title, pat in CLIENT_AUTH_GUARD_PATTERNS:
        for m in pat.finditer(code):
            start, end = m.span()
            snippet = redact_text(code[max(0, start - 40) : min(len(code), end + 40)], max_len=200)
            res.client_auth_patterns.append(
                ClientAuthPatternMatch(rule_id=rule_id, title=title, source_location=source_url, snippet=snippet)
            )
            break

    return res
