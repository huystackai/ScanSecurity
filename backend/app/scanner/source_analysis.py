"""Source code security analysis engine (Module F).

Capabilities:
1. Safe ZIP archive extraction & inspection in memory / isolated temp directory:
   - Enforces zip-slip path traversal rejection, symlink rejection, total file count limit,
     per-file size limit, and total uncompressed byte limit (zip-bomb protection).
   - Never executes any uploaded file.
2. Frontend insecure pattern rules:
   - Admin route guarded only by React state / client variable
   - Role or admin flag trusted from ``localStorage`` / ``sessionStorage``
   - Sensitive server secrets referenced via ``NEXT_PUBLIC_*`` / ``VITE_*`` / ``REACT_APP_*``
   - Hidden buttons / conditional JSX mistaken for access control
   - Unsanitized ``dangerouslySetInnerHTML`` / ``v-html``
3. Backend insecure pattern rules:
   - Next.js App Router / Pages API / Express / FastAPI administrative or mutating handlers missing
     authentication or role validation
   - Direct object lookup from request params without ownership constraint
   - Unsafe verbose error response serializing ``err.stack`` / full exception tracebacks
   - Insecure file upload handler without file type or size validation
   - Hardcoded secrets and credentials (via ``detect_secrets``)
4. Database & BaaS policy rules:
   - PostgreSQL / Supabase SQL migrations: ``CREATE TABLE public.<name>`` without corresponding
     ``ALTER TABLE ... ENABLE ROW LEVEL SECURITY``, or ``CREATE POLICY`` with ``USING (true)`` /
     ``WITH CHECK (true)`` on non-public tables
   - Firebase ``firestore.rules`` / ``storage.rules``: ``allow read, write: if true`` or missing
     ``request.auth != null``
5. Optional Semgrep integration when the ``semgrep`` binary is installed on the host.
"""

from __future__ import annotations

import asyncio
import io
import json
import posixpath
import re
import shutil
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

from app.config import get_settings
from app.core.redaction import redact_text
from app.scanner.config_exposure import RecoveredSourceFile
from app.scanner.findings import FindingDraft
from app.scanner.secrets import detect_secrets

TEXT_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".vue",
        ".svelte",
        ".py",
        ".sql",
        ".rules",
        ".json",
        ".toml",
        ".yaml",
        ".yml",
        ".env",
        ".example",
        ".prisma",
    }
)

IGNORED_DIRS: frozenset[str] = frozenset(
    {"node_modules", ".git", ".next", ".nuxt", "dist", "build", ".venv", "venv", "__pycache__", "coverage"}
)


class UnsafeArchiveError(Exception):
    """Raised when an uploaded ZIP archive violates safety constraints."""


@dataclass
class SourceFileEntry:
    rel_path: str
    content: str


def extract_safe_zip_entries(
    zip_bytes: bytes,
    *,
    max_files: int = 20000,
    max_total_bytes: int = 300 * 1024 * 1024,
    max_single_file_bytes: int = 2 * 1024 * 1024,
) -> tuple[list[SourceFileEntry], int]:
    """Validate a ZIP archive against zip-slip, symlinks, and zip-bombs and return text source entries."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except zipfile.BadZipFile as exc:
        raise UnsafeArchiveError("Uploaded file is not a valid ZIP archive") from exc

    infos = zf.infolist()
    if len(infos) > max_files:
        raise UnsafeArchiveError(f"Archive contains {len(infos)} entries (limit {max_files})")

    total_uncompressed = 0
    entries: list[SourceFileEntry] = []
    file_count = 0

    for info in infos:
        raw_name = info.filename.replace("\\", "/")
        if raw_name.startswith("/") or ".." in raw_name.split("/"):
            raise UnsafeArchiveError(f"Archive contains unsafe path traversal entry: {info.filename!r}")
        norm = posixpath.normpath(raw_name)
        if norm.startswith(("..", "/")):
            raise UnsafeArchiveError(f"Archive contains unsafe normalized path: {norm!r}")
        # Reject Unix symlinks (mode 0o120000 in external_attr >> 16)
        mode = (info.external_attr >> 16) & 0o170000
        if mode == 0o120000:
            raise UnsafeArchiveError(f"Archive contains a symbolic link entry: {info.filename!r}")
        if info.is_dir():
            continue

        file_count += 1
        total_uncompressed += info.file_size
        if total_uncompressed > max_total_bytes:
            raise UnsafeArchiveError(f"Archive uncompressed size exceeds limit ({max_total_bytes} bytes)")

        parts = [p for p in norm.split("/") if p]
        if any(p in IGNORED_DIRS for p in parts):
            continue
        if info.file_size > max_single_file_bytes:
            continue

        base_name = parts[-1].lower() if parts else ""
        ext = posixpath.splitext(base_name)[1]
        is_env = base_name.startswith(".env")
        is_rules = base_name.endswith(".rules")
        if ext not in TEXT_EXTENSIONS and not is_env and not is_rules:
            continue

        raw_bytes = zf.read(info)
        if len(raw_bytes) > max_single_file_bytes:
            raise UnsafeArchiveError(f"Entry {norm!r} exceeded declared size limit")
        if b"\x00" in raw_bytes[:1024]:
            continue  # skip binary files
        entries.append(SourceFileEntry(rel_path=norm, content=raw_bytes.decode("utf-8", errors="replace")))

    return entries, file_count


@dataclass(frozen=True)
class SourcePatternRule:
    rule_id: str
    title: str
    category: str
    severity: str
    status: str
    file_filter: re.Pattern[str]
    pattern: re.Pattern[str]
    impact: str
    remediation: str
    negative_guard: re.Pattern[str] | None = None


SOURCE_PATTERN_RULES: tuple[SourcePatternRule, ...] = (
    # --- Frontend rules ---
    SourcePatternRule(
        rule_id="SRC-FE-LOCALSTORAGE-ROLE",
        title="Authorization role or admin status trusted from browser storage",
        category="source_code",
        severity="medium",
        status="confirmed",
        file_filter=re.compile(r"\.(?:tsx?|jsx?|vue|svelte)$", re.I),
        pattern=re.compile(
            r"""(?:localStorage|sessionStorage)\s*\.\s*getItem\(\s*["'`](?:role|userRole|isAdmin|is_admin|admin|permissions|isSuperAdmin)["'`]\s*\)"""
        ),
        impact="Values in localStorage/sessionStorage are controlled by the user and can be modified in DevTools to bypass client-side route or UI restrictions.",
        remediation="Verify user roles on the server from an authenticated session or signed token; never store or trust authorization flags in browser storage.",
    ),
    SourcePatternRule(
        rule_id="SRC-FE-REACT-STATE-ADMIN-GUARD",
        title="Administrative route or component guarded only by client-side React state",
        category="source_code",
        severity="medium",
        status="potential",
        file_filter=re.compile(r"\.(?:tsx?|jsx?)$", re.I),
        pattern=re.compile(
            r"""const\s+\[\s*(?:isAdmin|isSuperAdmin|userRole|role)\s*,\s*set(?:IsAdmin|IsSuperAdmin|UserRole|Role)\s*\]\s*=\s*useState\s*\("""
        ),
        impact="Guarding administrative views with client-side useState allows attackers to toggle state in React DevTools and exposes admin functionality if backend APIs are not independently protected.",
        remediation="Enforce route protection in server middleware (e.g. Next.js middleware / Server Components) and validate roles on every backend API endpoint.",
    ),
    SourcePatternRule(
        rule_id="SRC-FE-PUBLIC-ENV-SECRET",
        title="Secret or private key exposed to client bundle via NEXT_PUBLIC_ / VITE_ / REACT_APP_ prefix",
        category="source_code",
        severity="high",
        status="confirmed",
        file_filter=re.compile(r"(?:\.(?:tsx?|jsx?|vue|svelte|mjs|cjs)|\.env.*)$", re.I),
        pattern=re.compile(
            r"""\b(?:NEXT_PUBLIC|VITE|REACT_APP|PUBLIC|NUXT_PUBLIC)_[A-Z0-9_]*(?:SECRET|SERVICE_ROLE|PRIVATE_KEY|PASSWORD|OPENAI_API_KEY|ANTHROPIC_API_KEY|STRIPE_SECRET|DATABASE_URL|ADMIN_KEY)[A-Z0-9_]*\b"""
        ),
        impact="Build tools inline NEXT_PUBLIC_*, VITE_*, and REACT_APP_* variables directly into client JavaScript bundles, exposing the secret to every visitor.",
        remediation="Remove the public prefix, access the variable only in server-side code, and rotate the exposed credential.",
    ),
    SourcePatternRule(
        rule_id="SRC-FE-HIDDEN-ADMIN-CONTROL",
        title="Hidden UI button or conditional JSX used to conceal administrative action",
        category="source_code",
        severity="low",
        status="informational",
        file_filter=re.compile(r"\.(?:tsx?|jsx?|vue|svelte)$", re.I),
        pattern=re.compile(
            r"""(?:isAdmin|user\??\.role\s*===\s*["'`]admin["'`])\s*&&\s*[<\(][\s\S]{0,200}?(?:deleteUser|promoteUser|admin|/api/admin)"""
        ),
        impact="Hiding buttons in JSX is a UX convenience, not an access control boundary; anyone can invoke the underlying API request directly.",
        remediation="Ensure the backend endpoint invoked by this control independently verifies the caller's administrator role.",
    ),
    # --- Backend rules ---
    SourcePatternRule(
        rule_id="SRC-BE-UNSAFE-ERROR-RESPONSE",
        title="API handler returns raw exception stack trace or error object to client",
        category="source_code",
        severity="medium",
        status="confirmed",
        file_filter=re.compile(r"\.(?:tsx?|jsx?|py)$", re.I),
        pattern=re.compile(
            r"""(?:NextResponse\.json|res\.status\(\d+\)\.json|res\.json|JSONResponse)\s*\([^)]{0,160}?\b(?:err\.stack|error\.stack|traceback\.format_exc\(\))\b"""
        ),
        impact="Serializing stack traces in HTTP responses leaks internal file paths, library versions, and query details.",
        remediation="Log stack traces server-side and return a generic error message and correlation ID to the client.",
    ),
    SourcePatternRule(
        rule_id="SRC-BE-INSECURE-FILE-UPLOAD",
        title="File upload handler processes uploaded file without visible content-type or size validation",
        category="source_code",
        severity="medium",
        status="potential",
        file_filter=re.compile(r"\.(?:tsx?|jsx?|py)$", re.I),
        pattern=re.compile(
            r"""(?:formData\(\)[\s\S]{0,240}?\.get\(\s*["'`]file["'`]\s*\)|multer\(\s*\{\s*dest\s*:|UploadFile\s*=\s*File\()"""
        ),
        negative_guard=re.compile(r"""(?:mimetype|content_type|size|maxSize|limits|allowedTypes|ALLOWED_EXTENSIONS)""", re.I),
        impact="Unrestricted file uploads can enable stored XSS, storage exhaustion, or server-side execution depending on how uploaded files are stored and served.",
        remediation="Enforce strict file size limits, validate MIME types and magic bytes against an allowlist, generate random storage filenames, and serve uploads from an isolated domain.",
    ),
    SourcePatternRule(
        rule_id="SRC-BE-SUPABASE-SERVICE-ROLE-CLIENT",
        title="Supabase service_role key initialized in shared or client-imported module",
        category="source_code",
        severity="high",
        status="confirmed",
        file_filter=re.compile(r"(?:src/lib|src/utils|components|pages|client)[^/]*\.(?:tsx?|jsx?)$", re.I),
        pattern=re.compile(r"""createClient\s*\([^)]*SERVICE_ROLE"""),
        impact="The Supabase service_role key bypasses all Row Level Security policies. If imported by client code or used for user-scoped queries without manual filtering, it exposes every tenant's rows.",
        remediation="Keep service_role clients strictly in isolated server-only modules (`import 'server-only'`) and prefer the user's scoped JWT client so RLS remains enforced.",
    ),
)

# Next.js / Express route handler authentication & role check heuristics
NEXT_ROUTE_FILE_RE = re.compile(r"(?:^|/)(?:app/api/.+/route|pages/api/.+)\.(?:ts|tsx|js|jsx)$", re.I)
ADMIN_OR_MUTATING_ROUTE_RE = re.compile(r"(?:^|/)(?:admin|users|roles|permissions|settings|config|webhooks|billing)(?:/|$)", re.I)
AUTH_CHECK_TOKENS_RE = re.compile(
    r"\b(?:getServerSession|auth\(\)|currentUser\(\)|getUser\(|verifyToken|jwt\.verify|requireAuth|requireAdmin|isAuthenticated|session\??\.user|req\.user|Depends\()\b"
)
ROLE_CHECK_TOKENS_RE = re.compile(
    r"\b(?:role\s*[!=]==?\s*[\"']admin[\"']|isAdmin|is_admin|requireAdmin|requireRole|hasRole|permissions\.includes)\b"
)

# SQL RLS patterns
CREATE_TABLE_RE = re.compile(
    r"""CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:public\.)?["`]?([A-Za-z0-9_]{2,64})["`]?""",
    re.IGNORECASE,
)
ENABLE_RLS_RE = re.compile(
    r"""ALTER\s+TABLE\s+(?:ONLY\s+)?(?:public\.)?["`]?([A-Za-z0-9_]{2,64})["`]?\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY""",
    re.IGNORECASE,
)
PERMISSIVE_POLICY_RE = re.compile(
    r"""CREATE\s+POLICY\s+["`]?([^"`\n]+)["`]?\s+ON\s+(?:public\.)?["`]?([A-Za-z0-9_]{2,64})["`]?[\s\S]{0,260}?(?:USING\s*\(\s*true\s*\)|WITH\s+CHECK\s*\(\s*true\s*\))""",
    re.IGNORECASE,
)

# Firestore rules patterns
FIRESTORE_ALLOW_TRUE_RE = re.compile(
    r"""allow\s+([^:;]+)\s*:\s*if\s+true\b""",
    re.IGNORECASE,
)


def _line_and_snippet(content: str, index: int, span_end: int) -> tuple[int, str]:
    line_no = content.count("\n", 0, index) + 1
    lines = content.splitlines()
    start_line = max(0, line_no - 2)
    end_line = min(len(lines), line_no + 2)
    snippet = "\n".join(f"{i + 1}: {lines[i]}" for i in range(start_line, end_line))
    return line_no, redact_text(snippet, max_len=360)


async def analyze_source_entries(
    entries: list[SourceFileEntry],
    *,
    run_semgrep_if_available: bool = True,
) -> list[FindingDraft]:
    findings: list[FindingDraft] = []
    sql_entries: list[SourceFileEntry] = []

    for entry in entries:
        path = entry.rel_path
        code = entry.content
        if not code.strip():
            continue

        # 1. Secret detection across all source files ( skipping .env.example templates )
        if not path.lower().endswith((".env.example", ".env.sample", ".env.template")):
            for sm in detect_secrets(code, path):
                if sm.kind == "public_identifier":
                    continue
                findings.append(
                    FindingDraft(
                        rule_id="SRC-HARDCODED-SECRET",
                        title=f"Hardcoded {sm.name} in source file {path}",
                        category="source_code",
                        severity=sm.severity,
                        status="confirmed" if sm.severity in ("critical", "high") else "potential",
                        confidence=0.93,
                        affected=f"{path}:{sm.line or 1}",
                        discriminator=sm.fingerprint,
                        evidence=[
                            {
                                "type": "source_secret",
                                "detail": f"{sm.name}: {sm.masked} (sha256:{sm.fingerprint})",
                                "location": f"{path}:{sm.line or 1}",
                                "snippet": sm.snippet,
                            }
                        ],
                        detection_method=f"Static source secret detection ({sm.rule_id})",
                        impact=sm.description,
                        reproduction=[f"Inspect {path} at line {sm.line or 1}"],
                        remediation=sm.remediation,
                    )
                )

        # 2. Pattern rules
        for rule in SOURCE_PATTERN_RULES:
            if not rule.file_filter.search(path):
                continue
            if rule.negative_guard and rule.negative_guard.search(code):
                continue
            for m in rule.pattern.finditer(code):
                line_no, snippet = _line_and_snippet(code, m.start(), m.end())
                findings.append(
                    FindingDraft(
                        rule_id=rule.rule_id,
                        title=rule.title,
                        category=rule.category,
                        severity=rule.severity,
                        status=rule.status,
                        confidence=0.88 if rule.status == "confirmed" else 0.72,
                        affected=f"{path}:{line_no}",
                        evidence=[
                            {
                                "type": "source_code",
                                "detail": f"{rule.title} at {path}:{line_no}",
                                "location": f"{path}:{line_no}",
                                "snippet": snippet,
                            }
                        ],
                        detection_method=f"Static source analysis rule {rule.rule_id}",
                        impact=rule.impact,
                        reproduction=[f"Review {path} around line {line_no}"],
                        remediation=rule.remediation,
                    )
                )
                break

        # 3. Next.js API route handlers missing authentication or role checks
        if NEXT_ROUTE_FILE_RE.search(path):
            _check_nextjs_api_route(entry, findings)

        # 4. Collect SQL files for cross-file RLS analysis
        if path.lower().endswith(".sql"):
            sql_entries.append(entry)

        # 5. Firebase / Firestore rules analysis
        if path.lower().endswith(".rules") or "firestore.rules" in path.lower():
            _check_firestore_rules(entry, findings)

    if sql_entries:
        _analyze_sql_rls_across_files(sql_entries, findings)

    if run_semgrep_if_available and entries:
        semgrep_findings = await _run_optional_semgrep(entries)
        findings.extend(semgrep_findings)

    return findings


def _check_nextjs_api_route(entry: SourceFileEntry, findings: list[FindingDraft]) -> None:
    path = entry.rel_path
    code = entry.content
    has_auth = bool(AUTH_CHECK_TOKENS_RE.search(code))
    has_role = bool(ROLE_CHECK_TOKENS_RE.search(code))
    is_admin_route = bool(ADMIN_OR_MUTATING_ROUTE_RE.search(path))
    has_mutation = bool(re.search(r"\bexport\s+async\s+function\s+(?:POST|PUT|PATCH|DELETE)\b", code))

    if is_admin_route and not has_auth:
        findings.append(
            FindingDraft(
                rule_id="SRC-BE-MISSING-AUTH-MIDDLEWARE",
                title=f"Administrative or sensitive API route handler {path} has no visible authentication check",
                category="source_code",
                severity="high",
                status="confirmed",
                confidence=0.86,
                affected=f"{path}:1",
                evidence=[
                    {
                        "type": "source_code",
                        "detail": f"API route {path} defines handlers without calling session/token verification helpers",
                        "location": f"{path}:1",
                        "snippet": redact_text("\n".join(code.splitlines()[:18]), max_len=360),
                    }
                ],
                detection_method="Static AST/token check for authentication guards in API route file",
                impact="Unauthenticated callers can invoke this API route directly.",
                reproduction=[f"Inspect {path} for session/authentication verification"],
                remediation="Verify the caller's session at the top of every route handler (e.g. `const session = await auth(); if (!session) return NextResponse.json({error: 'Unauthorized'}, {status: 401});`).",
            )
        )
    elif is_admin_route and has_auth and not has_role and "/admin/" in f"/{path.lower()}":
        findings.append(
            FindingDraft(
                rule_id="SRC-BE-MISSING-ROLE-VALIDATION",
                title=f"Administrative API route {path} checks authentication but lacks administrator role validation",
                category="source_code",
                severity="high",
                status="potential",
                confidence=0.78,
                affected=f"{path}:1",
                evidence=[
                    {
                        "type": "source_code",
                        "detail": f"Found authentication check in {path} but no role/permission assertion for an /admin/ route",
                        "location": f"{path}:1",
                        "snippet": redact_text("\n".join(code.splitlines()[:22]), max_len=360),
                    }
                ],
                detection_method="Static analysis of authentication vs role checks on /admin/ API route",
                impact="Any logged-in regular user may be able to invoke administrative functionality (Broken Function Level Authorization).",
                remediation="Check `session.user.role === 'admin'` (or equivalent permission claim) before executing administrative logic.",
            )
        )
    elif has_mutation and not has_auth and "webhook" not in path.lower() and "auth" not in path.lower():
        findings.append(
            FindingDraft(
                rule_id="SRC-BE-UNAUTH-MUTATION-HANDLER",
                title=f"Mutating API handler (POST/PUT/PATCH/DELETE) in {path} lacks visible authentication check",
                category="source_code",
                severity="medium",
                status="potential",
                confidence=0.75,
                affected=f"{path}:1",
                evidence=[
                    {
                        "type": "source_code",
                        "detail": f"Mutating HTTP verb exported in {path} without visible authentication call",
                        "location": f"{path}:1",
                        "snippet": redact_text("\n".join(code.splitlines()[:18]), max_len=360),
                    }
                ],
                detection_method="Static analysis of Next.js Route Handler exports",
                impact="Allows unauthenticated callers to create, modify, or delete data if no upstream middleware enforces authentication.",
                reproduction=[f"Inspect exported POST/PUT/PATCH/DELETE handler in {path}"],
                remediation="Authenticate the caller and validate resource ownership before performing mutations.",
            )
        )


def _analyze_sql_rls_across_files(sql_entries: list[SourceFileEntry], findings: list[FindingDraft]) -> None:
    created_tables: dict[str, tuple[str, int, str]] = {}
    rls_enabled_tables: set[str] = set()

    for entry in sql_entries:
        for m in ENABLE_RLS_RE.finditer(entry.content):
            rls_enabled_tables.add(m.group(1).lower())

    for entry in sql_entries:
        for m in CREATE_TABLE_RE.finditer(entry.content):
            tname = m.group(1)
            tlow = tname.lower()
            if tlow in ("schema_migrations", "migrations", "_prisma_migrations"):
                continue
            line_no, snippet = _line_and_snippet(entry.content, m.start(), m.end())
            created_tables.setdefault(tlow, (entry.rel_path, line_no, snippet))

        for m in PERMISSIVE_POLICY_RE.finditer(entry.content):
            pol_name = m.group(1).strip()
            tname = m.group(2).strip()
            match_text = m.group(0)
            is_write = bool(
                re.search(r"\bFOR\s+(?:ALL|INSERT|UPDATE|DELETE)\b|\bWITH\s+CHECK\s*\(\s*true\s*\)", match_text, re.I)
            )
            line_no, snippet = _line_and_snippet(entry.content, m.start(), m.end())
            findings.append(
                FindingDraft(
                    rule_id="SRC-DB-RLS-OVERPERMISSIVE",
                    title=f"Overly permissive RLS policy '{pol_name}' on table '{tname}' uses USING/WITH CHECK (true)",
                    category="database_policy",
                    severity="high" if is_write else "medium",
                    status="confirmed",
                    confidence=0.92,
                    affected=f"{entry.rel_path}:{line_no}",
                    evidence=[
                        {
                            "type": "sql_policy",
                            "detail": f"Policy '{pol_name}' on '{tname}' grants unrestricted access via (true)",
                            "location": f"{entry.rel_path}:{line_no}",
                            "snippet": snippet,
                        }
                    ],
                    detection_method="Static SQL migration analysis for PostgreSQL/Supabase RLS policies",
                    impact="Grants any anonymous or authenticated PostgREST client unrestricted access to rows in the table.",
                    reproduction=[f"Inspect policy '{pol_name}' in {entry.rel_path}:{line_no}"],
                    remediation="Restrict the policy predicate to the row owner (e.g. `USING (auth.uid() = user_id)` and `WITH CHECK (auth.uid() = user_id)`).",
                )
            )

    for tlow, (rel_path, line_no, snippet) in created_tables.items():
        if tlow not in rls_enabled_tables:
            findings.append(
                FindingDraft(
                    rule_id="SRC-DB-RLS-MISSING",
                    title=f"Public table '{tlow}' created without ENABLE ROW LEVEL SECURITY across SQL migrations",
                    category="database_policy",
                    severity="high",
                    status="confirmed",
                    confidence=0.9,
                    affected=f"{rel_path}:{line_no}",
                    evidence=[
                        {
                            "type": "sql_ddl",
                            "detail": f"CREATE TABLE {tlow} at {rel_path}:{line_no} has no matching ALTER TABLE {tlow} ENABLE ROW LEVEL SECURITY",
                            "location": f"{rel_path}:{line_no}",
                            "snippet": snippet,
                        }
                    ],
                    detection_method="Cross-file SQL migration analysis for CREATE TABLE vs ENABLE ROW LEVEL SECURITY",
                    impact="In Supabase/PostgREST, any table in the `public` schema without RLS enabled is readable and writable by anyone holding the public anon key.",
                    reproduction=[f"Check migrations in {rel_path} for `ALTER TABLE public.{tlow} ENABLE ROW LEVEL SECURITY;`"],
                    remediation=f"Add `ALTER TABLE public.{tlow} ENABLE ROW LEVEL SECURITY;` and define explicit owner-scoped policies.",
                )
            )


def _check_firestore_rules(entry: SourceFileEntry, findings: list[FindingDraft]) -> None:
    for m in FIRESTORE_ALLOW_TRUE_RE.finditer(entry.content):
        ops = m.group(1).strip()
        line_no, snippet = _line_and_snippet(entry.content, m.start(), m.end())
        findings.append(
            FindingDraft(
                rule_id="SRC-DB-FIRESTORE-ALLOW-TRUE",
                title=f"Firebase security rules allow '{ops}' unconditionally (`if true`)",
                category="database_policy",
                severity="high" if "write" in ops.lower() or "create" in ops.lower() or "update" in ops.lower() or "delete" in ops.lower() else "medium",
                status="confirmed",
                confidence=0.95,
                affected=f"{entry.rel_path}:{line_no}",
                evidence=[
                    {
                        "type": "firestore_rules",
                        "detail": f"Unconditional `allow {ops}: if true` in {entry.rel_path}:{line_no}",
                        "location": f"{entry.rel_path}:{line_no}",
                        "snippet": snippet,
                    }
                ],
                detection_method="Static analysis of Firebase security rules",
                impact="Allows any unauthenticated internet client to access or modify documents in the matched collection.",
                reproduction=[f"Inspect {entry.rel_path} at line {line_no}"],
                remediation="Require authentication and ownership validation (e.g. `allow read, write: if request.auth != null && request.auth.uid == resource.data.userId;`).",
            )
        )


async def _run_optional_semgrep(entries: list[SourceFileEntry]) -> list[FindingDraft]:
    settings = get_settings()
    semgrep_bin = shutil.which(settings.semgrep_binary)
    if not semgrep_bin:
        return []

    tmpdir = Path(tempfile.mkdtemp(prefix="vibescan-src-"))
    try:
        for entry in entries[:500]:
            dest = (tmpdir / entry.rel_path).resolve()
            if not str(dest).startswith(str(tmpdir.resolve())):
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(entry.content, encoding="utf-8")

        proc = await asyncio.create_subprocess_exec(
            semgrep_bin,
            "scan",
            "--json",
            "--quiet",
            "--metrics=off",
            str(tmpdir),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=settings.semgrep_timeout_seconds)
        except TimeoutError:
            proc.kill()
            return []

        data = json.loads(stdout.decode("utf-8", errors="replace") or "{}")
        results: list[FindingDraft] = []
        for item in (data.get("results") or [])[:50]:
            rel = str(item.get("path") or "").replace(str(tmpdir) + "/", "")
            line = int((item.get("start") or {}).get("line") or 1)
            extra = item.get("extra") or {}
            sev_raw = str(extra.get("severity") or "WARNING").upper()
            sev = "high" if sev_raw == "ERROR" else ("medium" if sev_raw == "WARNING" else "low")
            check_id = str(item.get("check_id") or "SEMGREP-FINDING")
            msg = str(extra.get("message") or check_id)
            lines_snip = redact_text(str(extra.get("lines") or ""), max_len=300)
            results.append(
                FindingDraft(
                    rule_id=f"SEMGREP-{check_id[-40:]}",
                    title=msg[:240],
                    category="source_code",
                    severity=sev,
                    status="potential",
                    confidence=0.8,
                    affected=f"{rel}:{line}",
                    evidence=[
                        {
                            "type": "semgrep",
                            "detail": f"Semgrep rule {check_id} matched at {rel}:{line}",
                            "location": f"{rel}:{line}",
                            "snippet": lines_snip,
                        }
                    ],
                    detection_method=f"Semgrep static analysis ({check_id})",
                    impact=msg,
                    reproduction=[f"Review {rel} at line {line}"],
                    remediation="Address the insecure pattern reported by Semgrep and add a regression test.",
                )
            )
        return results
    except Exception:
        return []
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def recovered_sourcemaps_to_entries(recovered: list[RecoveredSourceFile]) -> list[SourceFileEntry]:
    entries: list[SourceFileEntry] = []
    for rec in recovered[:80]:
        clean = posixpath.normpath(rec.virtual_path.lstrip("./").replace("../", ""))
        entries.append(SourceFileEntry(rel_path=f"sourcemap/{clean}", content=rec.content))
    return entries
