# VibeScan Frontend Dashboard

Production-ready Next.js 15 (App Router) + React 19 + TypeScript + Tailwind CSS dashboard for the **VibeScan** authorized web & AI-generated application security auditing platform.

## Architecture & Security Design

- **Same-Origin API Proxy (`next.config.mjs`)**: Rewrites `/api/:path*` and `/health` to `VIBESCAN_API_URL` (default `http://localhost:8000`) so `httpOnly` session cookies (`vibescan_session`) and double-submit CSRF tokens (`vibescan_csrf`) operate without cross-origin credential exposure.
- **Strict Content Security Policy & Hardened Headers**: Sets `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`, and `Cross-Origin-Opener-Policy: same-origin`.
- **XSS-Safe Rendering**: Code snippets, HTTP evidence, and AI outputs are rendered strictly as text inside React elements (`<pre><code>`); `dangerouslySetInnerHTML` is never used, and external links are validated via `safeHref()` (`http:` / `https:` only).
- **Write-Only Secrets**: Target test credentials, Supabase keys, and AI API keys use write-only password inputs with autofill disabled and are never echoed back from the server.

## Routes

| Route | Purpose |
|---|---|
| `/login` | Operator authentication with CSRF bootstrap |
| `/` | Security posture dashboard, KPI cards, severity distribution & historical trend charts, recent scans |
| `/targets` | Target inventory, registration modal, authorization status badges |
| `/targets/[id]` | Ownership verification (`dns_txt`, `well_known`, `meta_tag`, lab `attestation`), crawl scope, differential access test URLs, write-only credentials, Supabase integration |
| `/scans` | Scan history and status filtering |
| `/scans/new` | Launch scan with module toggles, optional white-box source ZIP upload, and mandatory operator authorization confirmation |
| `/scans/[id]` | Live 2-second scan progress polling, execution phase timeline, fingerprinted technologies, and deep links |
| `/admin-surfaces` | Administrative route explorer with HTTP status, auth observation, risk level, redirect chain, discovery methods, and evidence drawer |
| `/access-control` | Access control and privilege escalation findings with safe verification commands and operator triage (`PATCH /api/v1/findings/{id}`) |
| `/configuration` | Configuration exposure, leaked secrets, security headers, BaaS policies, fingerprinted technologies, and exposed source maps |
| `/api-explorer` | Discovered REST/GraphQL/BaaS endpoints, CORS posture analysis, and API security findings |
| `/source-audit` | Static source code and database policy findings grouped by file with redacted code snippets |
| `/ai-analysis` | Hallucination-guarded AI security synthesis, grounding badge, clickable `finding_key` citations, risk ranking, and phased remediation plan |
| `/reports` | Generate and download standalone HTML, PDF, and JSON security reports |
| `/settings` | Platform capabilities, AI provider configuration, operator management, and immutable audit logs |

## Local Development

```bash
cd frontend
npm install
VIBESCAN_API_URL=http://localhost:8000 npm run dev
```

## Production Build & Verification

```bash
npm run typecheck
npm run build
```
