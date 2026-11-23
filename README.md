# VibeScan — AI-Powered Security Scanner for Vibe-Coded Web Applications

VibeScan is a defensive, production-oriented web application security auditing platform purpose-built for applications generated with AI-assisted ("vibe-coding") tools and modern BaaS stacks:

- **Vibe-coding platforms**: Lovable, Bolt.new, v0, Replit, Base44, Cursor-generated apps
- **Frontend & full-stack frameworks**: Next.js, React, Vue, Nuxt, Angular, SvelteKit, Vite, Express, FastAPI
- **Managed BaaS & data layers**: Supabase (PostgREST + RLS), Firebase / Firestore, Appwrite, PocketBase, Convex

---

## Security & Operational Boundaries

VibeScan is strictly a **passive and non-destructive** security assessment platform:

1. **Mandatory target ownership verification**: A target cannot be scanned until ownership is verified via DNS TXT (`_vibescan.<host>`), `/.well-known/vibescan-verify.txt`, or `<meta name="vibescan-verification">` (plus an explicit per-scan authorization confirmation recorded in the audit log).
2. **Safe HTTP methods only**: `SafeHttpClient` enforces a hard allowlist of `GET`, `HEAD`, and `OPTIONS`. Any attempt to call `POST`, `PUT`, `PATCH`, or `DELETE` raises `DisallowedMethodError`. Routes containing destructive tokens (`delete`, `destroy`, `purge`, `wipe`, `logout`, `signout`, ...) are never invoked.
3. **DNS-pinned SSRF protection**: `SafeNetworkBackend` resolves DNS and blocks loopback (`127.0.0.0/8`, `::1`), RFC1918 private networks, link-local (`169.254.0.0/16`, `fe80::/10`), CGNAT (`100.64.0.0/10`), NAT64/IPv4-mapped IPv6, internal hostnames (`.localhost`, `.internal`, `.local`, `.svc.cluster.local`), and cloud metadata IPs (`169.254.169.254`, `169.254.170.2`, `100.100.100.200`, `192.0.0.192`, `fd00:ec2::254`). It then connects directly to the validated IP address while preserving the hostname for TLS SNI and certificate verification, eliminating the TOCTOU DNS-rebinding window.
4. **No credential attacks or exploitation**: VibeScan never performs brute-force logins, password cracking, account enumeration, privilege escalation, or auth bypass. Authenticated role comparison uses only session cookies or tokens supplied by the application owner (encrypted at rest with HKDF-SHA256 + Fernet), and cross-account object checks (`AC-IDOR-CROSS-TENANT`) only test resource URLs explicitly declared as test-owned.
5. **Secret redaction at the source**: Detected secrets are masked immediately (`sk_l************ef (len=35, sha256:...)`). Full secret values are never stored in PostgreSQL/SQLite, never sent to the LLM, and never printed in HTML/JSON/PDF reports.
6. **SPA baseline false-positive suppression**: Before evaluating routes, VibeScan probes random non-existent paths to fingerprint the target's SPA catch-all shell / soft-404 response. A route named `/admin` or `/settings` that merely returns the generic SPA shell is classified as `public_shell` (`informational`), never as a confirmed exposed administrative interface.

---

## Architecture Overview

```
ScanSecurity/
├── backend/                     # Python 3.12 + FastAPI + SQLAlchemy 2 (async) + arq worker
│   ├── app/
│   │   ├── api/                 # REST v1 endpoints: auth, targets, scans, findings, reports, settings
│   │   ├── core/                # Argon2id auth, HKDF+Fernet crypto, secret redaction, audit log, rate limit
│   │   ├── db/                  # SQLAlchemy ORM models & async session management
│   │   ├── reports/             # HTML (Jinja2 autoescaped), JSON, and pure-Python PDF 1.4 generator
│   │   ├── scanner/
│   │   │   ├── netguard.py      # IP/hostname SSRF policy & DNS-pinning SafeNetworkBackend
│   │   │   ├── scope.py         # ScopePolicy (host, scheme, port, include/exclude paths)
│   │   │   ├── http.py          # SafeHttpClient (GET/HEAD/OPTIONS, rate limit, budget, redirect check)
│   │   │   ├── verification.py  # DNS TXT, well-known file, HTML meta tag verification
│   │   │   ├── baseline.py      # SPA catch-all shell & soft-404 baseline profiler
│   │   │   ├── crawler.py       # Module A: BFS crawler, asset harvester, optional Playwright pass
│   │   │   ├── html_parse.py    # HTML link/form/script/admin-marker extraction
│   │   │   ├── js_analysis.py   # Client router paths, API calls, BaaS configs, client-only guards
│   │   │   ├── fingerprint.py   # Module A.B/C: Framework, BaaS, and vibe-platform fingerprinting
│   │   │   ├── admin_surface.py # Module B: 6-category Admin Surface Discovery & classification
│   │   │   ├── access_control.py# Module C: Unauth, client-guard correlation, role diff, test-owned IDOR
│   │   │   ├── config_exposure.py# Module D: .env/.git/sourcemaps/headers + Supabase/Firebase/Appwrite
│   │   │   ├── secrets.py       # Entropy + JWT claim classifier (anon vs service_role)
│   │   │   ├── api_discovery.py # Module E: Bundle/OpenAPI discovery, CORS reflection, PII disclosure
│   │   │   ├── source_analysis.py# Module F: Safe ZIP reader, React/Next/SQL RLS/Firestore rules, Semgrep
│   │   │   ├── ai_analyst.py    # Module G: Prompt-injection hardened LLM analyst + grounding validator
│   │   │   ├── findings.py      # Deterministic VS-XXXXXX keys, deduplication, CVSS 4.0 scoring
│   │   │   └── engine.py        # 11-phase scan orchestrator with progress & cooperative cancellation
│   │   ├── config.py
│   │   ├── main.py
│   │   └── worker.py
│   ├── tests/                   # 50 unit, integration, and live lab tests across Phases 1–7
│   ├── Dockerfile
│   └── pyproject.toml
├── frontend/                    # Next.js 15 (App Router) + React 19 + TypeScript + Tailwind + Recharts
│   ├── src/
│   │   ├── app/                 # All 12 security dashboard pages + /login
│   │   ├── components/          # AppShell, FindingSheet, ScanSelector, status/severity badges, UI primitives
│   │   └── lib/                 # Typed API client with CSRF handling & contract types
│   ├── Dockerfile
│   └── package.json
├── docs/
│   └── api-contract.md          # Complete REST v1 specification
├── docker-compose.yml           # PostgreSQL 16, Redis 7, API, arq Worker, Next.js Frontend + optional Lab profile
└── .env.example
```

---

## Quick Start (Docker Compose — Production Stack)

1. Copy `.env.example` to `.env` and set a strong `VIBESCAN_SECRET_KEY` and `VIBESCAN_BOOTSTRAP_ADMIN_PASSWORD`:
   ```bash
   cp .env.example .env
   ```
2. Build and start PostgreSQL, Redis, FastAPI API, arq background worker, and Next.js dashboard:
   ```bash
   docker compose up --build -d
   ```
3. Open `http://localhost:3000` and sign in with `VIBESCAN_BOOTSTRAP_ADMIN_EMAIL` / `VIBESCAN_BOOTSTRAP_ADMIN_PASSWORD`.

---

## Local Development (Without Docker)

### 1. Backend (FastAPI + SQLite/PostgreSQL)
```bash
cd backend
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -e '.[dev,browser]'

# Start in development mode (bootstraps admin@vibescan.local / VibeScan-Dev-Admin!2026 if DB is empty)
.venv/bin/uvicorn app.main:app --reload --port 8000
```

### 2. Frontend (Next.js 15)
```bash
cd frontend
npm install
npm run dev
```
Navigate to `http://localhost:3000`. The Next.js dev server automatically proxies `/api/*` and `/health` to `http://localhost:8000`.

---

## Running in an Isolated Local Lab (OWASP Juice Shop / WebGoat)

By default, VibeScan blocks all private, loopback, and internal IP ranges. To test against intentionally vulnerable applications running in an isolated local Docker network:

1. In `.env`, enable lab mode with an explicit CIDR allowlist for the lab subnet (cloud metadata IPs `169.254.169.254`, etc. remain permanently blocked even in lab mode):
   ```env
   VIBESCAN_LAB_MODE=true
   VIBESCAN_ALLOW_ATTESTATION_ONLY=true
   VIBESCAN_ALLOW_PRIVATE_TARGETS=true
   VIBESCAN_PRIVATE_TARGET_ALLOWLIST=127.0.0.1/32,172.16.0.0/12
   ```
2. Start the stack with the `lab` profile (starts local `juice-shop` and `webgoat` containers bound to `127.0.0.1` only):
   ```bash
   docker compose --profile lab up --build -d
   ```
3. In the dashboard under **Target Inventory**, register `http://juice-shop:3000`, complete **Lab Attestation**, and launch a scan.

---

## Running Tests & Linting

```bash
# Backend unit, integration, and live lab test suite (50 tests)
cd backend
.venv/bin/pytest -v
.venv/bin/ruff check app tests

# Frontend TypeScript & production build verification
cd ../frontend
npx tsc --noEmit
npm run build
```
