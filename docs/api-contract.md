# VibeScan REST API Contract (v1)

Base path: `/api/v1`. The Next.js frontend proxies `/api/*` to the FastAPI backend (same origin), so
cookies work without CORS.

## Conventions

- Auth: server-side session cookie `vibescan_session` (httpOnly, SameSite=Lax, Secure in production).
- CSRF: every state-changing request (POST/PUT/PATCH/DELETE) must send header `X-CSRF-Token` equal to
  the value of the readable cookie `vibescan_csrf` (also returned by `/auth/login` and `/auth/me`).
- Errors: `{"detail": "message"}` (or FastAPI validation error list) with 4xx/5xx status.
- Timestamps: ISO-8601 UTC strings. IDs: UUID strings.
- Pagination: list endpoints accept `limit` (default 100, max 500) and `offset`; responses are
  `{"items": [...], "total": N}`.

### Enumerations

| Name | Values |
|---|---|
| `OperatorRole` | `admin`, `operator`, `viewer` |
| `AuthorizationStatus` | `pending`, `verified`, `attested`, `expired`, `revoked` |
| `VerificationMethod` | `dns_txt`, `well_known`, `meta_tag`, `attestation` |
| `ScanStatus` | `queued`, `running`, `completed`, `failed`, `cancelled`, `timed_out` |
| `Severity` | `critical`, `high`, `medium`, `low`, `info` |
| `FindingStatus` | `confirmed`, `potential`, `informational`, `false_positive`, `not_tested` |
| `VerificationStatus` (operator triage) | `unverified`, `verified`, `false_positive`, `accepted_risk`, `fixed` |
| `FindingCategory` | `admin_surface`, `access_control`, `configuration_exposure`, `secret_exposure`, `api_security`, `source_code`, `database_policy`, `security_headers`, `information_disclosure`, `fingerprint` |
| `AdminCategory` | `authentication`, `admin_interface`, `user_management`, `system_configuration`, `workflow_management`, `backend_management`, `none` |
| `AuthObservation` | `public_content`, `public_shell`, `login_page`, `redirect_to_login`, `unauthorized` (401), `forbidden` (403), `not_found`, `error`, `redirect_other`, `not_tested` |
| `RiskLevel` | same as Severity plus `none` |

## Auth

- `POST /auth/login` `{email, password}` → `200 {operator: Operator, csrf_token}` (sets cookies). 429 when rate limited.
- `POST /auth/logout` → `204`
- `GET /auth/me` → `{operator: Operator, csrf_token}` or 401

`Operator`: `{id, email, display_name, role, is_active, created_at, last_login_at}`

- `GET /operators` (admin) → `{items: Operator[], total}`
- `POST /operators` (admin) `{email, display_name, password, role}` → Operator
- `PATCH /operators/{id}` (admin) `{display_name?, role?, is_active?, password?}` → Operator

## Targets

`Target`:
```json
{
  "id": "uuid", "name": "My Lovable app", "base_url": "https://app.example.com",
  "primary_host": "app.example.com", "allowed_hosts": ["app.example.com", "api.app.example.com"],
  "scope_config": {
    "include_paths": ["/"], "exclude_paths": ["/logout"], "max_depth": 4, "max_pages": 150,
    "requests_per_second": 5, "concurrency": 4, "respect_robots": true,
    "enable_path_probing": true, "render_js": false, "request_timeout_seconds": 15
  },
  "access_tests": [ {"url": "https://app.example.com/api/orders/test-123", "owner_role": "user_a", "description": "order owned by test user A"} ],
  "integrations": { "supabase": {"enabled": false, "project_url": null, "anon_key_set": false} },
  "authorization_status": "pending", "verification_method": null,
  "verification_token": "vibescan-verify=abc123...", "verified_at": null, "verification_expires_at": null,
  "attestation": null, "owner_operator_id": "uuid", "created_at": "...", "last_scan_at": null,
  "credential_roles": ["user_a", "admin_test"]
}
```

- `GET /targets` → `{items: Target[], total}`
- `POST /targets` `{name, base_url, allowed_hosts?, scope_config?, access_tests?}` → Target (201)
- `GET /targets/{id}` → Target
- `PATCH /targets/{id}` `{name?, allowed_hosts?, scope_config?, access_tests?, integrations?}` → Target
  - `integrations.supabase` input: `{enabled, project_url, anon_key}` (anon_key write-only)
- `DELETE /targets/{id}` → 204 (archives)
- `GET /targets/{id}/verification` → `{token, instructions: {dns_txt: {record_name, record_value}, well_known: {url, content}, meta_tag: {html}}, attestation_allowed: bool}`
- `POST /targets/{id}/verify` `{method: "dns_txt"|"well_known"|"meta_tag"}` → `{verified: bool, detail, target: Target}`
- `POST /targets/{id}/attest` `{statement, confirm: true}` (admin; only when lab mode allows) → Target
- `GET /targets/{id}/credentials` → `{items: [{id, role_name, auth_type, header_name, description, created_at}]}` (values never returned)
- `POST /targets/{id}/credentials` `{role_name, auth_type: "cookie"|"bearer"|"header", header_name?, value, description?}` → credential (201)
- `DELETE /targets/{id}/credentials/{cred_id}` → 204

## Source uploads

- `POST /source-uploads` multipart: `target_id` (form), `file` (ZIP ≤ 50 MB) → `{id, target_id, filename, sha256, size_bytes, file_count, status, created_at}`
- `GET /source-uploads?target_id=` → `{items, total}`

## Scans

`ScanOptions`:
```json
{
  "crawl": true, "render_js": false, "path_probing": true, "access_control": true,
  "config_exposure": true, "api_discovery": true, "source_analysis": true,
  "ai_analysis": false, "max_pages": null, "timeout_seconds": 900, "source_upload_id": null
}
```

`Scan`:
```json
{
  "id": "uuid", "target_id": "uuid", "target_name": "...", "target_url": "...", "operator_id": "uuid",
  "status": "running", "options": ScanOptions, "progress": 42, "current_phase": "crawl",
  "phase_log": [ {"phase": "preflight", "status": "completed", "started_at": "...", "finished_at": "...", "message": "..."} ],
  "stats": { "pages_crawled": 12, "requests_made": 80, "routes_discovered": 34, "admin_surfaces": 6,
             "api_endpoints": 9, "assets_analyzed": 5, "findings_total": 11,
             "findings_by_severity": {"critical":1,"high":2,"medium":3,"low":2,"info":3},
             "findings_by_status": {"confirmed":2,"potential":4,"informational":5} },
  "created_at": "...", "started_at": "...", "finished_at": null, "error": null, "cancel_requested": false
}
```

- `GET /scans?target_id=&status=` → `{items: Scan[], total}` (newest first)
- `POST /scans` `{target_id, options?, authorization_confirmed: true, authorization_statement}` → Scan (202)
  - 409 if target not verified/attested or verification expired; 400 if `authorization_confirmed` false.
- `GET /scans/{id}` → Scan (poll every 2s while queued/running)
- `POST /scans/{id}/cancel` → Scan
- `GET /scans/{id}/technologies` → `{items: [{id, name, kind: "framework"|"backend"|"baas"|"build_tool"|"platform", confidence: 0..1, evidence: [{signal, detail, weight}]}]}`
- `GET /scans/{id}/routes?admin_only=true&category=` → `{items: Route[], total}`
- `GET /scans/{id}/routes/{route_id}` → Route
- `GET /scans/{id}/endpoints?category=` → `{items: ApiEndpoint[], total}`
- `GET /scans/{id}/findings?category=&severity=&status=` → `{items: Finding[], total}`
- `GET /scans/{id}/assets` → `{items: [{id, url, kind, size_bytes, sha256, source_map_url, source_map_exposed}], total}`

`Route`:
```json
{
  "id": "uuid", "scan_id": "uuid", "url": "https://app.example.com/admin", "path": "/admin",
  "status_code": 200, "title": "Admin", "content_type": "text/html", "auth_observation": "public_shell",
  "redirect_chain": [ {"url": "...", "status": 302, "location": "/login"} ],
  "discovery_methods": ["crawl", "js_bundle", "path_probe"], "admin_category": "admin_interface",
  "is_admin_surface": true, "confidence": 0.8, "risk_level": "medium",
  "evidence": [ {"type": "bundle_route", "detail": "React Router path '/admin' in /assets/index-abc.js", "location": "/assets/index-abc.js"} ],
  "created_at": "..."
}
```

`ApiEndpoint`:
```json
{
  "id": "uuid", "scan_id": "uuid", "url": "https://app.example.com/api/admin/users",
  "path_template": "/api/admin/users", "methods": ["GET"], "category": "administration",
  "sources": ["js_bundle"], "status_code": 401, "auth_observation": "unauthorized", "content_type": "application/json",
  "cors": {"allow_origin": null, "allow_credentials": false, "reflects_origin": false},
  "tested": true, "test_note": null, "evidence": [ ... ], "created_at": "..."
}
```
`ApiEndpoint.category` ∈ `authentication, user_management, administration, configuration, database, file_storage, workflow, ai_agents, webhooks, internal, other`.

`Finding`:
```json
{
  "id": "uuid", "scan_id": "uuid", "finding_key": "VS-3F9A21", "rule_id": "AC-UNAUTH-ADMIN-API",
  "title": "Administrative API returns data without authentication", "category": "access_control",
  "severity": "high", "status": "confirmed", "confidence": 0.9, "affected": "https://app.example.com/api/admin/users",
  "evidence": [ {"type": "http_response", "detail": "GET returned 200 application/json with 25 objects containing keys email, role", "location": "...", "snippet": "[{\"email\":\"a***@e***.com\" ..."} ],
  "detection_method": "Unauthenticated GET request compared against SPA baseline",
  "impact": "...", "reproduction": ["curl -s -o /dev/null -w '%{http_code}' https://..."],
  "remediation": "...", "references": [{"title": "OWASP A01:2021", "url": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"}],
  "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", "cvss_score": 8.7,
  "verification_status": "unverified", "operator_note": null, "created_at": "..."
}
```
- `GET /findings/{id}` → Finding
- `PATCH /findings/{id}` `{verification_status, operator_note?}` → Finding

## AI analysis

- `POST /scans/{id}/analysis` → `AIAnalysis` (202; runs in background)
- `GET /scans/{id}/analysis` → latest `AIAnalysis` or 404

`AIAnalysis`:
```json
{
  "id": "uuid", "scan_id": "uuid", "provider": "openai" | "deterministic", "model": "gpt-4o-mini",
  "status": "pending" | "completed" | "failed", "error": null, "created_at": "...",
  "output": {
    "executive_summary": "...",
    "overall_risk": "high",
    "sections": {
      "admin_surfaces": [Insight], "exposed_configuration": [Insight], "access_control": [Insight],
      "api_security": [Insight], "source_code": [Insight]
    },
    "risk_prioritization": [ {"rank": 1, "finding_ids": ["VS-3F9A21"], "rationale": "..."} ],
    "remediation_plan": [ {"priority": "immediate"|"short_term"|"long_term", "action": "...", "finding_ids": ["..."]} ],
    "limitations": ["..."]
  },
  "grounding": {"valid": true, "dropped_claims": 0, "unknown_ids": []}
}
```
`Insight`: `{"summary": "...", "finding_ids": ["VS-..."], "severity": "high"}`. `finding_ids` reference `Finding.finding_key`.

## Reports

- `POST /scans/{id}/reports` `{format: "html"|"json"|"pdf"}` → `{id, scan_id, format, size_bytes, sha256, created_at}` (201)
- `GET /scans/{id}/reports` → `{items, total}`
- `GET /reports/{id}/download` → file (Content-Disposition attachment)

## Dashboard

- `GET /dashboard/summary` →
```json
{
  "total_targets": 3, "verified_targets": 2, "total_scans": 7, "running_scans": 1,
  "total_routes_scanned": 230, "admin_surfaces": 18, "exposed_configurations": 4,
  "access_control_findings": 5, "critical_high_findings": 6,
  "findings_by_severity": {"critical":1,"high":5,"medium":7,"low":4,"info":12},
  "findings_by_category": {"access_control": 5, "...": 1},
  "severity_trend": [ {"scan_id": "uuid", "date": "...", "target_name": "...", "critical":0,"high":1,"medium":2,"low":1,"info":3} ],
  "recent_scans": [Scan]
}
```

## Settings / audit

- `GET /settings/ai` (admin) → `{provider: "openai"|"disabled", model, base_url, api_key_set: bool, auto_analyze: bool}`
- `PUT /settings/ai` (admin) `{provider, model, base_url, api_key?, auto_analyze}` → same as GET
- `GET /settings/platform` → `{lab_mode, allow_attestation_only, allow_private_targets, max_scan_timeout_seconds, semgrep_available, playwright_available, version}`
- `GET /audit-logs?limit=&offset=` (admin) → `{items: [{id, operator_email, action, target_id, scan_id, ip, details, created_at}], total}`
- `GET /health` (no auth, not under /api/v1 prefix: `/health`) → `{status: "ok"}`
