"""Technology, framework, BaaS, and vibe-coding platform fingerprinting (Module A.B & A.C).

Key rule:
- Do not claim that a vibe-coding platform generated an application based on a single ambiguous
  indicator. Every detection records weighted signals and requires either multiple independent
  signals or a high-confidence platform-specific signature (confidence >= 0.45 to report as a
  detected platform; single weak signals are marked below threshold and excluded or noted as low
  confidence).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.scanner.html_parse import ParsedHtmlPage
from app.scanner.http import SafeResponse
from app.scanner.js_analysis import JsAnalysisResult


@dataclass
class FingerprintSignal:
    signal: str
    detail: str
    weight: float

    def to_dict(self) -> dict:
        return {"signal": self.signal, "detail": self.detail, "weight": round(self.weight, 2)}


@dataclass
class DetectedTechnology:
    name: str
    kind: str  # framework | backend | baas | build_tool | platform
    confidence: float
    signals: list[FingerprintSignal] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "kind": self.kind,
            "confidence": round(min(1.0, self.confidence), 2),
            "evidence": [s.to_dict() for s in self.signals],
        }


def fingerprint_application(
    responses: list[SafeResponse],
    pages: list[ParsedHtmlPage],
    js_blobs: list[tuple[str, str]],
    js_results: list[JsAnalysisResult],
) -> list[DetectedTechnology]:
    signals: dict[tuple[str, str], list[FingerprintSignal]] = {}

    def add(name: str, kind: str, sig: str, detail: str, weight: float) -> None:
        key = (name, kind)
        bucket = signals.setdefault(key, [])
        if any(s.signal == sig for s in bucket):
            return
        bucket.append(FingerprintSignal(signal=sig, detail=detail[:240], weight=weight))

    all_headers: dict[str, set[str]] = {}
    for r in responses:
        for k, v in r.headers.items():
            all_headers.setdefault(k.lower(), set()).add(v)

    all_html = "\n".join(r.text[:65536] for r in responses if "html" in (r.content_type or "").lower())
    all_js_urls = [u for p in pages for u in p.script_urls] + [u for u, _ in js_blobs]
    combined_js = "\n".join(code[:200000] for _, code in js_blobs[:15])

    # --- Frameworks & build tools ---
    if any(
        "__next" in p.root_element_ids or p.next_data_json is not None for p in pages
    ):
        add("Next.js", "framework", "next_dom_root", "Found #__next or __NEXT_DATA__ script payload in HTML", 0.55)
    if any("/_next/static/" in u for u in all_js_urls):
        add("Next.js", "framework", "next_static_chunks", "Found /_next/static/ JavaScript chunks", 0.45)
    if any("next" in v.lower() for v in all_headers.get("x-powered-by", set())):
        add("Next.js", "framework", "x_powered_by_next", "X-Powered-By header references Next.js", 0.4)

    if any("root" in p.root_element_ids for p in pages) and (
        re.search(r"react-dom|__REACT_DEVTOOLS_GLOBAL_HOOK__|createRoot\(|jsxRuntime", combined_js)
        or ("Next.js", "framework") in signals
    ):
        add("React", "framework", "react_runtime", "React DOM runtime / createRoot signature in frontend assets", 0.6)
    if re.search(r"react-router|createBrowserRouter|RouterProvider", combined_js):
        add("React", "framework", "react_router", "React Router signature in bundle", 0.35)

    if any("__nuxt" in p.root_element_ids for p in pages) or any("/_nuxt/" in u for u in all_js_urls):
        add("Nuxt", "framework", "nuxt_signature", "Found #__nuxt root or /_nuxt/ assets", 0.85)
        add("Vue", "framework", "vue_via_nuxt", "Nuxt implies Vue runtime", 0.6)
    if re.search(r"__VUE__|createVNode|defineComponent\(|vue-router", combined_js):
        add("Vue", "framework", "vue_runtime", "Vue 3 runtime symbols (__VUE__ / createVNode) in bundle", 0.65)

    if re.search(r"ng-version=|platformBrowserDynamic|@angular/core", all_html + combined_js):
        add("Angular", "framework", "angular_signature", "Angular ng-version attribute or @angular/core runtime", 0.85)

    if re.search(r"__sveltekit|sveltekit:", all_html + combined_js) or any("/_app/immutable/" in u for u in all_js_urls):
        add("SvelteKit", "framework", "sveltekit_signature", "SvelteKit __sveltekit runtime or /_app/immutable/ assets", 0.85)

    if any(re.search(r"/assets/index-[A-Za-z0-9_-]{6,}\.(?:js|css)", u) for u in all_js_urls) or re.search(
        r"vite/modulepreload-polyfill", combined_js
    ):
        add("Vite", "build_tool", "vite_bundle_layout", "Vite /assets/index-<hash>.js bundle naming or modulepreload polyfill", 0.65)

    # --- Backend frameworks ---
    for v in all_headers.get("x-powered-by", set()):
        if "express" in v.lower():
            add("Express", "backend", "x_powered_by_express", f"X-Powered-By: {v}", 0.85)
    for v in all_headers.get("server", set()):
        if "uvicorn" in v.lower() or "hypercorn" in v.lower():
            add("FastAPI", "backend", "asgi_server_header", f"Server: {v}", 0.45)
    if any(
        "/openapi.json" in r.url and r.status_code == 200 and '"openapi"' in r.text[:200] and '"FastAPI"' in r.text[:1000]
        for r in responses
    ):
        add("FastAPI", "backend", "fastapi_openapi", "OpenAPI schema identifies FastAPI", 0.6)

    # --- BaaS / Managed backends ---
    supa_urls = {u for jr in js_results for u in jr.supabase_urls}
    supa_tables = {t for jr in js_results for t in jr.supabase_tables}
    if supa_urls:
        add("Supabase", "baas", "supabase_project_url", f"Supabase project URL(s): {', '.join(sorted(supa_urls)[:3])}", 0.6)
    if supa_tables or re.search(r"@supabase/supabase-js|supabaseClient|createClient\(", combined_js):
        add("Supabase", "baas", "supabase_js_sdk", f"Supabase JS SDK / .from() table queries ({len(supa_tables)} tables)", 0.4)

    fb_projects = {p["project_id"] for jr in js_results for p in jr.firebase_projects}
    if fb_projects:
        add("Firebase", "baas", "firebase_config", f"Firebase project config for: {', '.join(sorted(fb_projects)[:3])}", 0.65)
    if re.search(r"firebase/app|getFirestore|initializeApp\(|firebaseAuth", combined_js):
        add("Firebase", "baas", "firebase_js_sdk", "Firebase JS SDK markers in bundle", 0.35)

    aw_projects = {p for jr in js_results for p in jr.appwrite_projects}
    aw_endpoints = {e for jr in js_results for e in jr.appwrite_endpoints}
    if aw_projects or aw_endpoints:
        add("Appwrite", "baas", "appwrite_client", f"Appwrite SDK setEndpoint/setProject ({', '.join(sorted(aw_projects)[:2])})", 0.85)

    if re.search(r"PocketBase|/api/collections/[A-Za-z0-9_]+/records", combined_js):
        add("PocketBase", "baas", "pocketbase_sdk", "PocketBase SDK or /api/collections/*/records endpoint pattern", 0.8)

    if re.search(r"\.convex\.cloud\b|ConvexReactClient|useConvex\(", combined_js + all_html):
        add("Convex", "baas", "convex_client", "Convex deployment URL (*.convex.cloud) or ConvexReactClient", 0.85)

    # --- Vibe-coding platform fingerprinting (Module A.C) ---
    # Requires >= 2 signals OR confidence >= 0.55 from multiple weighted indicators.
    # 1. Lovable (lovable.dev / gptengineer.app)
    if re.search(r"lovable-tagger|data-lov-id|__LOVABLE__|componentTagger", all_html + combined_js):
        add("Lovable", "platform", "lovable_component_tagger", "Found lovable-tagger / data-lov-id component instrumentation", 0.55)
    if re.search(r"cdn\.gpteng\.co|gptengineer\.js|lovable\.dev/opengraph|lovable\.app", all_html + combined_js):
        add("Lovable", "platform", "lovable_gpteng_asset", "Found gpteng.co / lovable.dev script or OpenGraph asset", 0.45)
    for p in pages:
        if "lovable" in (p.meta_tags.get("author", "") + " " + p.meta_tags.get("generator", "")).lower():
            add("Lovable", "platform", "lovable_meta_author", f"Meta author/generator references Lovable ({p.meta_tags})", 0.35)
    if ("Vite", "build_tool") in signals and ("Supabase", "baas") in signals and ("Lovable", "platform") in signals:
        add("Lovable", "platform", "lovable_stack_match", "Vite + React + Supabase stack consistent with Lovable template", 0.15)

    # 2. Bolt.new (StackBlitz)
    if re.search(r"bolt\.new|stackblitz\.com|@bolt/|__bolt__", all_html + combined_js):
        add("Bolt.new", "platform", "bolt_marker", "Found bolt.new / StackBlitz marker in HTML or bundle", 0.45)
    if any("webcontainer" in v.lower() or "stackblitz" in v.lower() for hdr_set in all_headers.values() for v in hdr_set):
        add("Bolt.new", "platform", "bolt_webcontainer_header", "Response header references StackBlitz / WebContainer", 0.45)
    if re.search(r"lucide-react", combined_js) and ("Vite", "build_tool") in signals and ("Bolt.new", "platform") in signals:
        add("Bolt.new", "platform", "bolt_vite_lucide_stack", "Vite + Lucide + React template structure", 0.2)

    # 3. v0 (Vercel v0.dev)
    if re.search(r"\bv0\.dev\b|v0-tag|data-v0-t=|Generated by create-v0|v0\.app", all_html + combined_js):
        add("v0", "platform", "v0_dom_or_comment_marker", "Found v0.dev / data-v0-t attribute or generator marker", 0.55)
    if re.search(r"placeholder\.svg\?height=\d+&width=\d+", all_html + combined_js):
        add("v0", "platform", "v0_placeholder_svg", "Found v0 signature placeholder.svg?height=...&width=... asset pattern", 0.35)
    if any("x-vercel-id" in k for k in all_headers) and ("v0", "platform") in signals:
        add("v0", "platform", "v0_vercel_deployment", "Hosted on Vercel (x-vercel-id header) alongside v0 markers", 0.15)

    # 4. Replit
    if re.search(r"replit\.dev|repl\.co|__replit|replit-dev-banner|@replit/", all_html + combined_js):
        add("Replit", "platform", "replit_script_or_domain", "Found Replit domain / dev banner / @replit package reference", 0.5)
    if any("replit" in k or any("replit" in v.lower() for v in vals) for k, vals in all_headers.items()):
        add("Replit", "platform", "replit_header", "HTTP response headers contain Replit routing identifiers", 0.45)

    # 5. Base44
    if re.search(r"@base44/sdk|base44\.app|api\.base44\.com|createBase44Client", all_html + combined_js):
        add("Base44", "platform", "base44_sdk", "Found @base44/sdk or api.base44.com endpoint in frontend bundle", 0.6)
    if re.search(r"/api/apps/[0-9a-f]{16,32}/entities/", combined_js):
        add("Base44", "platform", "base44_entity_api", "Found Base44 /api/apps/<id>/entities/ API pattern", 0.4)

    detected: list[DetectedTechnology] = []
    for (name, kind), sigs in signals.items():
        total = min(1.0, sum(s.weight for s in sigs))
        if kind == "platform":
            # Do not report a vibe-coding platform from a single weak/ambiguous indicator.
            if len(sigs) < 2 and total < 0.55:
                continue
        if total < 0.35:
            continue
        detected.append(DetectedTechnology(name=name, kind=kind, confidence=round(total, 2), signals=sigs))

    detected.sort(key=lambda t: (t.kind == "platform", t.confidence), reverse=True)
    return detected
