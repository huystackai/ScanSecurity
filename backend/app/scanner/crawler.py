"""Website crawler and asset harvester (Module A.A).

Crawls internal links up to ``max_depth`` and ``max_pages``, respects ``robots.txt`` (when enabled)
and scope restrictions, fetches referenced JS/CSS assets, and optionally uses Playwright (with strict
request interception enforcing ``ScopePolicy`` and ``SAFE_METHODS``) to discover client-rendered routes
and network calls.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urlparse

from app.scanner.html_parse import ParsedHtmlPage, parse_html_page
from app.scanner.http import SAFE_METHODS, SafeHttpClient, SafeResponse
from app.scanner.js_analysis import JsAnalysisResult, analyze_javascript
from app.scanner.robots import RobotsPolicy, fetch_robots
from app.scanner.scope import ScopePolicy


@dataclass
class CrawledAsset:
    url: str
    kind: str  # js | css
    response: SafeResponse
    js_analysis: JsAnalysisResult | None = None


@dataclass
class CrawlOutcome:
    robots: RobotsPolicy
    page_responses: dict[str, SafeResponse] = field(default_factory=dict)
    parsed_pages: dict[str, ParsedHtmlPage] = field(default_factory=dict)
    discovery_methods: dict[str, set[str]] = field(default_factory=dict)
    assets: dict[str, CrawledAsset] = field(default_factory=dict)
    js_results: list[JsAnalysisResult] = field(default_factory=list)
    browser_api_requests: list[tuple[str, str]] = field(default_factory=list)


async def run_crawler(
    client: SafeHttpClient,
    scope: ScopePolicy,
    *,
    max_pages_override: int | None = None,
    render_js: bool = False,
) -> CrawlOutcome:
    robots = await fetch_robots(client, scope.base_url)
    outcome = CrawlOutcome(robots=robots)
    max_pages = min(max_pages_override or scope.config.max_pages, scope.config.max_pages)
    max_depth = scope.config.max_depth

    queue: deque[tuple[str, int, str]] = deque([(scope.base_url, 0, "seed")])
    visited: set[str] = set()
    script_queue: list[str] = []
    css_queue: list[str] = []

    def record_discovery(url: str, method: str) -> None:
        outcome.discovery_methods.setdefault(url, set()).add(method)

    record_discovery(scope.base_url, "seed")

    while queue and len(visited) < max_pages:
        url, depth, method = queue.popleft()
        if url in visited:
            continue
        if not scope.is_in_scope(url):
            continue
        if scope.config.respect_robots and not robots.can_fetch(client.user_agent, url):
            continue

        visited.add(url)
        try:
            resp = await client.get(url, follow_redirects=True)
        except Exception:
            continue

        outcome.page_responses[url] = resp
        record_discovery(url, method)
        if resp.final_url != url and scope.is_in_scope(resp.final_url):
            outcome.page_responses.setdefault(resp.final_url, resp)
            record_discovery(resp.final_url, method)

        ct = (resp.content_type or "").lower()
        if "html" not in ct and not resp.text.lstrip().startswith("<!"):
            continue

        parsed = parse_html_page(resp.text, resp.final_url, scope)
        outcome.parsed_pages[url] = parsed

        for inline_idx, inline_code in enumerate(parsed.inline_scripts):
            jr = analyze_javascript(inline_code, f"{url}#inline-{inline_idx}")
            outcome.js_results.append(jr)
            for r_path in jr.routes:
                resolved = scope.resolve_in_scope(r_path, url)
                if resolved and ":" not in r_path and "*" not in r_path and "[" not in r_path:
                    record_discovery(resolved, "inline_script")
                    if depth + 1 <= max_depth and resolved not in visited:
                        queue.append((resolved, depth + 1, "inline_script"))

        for s_url in parsed.script_urls:
            if s_url not in script_queue:
                script_queue.append(s_url)
        for c_url in parsed.stylesheet_urls:
            if c_url not in css_queue:
                css_queue.append(c_url)

        if depth < max_depth:
            for link in parsed.links:
                record_discovery(link, "crawl")
                if link not in visited:
                    queue.append((link, depth + 1, "crawl"))

    # Fetch JS assets (bounded to 40 bundles to respect scan budget)
    for s_url in script_queue[:40]:
        if s_url in outcome.assets:
            continue
        try:
            s_resp = await client.get(s_url, follow_redirects=True, for_asset=True, max_bytes=3 * 1024 * 1024)
        except Exception:
            continue
        if s_resp.status_code != 200:
            continue
        jr = analyze_javascript(s_resp.text, s_url)
        outcome.js_results.append(jr)
        outcome.assets[s_url] = CrawledAsset(url=s_url, kind="js", response=s_resp, js_analysis=jr)
        for r_path in jr.routes:
            resolved = scope.resolve_in_scope(r_path, scope.base_url)
            if resolved:
                record_discovery(resolved, "js_bundle")

    for c_url in css_queue[:20]:
        if c_url in outcome.assets:
            continue
        try:
            c_resp = await client.get(c_url, follow_redirects=True, for_asset=True, max_bytes=1024 * 1024)
        except Exception:
            continue
        if c_resp.status_code == 200:
            outcome.assets[c_url] = CrawledAsset(url=c_url, kind="css", response=c_resp)

    if render_js:
        await _optional_playwright_pass(scope, outcome)

    return outcome


async def _optional_playwright_pass(scope: ScopePolicy, outcome: CrawlOutcome) -> None:
    """Optional headless browser pass with strict request interception (safe methods + in-scope only)."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return

    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try:
                context = await browser.new_context(ignore_https_errors=False)
                page = await context.new_page()

                async def intercept(route) -> None:  # type: ignore[no-untyped-def]
                    req = route.request
                    if req.method.upper() not in SAFE_METHODS:
                        await route.abort()
                        return
                    if not scope.is_in_scope(req.url, for_asset=True):
                        await route.abort()
                        return
                    parsed = urlparse(req.url)
                    if parsed.path.startswith(("/api/", "/v1/", "/v2/", "/graphql", "/trpc", "/rest/v1/")):
                        outcome.browser_api_requests.append((req.method.upper(), req.url))
                    await route.continue_()

                await page.route("**/*", intercept)
                await page.goto(scope.base_url, wait_until="networkidle", timeout=10000)
                hrefs = await page.eval_on_selector_all("a[href]", "els => els.map(e => e.getAttribute('href'))")
                for h in hrefs or []:
                    if not h:
                        continue
                    resolved = scope.resolve_in_scope(str(h), scope.base_url)
                    if resolved:
                        outcome.discovery_methods.setdefault(resolved, set()).add("playwright_dom")
            finally:
                await browser.close()
    except Exception:
        return
