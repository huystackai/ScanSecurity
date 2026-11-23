"""HTML parsing helpers: links, forms, assets, inline scripts, meta tags, and page classification."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from bs4 import BeautifulSoup

from app.scanner.scope import ScopePolicy

LOGIN_KEYWORDS_RE = re.compile(
    r"\b(sign\s*in|log\s*in|forgot\s*password|continue\s*with\s*(google|github)|magic\s*link|enter\s*your\s*password)\b",
    re.IGNORECASE,
)
ADMIN_UI_INDICATORS_RE = re.compile(
    r"\b(admin\s*(dashboard|panel|console)|user\s*management|role\s*management|system\s*settings|feature\s*flags|audit\s*logs?|super\s*admin|manage\s*users|permissions?\s*matrix|webhook\s*settings|database\s*explorer)\b",
    re.IGNORECASE,
)


@dataclass
class FormInfo:
    action: str
    method: str
    input_names: list[str]
    input_types: list[str]
    has_password: bool
    is_login_form: bool


@dataclass
class ParsedHtmlPage:
    url: str
    title: str
    links: list[str] = field(default_factory=list)
    script_urls: list[str] = field(default_factory=list)
    stylesheet_urls: list[str] = field(default_factory=list)
    inline_scripts: list[str] = field(default_factory=list)
    forms: list[FormInfo] = field(default_factory=list)
    meta_tags: dict[str, str] = field(default_factory=dict)
    comments: list[str] = field(default_factory=list)
    has_login_form: bool = False
    looks_like_login_page: bool = False
    admin_ui_phrases: list[str] = field(default_factory=list)
    root_element_ids: list[str] = field(default_factory=list)
    next_data_json: str | None = None


def parse_html_page(html: str, page_url: str, scope: ScopePolicy) -> ParsedHtmlPage:
    soup = BeautifulSoup(html or "", "lxml")
    title = (soup.title.string.strip() if soup.title and soup.title.string else "")[:300]
    parsed = ParsedHtmlPage(url=page_url, title=title)

    for root_id in ("root", "__next", "__nuxt", "app", "svelte"):
        if soup.find(id=root_id) is not None:
            parsed.root_element_ids.append(root_id)

    for meta in soup.find_all("meta"):
        name = (meta.get("name") or meta.get("property") or "").strip().lower()
        content = (meta.get("content") or "").strip()
        if name and content:
            parsed.meta_tags[name] = content[:500]

    seen_links: set[str] = set()
    for tag in soup.find_all(["a", "area"]):
        href = tag.get("href")
        if not href:
            continue
        resolved = scope.resolve_in_scope(str(href), page_url)
        if resolved and resolved not in seen_links:
            seen_links.add(resolved)
            parsed.links.append(resolved)

    seen_scripts: set[str] = set()
    for script in soup.find_all("script"):
        src = script.get("src")
        if src:
            resolved = scope.resolve_in_scope(str(src), page_url, for_asset=True)
            if resolved and resolved not in seen_scripts:
                seen_scripts.add(resolved)
                parsed.script_urls.append(resolved)
        else:
            body = script.string or script.get_text() or ""
            if script.get("id") == "__NEXT_DATA__":
                parsed.next_data_json = body[:512 * 1024]
            if body.strip():
                parsed.inline_scripts.append(body[:256 * 1024])

    seen_css: set[str] = set()
    for link in soup.find_all("link"):
        rels = [r.lower() for r in (link.get("rel") or [])]
        href = link.get("href")
        if not href:
            continue
        if "stylesheet" in rels or str(href).endswith(".css"):
            resolved = scope.resolve_in_scope(str(href), page_url, for_asset=True)
            if resolved and resolved not in seen_css:
                seen_css.add(resolved)
                parsed.stylesheet_urls.append(resolved)
        elif "modulepreload" in rels or ("preload" in rels and link.get("as") == "script"):
            resolved = scope.resolve_in_scope(str(href), page_url, for_asset=True)
            if resolved and resolved not in seen_scripts:
                seen_scripts.add(resolved)
                parsed.script_urls.append(resolved)

    for form in soup.find_all("form"):
        action_raw = str(form.get("action") or page_url)
        action = scope.resolve_in_scope(action_raw, page_url) or action_raw
        method = str(form.get("method") or "GET").upper()
        inputs = form.find_all(["input", "select", "textarea"])
        names = [str(i.get("name") or i.get("id") or "") for i in inputs if i.get("name") or i.get("id")]
        types = [str(i.get("type") or "text").lower() for i in inputs]
        has_pw = "password" in types
        form_text = form.get_text(" ", strip=True)
        is_login = has_pw or bool(LOGIN_KEYWORDS_RE.search(form_text))
        parsed.forms.append(
            FormInfo(
                action=action,
                method=method,
                input_names=names[:30],
                input_types=types[:30],
                has_password=has_pw,
                is_login_form=is_login,
            )
        )
        if is_login:
            parsed.has_login_form = True

    visible = soup.get_text(" ", strip=True)
    if parsed.has_login_form or (
        LOGIN_KEYWORDS_RE.search(title) or (len(visible) < 2500 and LOGIN_KEYWORDS_RE.search(visible))
    ):
        parsed.looks_like_login_page = True

    for m in ADMIN_UI_INDICATORS_RE.finditer(visible):
        phrase = m.group(0).strip()
        if phrase.lower() not in {p.lower() for p in parsed.admin_ui_phrases}:
            parsed.admin_ui_phrases.append(phrase)

    return parsed
