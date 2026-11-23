"""SPA shell and soft-404 baseline fingerprinting.

Vibe-coded SPAs (Vite/React, Next.js, Lovable, Bolt.new, v0, Base44) typically return HTTP 200 with
the exact same HTML shell for *every* unknown path, or a branded 404 HTML page with HTTP 200.

``BaselineProfile`` probes two random non-existent paths at the start of a scan and records:
- Normalized structural HTML skeleton hash and text hash
- Root element id (e.g. ``root``, ``__next``, ``app``) and script bundle list
- Title and status code

Later modules compare candidate routes against this baseline so that:
- An unknown path returning the generic SPA shell is classified as ``public_shell`` (or ``not_found``
  for probes not referenced in code) rather than a "Confirmed exposed admin page".
"""

from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass, field

from bs4 import BeautifulSoup

from app.scanner.http import SafeHttpClient, SafeResponse

WHITESPACE_RE = re.compile(r"\s+")
NONCE_ATTR_RE = re.compile(r"(nonce|csrf|token|timestamp)", re.IGNORECASE)


def normalize_html_structure(html: str) -> tuple[str, str, str, list[str]]:
    """Return ``(title, structure_hash, visible_text_hash, script_srcs)``."""
    soup = BeautifulSoup(html or "", "lxml")
    title = (soup.title.string.strip() if soup.title and soup.title.string else "")[:300]
    scripts: list[str] = []
    for s in soup.find_all("script"):
        src = s.get("src")
        if src:
            scripts.append(str(src).split("?", 1)[0])
    for tag in soup.find_all(["script", "style", "noscript"]):
        tag.decompose()
    tag_seq: list[str] = []
    for el in soup.find_all(True):
        el_id = el.get("id") or ""
        tag_seq.append(f"{el.name}#{el_id}" if el_id else el.name)
    struct_hash = hashlib.sha256("|".join(tag_seq).encode("utf-8")).hexdigest()[:16]
    visible_text = WHITESPACE_RE.sub(" ", soup.get_text(" ", strip=True)).strip()
    text_hash = hashlib.sha256(visible_text.encode("utf-8", "replace")).hexdigest()[:16]
    return title, struct_hash, text_hash, sorted(set(scripts))


@dataclass
class BaselineProfile:
    probe_status: int | None = None
    title: str = ""
    struct_hash: str = ""
    text_hash: str = ""
    body_sha256: str = ""
    body_length: int = 0
    script_srcs: list[str] = field(default_factory=list)
    is_spa_catchall: bool = False
    root_text_hash: str = ""
    root_struct_hash: str = ""

    def to_dict(self) -> dict:
        return {
            "probe_status": self.probe_status,
            "title": self.title,
            "struct_hash": self.struct_hash,
            "text_hash": self.text_hash,
            "body_sha256": self.body_sha256,
            "body_length": self.body_length,
            "script_srcs": self.script_srcs,
            "is_spa_catchall": self.is_spa_catchall,
        }

    def matches_spa_shell(self, resp: SafeResponse) -> bool:
        """True if ``resp`` is indistinguishable from the generic unrendered SPA shell / soft-404."""
        if not self.is_spa_catchall or resp.status_code != 200:
            return False
        if "html" not in (resp.content_type or "").lower():
            return False
        if resp.sha256 == self.body_sha256:
            return True
        title, struct_h, text_h, scripts = normalize_html_structure(resp.text)
        if struct_h == self.struct_hash and text_h == self.text_hash:
            return True
        if scripts and scripts == self.script_srcs and abs(len(resp.body) - self.body_length) < 128 and text_h == self.text_hash:
            return True
        return False


async def build_baseline(client: SafeHttpClient, base_url: str, root_resp: SafeResponse | None = None) -> BaselineProfile:
    profile = BaselineProfile()
    if root_resp is not None and "html" in (root_resp.content_type or "").lower():
        _, r_struct, r_text, _ = normalize_html_structure(root_resp.text)
        profile.root_struct_hash = r_struct
        profile.root_text_hash = r_text

    rand1 = f"{base_url.rstrip('/')}/__vibescan_nonexistent_{secrets.token_hex(6)}"
    rand2 = f"{base_url.rstrip('/')}/admin/__vibescan_nonexistent_{secrets.token_hex(6)}"
    try:
        r1 = await client.get(rand1, follow_redirects=False, for_asset=True)
    except Exception:
        return profile

    profile.probe_status = r1.status_code
    if r1.status_code == 200 and "html" in (r1.content_type or "").lower():
        title1, struct1, text1, scripts1 = normalize_html_structure(r1.text)
        profile.title = title1
        profile.struct_hash = struct1
        profile.text_hash = text1
        profile.body_sha256 = r1.sha256
        profile.body_length = len(r1.body)
        profile.script_srcs = scripts1
        try:
            r2 = await client.get(rand2, follow_redirects=False, for_asset=True)
            if r2.status_code == 200 and "html" in (r2.content_type or "").lower():
                _, struct2, text2, _ = normalize_html_structure(r2.text)
                profile.is_spa_catchall = struct1 == struct2 and text1 == text2
            else:
                profile.is_spa_catchall = True
        except Exception:
            profile.is_spa_catchall = True
    return profile
