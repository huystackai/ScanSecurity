"""robots.txt parser that both checks crawl permissions and harvests referenced paths (passive)."""

from __future__ import annotations

import urllib.robotparser
from dataclasses import dataclass, field

from app.scanner.http import SafeHttpClient


@dataclass
class RobotsPolicy:
    fetched: bool = False
    raw_content: str = ""
    disallowed_paths: list[str] = field(default_factory=list)
    allowed_paths: list[str] = field(default_factory=list)
    sitemaps: list[str] = field(default_factory=list)
    _parser: urllib.robotparser.RobotFileParser = field(default_factory=urllib.robotparser.RobotFileParser)

    def can_fetch(self, user_agent: str, url: str) -> bool:
        if not self.fetched:
            return True
        try:
            return self._parser.can_fetch(user_agent, url)
        except Exception:
            return True


async def fetch_robots(client: SafeHttpClient, base_url: str) -> RobotsPolicy:
    policy = RobotsPolicy()
    robots_url = f"{base_url.rstrip('/')}/robots.txt"
    try:
        resp = await client.get(robots_url, follow_redirects=True, for_asset=True, max_bytes=128 * 1024)
    except Exception:
        return policy
    if resp.status_code != 200 or "html" in (resp.content_type or "").lower():
        return policy

    text = resp.text
    policy.fetched = True
    policy.raw_content = text[:16384]
    lines = text.splitlines()
    policy._parser.parse(lines)
    for raw_line in lines:
        line = raw_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        directive, value = [p.strip() for p in line.split(":", 1)]
        d_low = directive.lower()
        if d_low == "disallow" and value.startswith("/"):
            clean = value.split("*", 1)[0].rstrip("$") or "/"
            if clean not in policy.disallowed_paths:
                policy.disallowed_paths.append(clean)
        elif d_low == "allow" and value.startswith("/"):
            clean = value.split("*", 1)[0].rstrip("$") or "/"
            if clean not in policy.allowed_paths:
                policy.allowed_paths.append(clean)
        elif d_low == "sitemap" and value.startswith(("http://", "https://")):
            if value not in policy.sitemaps:
                policy.sitemaps.append(value)
    return policy
