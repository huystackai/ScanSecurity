"""Target scope validation and enforcement.

``ScopePolicy`` compiles an authorized target's ``base_url``, ``allowed_hosts``, and ``scope_config``
into a deterministic policy. Every URL must pass ``check_url`` before any request is issued and on
every redirect hop.
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass, field
from urllib.parse import ParseResult, urljoin, urlparse, urlunparse

DEFAULT_EXCLUDED_PATHS: tuple[str, ...] = (
    "/logout",
    "/signout",
    "/sign-out",
    "/log-out",
    "/api/auth/signout",
    "/auth/logout",
    "/account/delete",
    "/delete-account",
)

DESTRUCTIVE_PATH_TOKENS: tuple[str, ...] = (
    "delete",
    "destroy",
    "drop",
    "purge",
    "wipe",
    "reset-all",
    "truncate",
    "remove",
    "revoke-all",
    "terminate",
    "nuke",
    "unsubscribe",
)


class OutOfScopeError(Exception):
    """Raised when a URL violates the target scope policy."""

    def __init__(self, url: str, reason: str) -> None:
        super().__init__(f"Out of scope {url!r}: {reason}")
        self.url = url
        self.reason = reason


@dataclass
class ScopeConfig:
    include_paths: list[str] = field(default_factory=lambda: ["/"])
    exclude_paths: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDED_PATHS))
    max_depth: int = 4
    max_pages: int = 150
    requests_per_second: float = 5.0
    concurrency: int = 4
    respect_robots: bool = True
    enable_path_probing: bool = True
    render_js: bool = False
    request_timeout_seconds: float = 15.0

    @classmethod
    def from_dict(cls, data: dict | None) -> ScopeConfig:
        if not data:
            return cls()
        include = list(data.get("include_paths") or ["/"])
        exclude = list(data.get("exclude_paths") or list(DEFAULT_EXCLUDED_PATHS))
        for p in DEFAULT_EXCLUDED_PATHS:
            if p not in exclude:
                exclude.append(p)
        return cls(
            include_paths=[_clean_prefix(p) for p in include],
            exclude_paths=[_clean_prefix(p) for p in exclude],
            max_depth=max(0, min(int(data.get("max_depth", 4)), 16)),
            max_pages=max(1, min(int(data.get("max_pages", 150)), 5000)),
            requests_per_second=max(0.2, min(float(data.get("requests_per_second", 5.0)), 100.0)),
            concurrency=max(1, min(int(data.get("concurrency", 4)), 50)),
            respect_robots=bool(data.get("respect_robots", True)),
            enable_path_probing=bool(data.get("enable_path_probing", True)),
            render_js=bool(data.get("render_js", False)),
            request_timeout_seconds=max(2.0, min(float(data.get("request_timeout_seconds", 15.0)), 60.0)),
        )

    def to_dict(self) -> dict:
        return {
            "include_paths": self.include_paths,
            "exclude_paths": self.exclude_paths,
            "max_depth": self.max_depth,
            "max_pages": self.max_pages,
            "requests_per_second": self.requests_per_second,
            "concurrency": self.concurrency,
            "respect_robots": self.respect_robots,
            "enable_path_probing": self.enable_path_probing,
            "render_js": self.render_js,
            "request_timeout_seconds": self.request_timeout_seconds,
        }


def _clean_prefix(prefix: str) -> str:
    p = (prefix or "/").strip()
    if not p.startswith("/"):
        p = "/" + p
    return p


def _normalize_host(host: str) -> str:
    return host.strip().lower().rstrip(".")


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def normalize_target_url(raw_url: str) -> tuple[str, str, int]:
    """Validate and normalize a target base URL. Returns ``(normalized_url, host, port)``."""
    raw = (raw_url or "").strip()
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Target URL must use http or https scheme")
    if not parsed.hostname:
        raise ValueError("Target URL must include a hostname")
    if parsed.username or parsed.password:
        raise ValueError("Target URL must not embed credentials")
    host = _normalize_host(parsed.hostname)
    try:
        port = parsed.port or _default_port(parsed.scheme)
    except ValueError as exc:
        raise ValueError("Invalid port in target URL") from exc
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    netloc = f"{host}:{port}" if port != _default_port(parsed.scheme) else host
    normalized = urlunparse((parsed.scheme, netloc, path.rstrip("/") or "/", "", "", ""))
    return normalized, host, port


def normalize_url(url: str, base_url: str | None = None) -> str | None:
    """Resolve ``url`` against ``base_url`` (if given), strip fragments, and normalize the path."""
    raw = (url or "").strip()
    if not raw or raw.startswith(("javascript:", "mailto:", "tel:", "data:", "blob:", "#")):
        return None
    full = urljoin(base_url, raw) if base_url else raw
    try:
        parsed = urlparse(full)
    except ValueError:
        return None
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    if parsed.username or parsed.password:
        return None
    host = _normalize_host(parsed.hostname)
    try:
        port = parsed.port or _default_port(parsed.scheme)
    except ValueError:
        return None
    path = parsed.path or "/"
    trailing_slash = path.endswith("/") and len(path) > 1
    norm_path = posixpath.normpath(path)
    if not norm_path.startswith("/"):
        norm_path = "/" + norm_path
    if trailing_slash and not norm_path.endswith("/"):
        norm_path += "/"
    netloc = f"{host}:{port}" if port != _default_port(parsed.scheme) else host
    return urlunparse((parsed.scheme.lower(), netloc, norm_path, "", parsed.query, ""))


def path_Looks_destructive(path: str) -> bool:
    lower = path.lower()
    segments = [s for s in lower.split("/") if s]
    for seg in segments:
        for tok in DESTRUCTIVE_PATH_TOKENS:
            if seg == tok or seg.startswith(f"{tok}-") or seg.endswith(f"-{tok}") or seg.startswith(f"{tok}_"):
                return True
    return False


class ScopePolicy:
    """Enforces that every request stays within authorized hosts, ports, schemes, and path rules."""

    def __init__(
        self,
        base_url: str,
        allowed_hosts: list[str] | None = None,
        config: ScopeConfig | dict | None = None,
        allow_Static_assets_any_path: bool = True,
    ) -> None:
        normalized, primary_host, primary_port = normalize_target_url(base_url)
        self.base_url = normalized
        self.primary_host = primary_host
        self.primary_port = primary_port
        self.base_parsed: ParseResult = urlparse(normalized)
        self.config = config if isinstance(config, ScopeConfig) else ScopeConfig.from_dict(config)
        self.allow_static_assets_any_path = allow_Static_assets_any_path

        hosts = {primary_host}
        for h in allowed_hosts or []:
            h_clean = _normalize_host(h)
            if not h_clean:
                continue
            if "*" in h_clean or "/" in h_clean or ":" in h_clean:
                raise ValueError(f"Wildcard or malformed host {h!r} is not permitted in allowed_hosts")
            hosts.add(h_clean)
        self.allowed_hosts: frozenset[str] = frozenset(hosts)
        self.allowed_ports: frozenset[int] = frozenset({80, 443, primary_port})

    def check_url(self, url: str, *, for_asset: bool = False) -> tuple[bool, str]:
        norm = normalize_url(url, self.base_url)
        if not norm:
            return False, "invalid or unsupported URL"
        parsed = urlparse(norm)
        if parsed.scheme not in ("http", "https"):
            return False, f"disallowed scheme {parsed.scheme!r}"
        if self.base_parsed.scheme == "https" and parsed.scheme != "https":
            return False, "downgrade from https to http is not permitted"
        host = _normalize_host(parsed.hostname or "")
        if host not in self.allowed_hosts:
            return False, f"host {host!r} is not in allowed_hosts {sorted(self.allowed_hosts)}"
        port = parsed.port or _default_port(parsed.scheme)
        if port not in self.allowed_ports:
            return False, f"port {port} is not in allowed ports {sorted(self.allowed_ports)}"
        path = parsed.path or "/"
        for ex in self.config.exclude_paths:
            if path == ex or path.startswith(ex.rstrip("/") + "/"):
                return False, f"path {path!r} matches excluded prefix {ex!r}"
        if for_asset and self.allow_static_assets_any_path:
            return True, "ok"
        if self.config.include_paths:
            matched = any(
                inc == "/" or path == inc.rstrip("/") or path.startswith(inc.rstrip("/") + "/")
                for inc in self.config.include_paths
            )
            if not matched:
                return False, f"path {path!r} is outside include_paths {self.config.include_paths}"
        return True, "ok"

    def assert_in_scope(self, url: str, *, for_asset: bool = False) -> str:
        norm = normalize_url(url, self.base_url)
        if not norm:
            raise OutOfScopeError(url, "invalid URL")
        ok, reason = self.check_url(norm, for_asset=for_asset)
        if not ok:
            raise OutOfScopeError(norm, reason)
        return norm

    def is_in_scope(self, url: str, *, for_asset: bool = False) -> bool:
        return self.check_url(url, for_asset=for_asset)[0]

    def resolve_in_scope(self, href: str, current_url: str | None = None, *, for_asset: bool = False) -> str | None:
        norm = normalize_url(href, current_url or self.base_url)
        if not norm:
            return None
        ok, _ = self.check_url(norm, for_asset=for_asset)
        return norm if ok else None
