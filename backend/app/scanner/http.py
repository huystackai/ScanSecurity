"""Safe, non-destructive HTTP client used by every scanner module.

Guarantees:
1. Only safe methods (``GET``, ``HEAD``, ``OPTIONS``) are ever sent.
2. Every request URL and every redirect hop is checked against ``ScopePolicy``.
3. Every TCP connection goes through ``SafeNetworkBackend`` (DNS resolution + IP policy check +
   direct connection to the validated IP; env proxies disabled).
4. Per-scan request budget, concurrency semaphore, token-bucket rate limiter, response-size cap,
   and cooperative cancellation hook.
"""

from __future__ import annotations

import asyncio
import hashlib
import ssl
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from urllib.parse import urljoin

import certifi
import httpcore
import httpx

from app.scanner.netguard import BlockedDestinationError, NetGuard, NetworkPolicy, SafeNetworkBackend
from app.scanner.scope import OutOfScopeError, ScopePolicy

SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})


class DisallowedMethodError(Exception):
    """Raised if any caller attempts a non-safe HTTP method."""


class RequestBudgetExceededError(Exception):
    """Raised when a scan exceeds its total request budget."""


class ScanCancelledError(Exception):
    """Raised when cooperative cancellation is triggered."""


@dataclass
class RedirectHop:
    url: str
    status_code: int
    location: str

    def to_dict(self) -> dict:
        return {"url": self.url, "status": self.status_code, "location": self.location}


@dataclass
class SafeResponse:
    url: str
    final_url: str
    status_code: int
    headers: dict[str, str]
    body: bytes
    content_type: str
    redirect_chain: list[RedirectHop] = field(default_factory=list)
    truncated: bool = False
    elapsed_ms: int = 0
    blocked_redirect: str | None = None

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.body).hexdigest()

    def header(self, name: str, default: str | None = None) -> str | None:
        return self.headers.get(name.lower(), default)


class _AsyncRateLimiter:
    def __init__(self, rps: float) -> None:
        self.interval = 1.0 / max(rps, 0.1)
        self._lock = asyncio.Lock()
        self._next_allowed = 0.0

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            if now < self._next_allowed:
                await asyncio.sleep(self._next_allowed - now)
            self._next_allowed = max(now, self._next_allowed) + self.interval


class SafeAsyncTransport(httpx.AsyncBaseTransport):
    """httpx transport backed by an httpcore pool using ``SafeNetworkBackend``."""

    def __init__(self, guard: NetGuard, verify: bool | ssl.SSLContext = True, max_connections: int = 20) -> None:
        if isinstance(verify, ssl.SSLContext):
            ssl_ctx = verify
        else:
            ssl_ctx = ssl.create_default_context(cafile=certifi.where())
            if not verify:
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
        self.backend = SafeNetworkBackend(guard)
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl_ctx,
            max_connections=max_connections,
            max_keepalive_connections=max(4, max_connections // 2),
            keepalive_expiry=15.0,
            http1=True,
            http2=False,
            network_backend=self.backend,
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        req = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )
        resp = await self._pool.handle_async_request(req)
        return httpx.Response(
            status_code=resp.status,
            headers=resp.headers,
            stream=_HttpcoreStreamAdapter(resp.stream),
            extensions=resp.extensions,
        )

    async def aclose(self) -> None:
        await self._pool.aclose()


class _HttpcoreStreamAdapter(httpx.AsyncByteStream):
    def __init__(self, stream) -> None:  # type: ignore[no-untyped-def]
        self._stream = stream

    async def __aiter__(self):  # type: ignore[override]
        async for part in self._stream:
            yield part

    async def aclose(self) -> None:
        await self._stream.aclose()


CancelCheck = Callable[[], Awaitable[bool]]


class SafeHttpClient:
    """Scope-enforcing, SSRF-guarded, rate-limited HTTP client for passive/non-destructive checks."""

    def __init__(
        self,
        scope: ScopePolicy,
        guard: NetGuard | None = None,
        *,
        user_agent: str = "VibeScan/0.1 (authorized security assessment; non-destructive)",
        max_requests: int = 3000,
        max_response_bytes: int = 5 * 1024 * 1024,
        max_redirects: int = 5,
        cancel_check: CancelCheck | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.scope = scope
        self.guard = guard or NetGuard(NetworkPolicy(allow_private=False))
        self.user_agent = user_agent
        self.max_requests = max_requests
        self.max_response_bytes = max_response_bytes
        self.max_redirects = max_redirects
        self.cancel_check = cancel_check
        self.requests_made = 0
        self._semaphore = asyncio.Semaphore(scope.config.concurrency)
        self._limiter = _AsyncRateLimiter(scope.config.requests_per_second)
        self._transport = transport or SafeAsyncTransport(
            self.guard, max_connections=max(8, scope.config.concurrency * 2)
        )
        self._client = httpx.AsyncClient(
            transport=self._transport,
            follow_redirects=False,
            trust_env=False,
            timeout=httpx.Timeout(scope.config.request_timeout_seconds, connect=min(8.0, scope.config.request_timeout_seconds)),
            headers={"User-Agent": self.user_agent, "Accept": "text/html,application/json;q=0.9,*/*;q=0.8"},
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> SafeHttpClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        follow_redirects: bool = True,
        for_asset: bool = False,
        max_bytes: int | None = None,
        allow_cross_host_Validate: Callable[[str], None] | None = None,
    ) -> SafeResponse:
        m = method.upper().strip()
        if m not in SAFE_METHODS:
            raise DisallowedMethodError(f"HTTP method {m!r} is forbidden; VibeScan only allows {sorted(SAFE_METHODS)}")
        if self.cancel_check and await self.cancel_check():
            raise ScanCancelledError("Scan cancelled by operator")

        if allow_cross_host_Validate is not None:
            allow_cross_host_Validate(url)
            current_url = url
        else:
            current_url = self.scope.assert_in_scope(url, for_asset=for_asset)

        redirect_chain: list[RedirectHop] = []
        blocked_redirect: str | None = None
        cap = min(max_bytes or self.max_response_bytes, self.max_response_bytes)
        t0 = time.monotonic()

        for _hop in range(self.max_redirects + 1):
            if self.requests_made >= self.max_requests:
                raise RequestBudgetExceededError(f"Scan request budget ({self.max_requests}) reached")
            await self._limiter.acquire()
            async with self._semaphore:
                self.requests_made += 1
                req = self._client.build_request(m, current_url, headers=headers)
                resp = await self._client.send(req, stream=True)
                try:
                    status = resp.status_code
                    resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                    content_type = resp_headers.get("content-type", "")
                    location = resp_headers.get("location")
                    if follow_redirects and status in (301, 302, 303, 307, 308) and location:
                        await resp.aclose()
                        next_url = urljoin(current_url, location)
                        redirect_chain.append(RedirectHop(url=current_url, status_code=status, location=next_url))
                        try:
                            if allow_cross_host_Validate is not None:
                                allow_cross_host_Validate(next_url)
                                current_url = next_url
                            else:
                                current_url = self.scope.assert_in_scope(next_url, for_asset=for_asset)
                        except OutOfScopeError as exc:
                            blocked_redirect = f"{next_url} ({exc.reason})"
                            return SafeResponse(
                                url=url,
                                final_url=current_url,
                                status_code=status,
                                headers=resp_headers,
                                body=b"",
                                content_type=content_type,
                                redirect_chain=redirect_chain,
                                elapsed_ms=int((time.monotonic() - t0) * 1000),
                                blocked_redirect=blocked_redirect,
                            )
                        continue

                    chunks: list[bytes] = []
                    total = 0
                    truncated = False
                    if m != "HEAD":
                        async for chunk in resp.aiter_bytes():
                            if total + len(chunk) > cap:
                                chunks.append(chunk[: cap - total])
                                truncated = True
                                break
                            chunks.append(chunk)
                            total += len(chunk)
                    body = b"".join(chunks)
                finally:
                    await resp.aclose()

                return SafeResponse(
                    url=url,
                    final_url=current_url,
                    status_code=status,
                    headers=resp_headers,
                    body=body,
                    content_type=content_type,
                    redirect_chain=redirect_chain,
                    truncated=truncated,
                    elapsed_ms=int((time.monotonic() - t0) * 1000),
                )

        raise httpx.TooManyRedirects(f"Exceeded {self.max_redirects} redirects for {url}")

    async def get(self, url: str, **kw) -> SafeResponse:  # type: ignore[no-untyped-def]
        return await self.request("GET", url, **kw)

    async def head(self, url: str, **kw) -> SafeResponse:  # type: ignore[no-untyped-def]
        return await self.request("HEAD", url, **kw)

    async def options(self, url: str, **kw) -> SafeResponse:  # type: ignore[no-untyped-def]
        return await self.request("OPTIONS", url, **kw)


def build_netguard_from_settings() -> NetGuard:
    from app.config import get_settings

    s = get_settings()
    policy = NetworkPolicy(allow_private=s.allow_private_targets, private_allowlist=s.private_networks)
    return NetGuard(policy)


__all__ = [
    "BlockedDestinationError",
    "DisallowedMethodError",
    "OutOfScopeError",
    "RedirectHop",
    "RequestBudgetExceededError",
    "SAFE_METHODS",
    "SafeAsyncTransport",
    "SafeHttpClient",
    "SafeResponse",
    "ScanCancelledError",
    "build_netguard_from_settings",
]
