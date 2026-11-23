"""Network destination policy and SSRF protection.

``NetGuard`` resolves hostnames and rejects any destination that is not a public (global) address,
unless it is inside an explicitly configured lab allowlist. ``SafeNetworkBackend`` plugs into
httpcore so that the *validated* IP is the one actually connected to (no DNS-rebinding window),
while TLS SNI / certificate validation still use the original hostname.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import typing
from collections.abc import Awaitable, Callable, Iterable

import httpcore

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# Always blocked, even in lab mode: cloud metadata services and non-unicast/unspecified space.
ALWAYS_BLOCKED: tuple[IPNetwork, ...] = tuple(
    ipaddress.ip_network(n)
    for n in (
        "169.254.169.254/32",  # AWS/GCP/Azure/OpenStack metadata
        "169.254.170.2/32",  # AWS ECS task metadata
        "169.254.169.253/32",  # AWS DNS
        "100.100.100.200/32",  # Alibaba metadata
        "192.0.0.192/32",  # Oracle Cloud metadata
        "fd00:ec2::254/128",  # AWS IMDS IPv6
        "0.0.0.0/8",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "255.255.255.255/32",
        "::/128",
        "ff00::/8",
    )
)

BLOCKED_HOSTNAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
        "metadata",
        "metadata.google.internal",
        "metadata.goog",
        "instance-data",
        "instance-data.ec2.internal",
        "kubernetes.default",
        "kubernetes.default.svc",
    }
)
BLOCKED_HOST_SUFFIXES = (".localhost", ".internal", ".local", ".localdomain", ".svc", ".cluster.local", ".home.arpa")

NAT64 = ipaddress.ip_network("64:ff9b::/96")
SIX_TO_FOUR = ipaddress.ip_network("2002::/16")

Resolver = Callable[[str, int], Awaitable[list[str]]]


class BlockedDestinationError(Exception):
    """Raised when a destination host or IP violates the network policy."""

    def __init__(self, host: str, reason: str) -> None:
        super().__init__(f"Blocked destination {host!r}: {reason}")
        self.host = host
        self.reason = reason


def _embedded_ipv4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip in NAT64:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    if ip.sixtofour is not None:
        return ip.sixtofour
    if ip.teredo is not None:
        return ip.teredo[1]
    return None


class NetworkPolicy:
    def __init__(self, allow_private: bool = False, private_allowlist: Iterable[IPNetwork] = ()) -> None:
        self.allow_private = allow_private
        self.private_allowlist = tuple(private_allowlist)

    def check_ip(self, ip: IPAddress | str) -> tuple[bool, str]:
        if isinstance(ip, str):
            try:
                ip = ipaddress.ip_address(ip.split("%", 1)[0])
            except ValueError:
                return False, "invalid IP address"
        if isinstance(ip, ipaddress.IPv6Address):
            embedded = _embedded_ipv4(ip)
            if embedded is not None:
                ok, reason = self.check_ip(embedded)
                if not ok:
                    return False, f"embedded IPv4 {embedded}: {reason}"
        for net in ALWAYS_BLOCKED:
            if ip.version == net.version and ip in net:
                return False, f"address {ip} is in always-blocked range {net}"
        if ip.is_global and not ip.is_multicast:
            return True, "public address"
        if self.allow_private and any(ip.version == n.version and ip in n for n in self.private_allowlist):
            return True, "address in explicit lab allowlist"
        kind = (
            "loopback"
            if ip.is_loopback
            else "link-local"
            if ip.is_link_local
            else "private"
            if ip.is_private
            else "reserved/non-global"
        )
        return False, f"{kind} address {ip} is not allowed"

    def check_hostname(self, host: str) -> tuple[bool, str]:
        h = host.lower().rstrip(".")
        try:
            ipaddress.ip_address(h.strip("[]"))
            return True, "ip literal"
        except ValueError:
            pass
        if self.allow_private:
            return True, "lab mode"
        if h in BLOCKED_HOSTNAMES or h.endswith(BLOCKED_HOST_SUFFIXES) or "." not in h:
            return False, f"hostname {h!r} refers to an internal name"
        return True, "ok"


async def system_resolver(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    ips: list[str] = []
    for _family, _type, _proto, _canon, sockaddr in infos:
        ip = str(sockaddr[0])
        if ip not in ips:
            ips.append(ip)
    return ips


class NetGuard:
    def __init__(
        self,
        policy: NetworkPolicy,
        resolver: Resolver | None = None,
        resolve_timeout: float = 5.0,
    ) -> None:
        self.policy = policy
        self._resolver = resolver or system_resolver
        self.resolve_timeout = resolve_timeout

    async def resolve(self, host: str, port: int) -> list[str]:
        """Resolve ``host`` and return addresses only if *every* address is allowed."""
        host_clean = host.strip("[]").rstrip(".")
        ok, reason = self.policy.check_hostname(host_clean)
        if not ok:
            raise BlockedDestinationError(host, reason)
        try:
            literal = ipaddress.ip_address(host_clean)
        except ValueError:
            literal = None
        if literal is not None:
            ok, reason = self.policy.check_ip(literal)
            if not ok:
                raise BlockedDestinationError(host, reason)
            return [str(literal)]
        try:
            ips = await asyncio.wait_for(self._resolver(host_clean, port), timeout=self.resolve_timeout)
        except (TimeoutError, OSError, socket.gaierror) as exc:
            raise BlockedDestinationError(host, f"DNS resolution failed: {exc}") from exc
        if not ips:
            raise BlockedDestinationError(host, "DNS returned no addresses")
        for ip in ips:
            ok, reason = self.policy.check_ip(ip)
            if not ok:
                # Reject the whole host if any record is internal (prevents mixed-record rebinding tricks).
                raise BlockedDestinationError(host, reason)
        return ips


class SafeNetworkBackend(httpcore.AsyncNetworkBackend):
    """httpcore backend that re-validates DNS on every new connection and connects to the vetted IP."""

    def __init__(self, guard: NetGuard, inner: httpcore.AsyncNetworkBackend | None = None) -> None:
        self.guard = guard
        self.inner = inner or httpcore.AnyIOBackend()
        self.connections: list[tuple[str, str, int]] = []

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: typing.Iterable[typing.Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        ips = await self.guard.resolve(host, port)
        last_exc: Exception | None = None
        for ip in ips:
            try:
                stream = await self.inner.connect_tcp(
                    ip, port, timeout=timeout, local_address=local_address, socket_options=socket_options
                )
                self.connections.append((host, ip, port))
                return stream
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last_exc = exc
        assert last_exc is not None
        raise last_exc

    async def connect_unix_socket(self, path: str, timeout: float | None = None, socket_options: typing.Any = None):  # type: ignore[override]
        raise httpcore.ConnectError("Unix sockets are disabled by the VibeScan network policy")

    async def sleep(self, seconds: float) -> None:
        await self.inner.sleep(seconds)
