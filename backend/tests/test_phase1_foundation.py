"""Unit tests for Phase 1 security boundaries: NetGuard (SSRF), ScopePolicy, SafeHttpClient, redaction, auth, and target verification."""

from __future__ import annotations

import ipaddress

import httpx
import pytest

from app.core.redaction import mask_secret, redact_text
from app.scanner.http import (
    DisallowedMethodError,
    RequestBudgetExceededError,
    SafeHttpClient,
    ScanCancelledError,
)
from app.scanner.netguard import BlockedDestinationError, NetGuard, NetworkPolicy
from app.scanner.scope import OutOfScopeError, ScopeConfig, ScopePolicy, path_Looks_destructive
from app.scanner.secrets import detect_secrets


class TestNetworkPolicyAndSSRF:
    @pytest.mark.parametrize(
        "ip_str",
        [
            "127.0.0.1",
            "127.0.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.1",
            "169.254.169.254",
            "169.254.170.2",
            "100.64.0.1",
            "100.100.100.200",
            "192.0.0.192",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "fd00:ec2::254",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "64:ff9b::169.254.169.254",
            "2002:7f00:0001::1",
        ],
    )
    def test_blocks_private_loopback_metadata_and_mapped_ipv6(self, ip_str: str) -> None:
        policy = NetworkPolicy(allow_private=False)
        ok, reason = policy.check_ip(ip_str)
        assert not ok, f"Expected {ip_str} to be blocked, got reason={reason}"

    def test_allows_public_ip(self) -> None:
        policy = NetworkPolicy(allow_private=False)
        ok, _ = policy.check_ip("93.184.216.34")
        assert ok

    def test_lab_allowlist_still_blocks_cloud_metadata(self) -> None:
        policy = NetworkPolicy(
            allow_private=True,
            private_allowlist=[
                ipaddress.ip_network("127.0.0.0/8"),
                ipaddress.ip_network("169.254.0.0/16"),
            ],
        )
        assert policy.check_ip("127.0.0.1")[0] is True
        # Even if someone misconfigures 169.254.0.0/16 in the lab allowlist, IMDS remains blocked.
        assert policy.check_ip("169.254.169.254")[0] is False
        assert policy.check_ip("169.254.170.2")[0] is False
        assert policy.check_ip("fd00:ec2::254")[0] is False

    @pytest.mark.parametrize(
        "host",
        ["localhost", "metadata.google.internal", "app.internal", "db.local", "redis", "api.svc.cluster.local"],
    )
    def test_blocks_internal_hostnames(self, host: str) -> None:
        policy = NetworkPolicy(allow_private=False)
        ok, _ = policy.check_hostname(host)
        assert not ok

    async def test_netguard_rejects_mixed_dns_records(self) -> None:
        async def fake_resolver(host: str, port: int) -> list[str]:
            return ["93.184.216.34", "127.0.0.1"]

        guard = NetGuard(NetworkPolicy(allow_private=False), resolver=fake_resolver)
        with pytest.raises(BlockedDestinationError):
            await guard.resolve("rebind.example.com", 443)


class TestScopePolicy:
    def test_host_scheme_and_path_enforcement(self) -> None:
        scope = ScopePolicy(
            "https://app.example.com",
            allowed_hosts=["app.example.com", "api.app.example.com"],
            config=ScopeConfig(include_paths=["/app", "/api"], exclude_paths=["/app/logout"]),
        )
        assert scope.is_in_scope("https://app.example.com/app/dashboard")
        assert scope.is_in_scope("https://api.app.example.com/api/v1/users")
        # Disallow HTTP downgrade when target is HTTPS
        assert not scope.is_in_scope("http://app.example.com/app/dashboard")
        # Disallow other subdomains
        assert not scope.is_in_scope("https://evil.example.com/app/dashboard")
        # Disallow excluded paths
        assert not scope.is_in_scope("https://app.example.com/app/logout")
        # Disallow out-of-include paths for page navigation, but allow static assets
        assert not scope.is_in_scope("https://app.example.com/marketing")
        assert scope.is_in_scope("https://app.example.com/_next/static/chunk.js", for_asset=True)

    def test_rejects_wildcard_hosts_and_embedded_credentials(self) -> None:
        with pytest.raises(ValueError):
            ScopePolicy("https://app.example.com", allowed_hosts=["*.example.com"])
        with pytest.raises(ValueError):
            ScopePolicy("https://user:pass@app.example.com")

    def test_destructive_path_detection(self) -> None:
        assert path_Looks_destructive("/api/users/delete")
        assert path_Looks_destructive("/admin/purge-cache")
        assert not path_Looks_destructive("/admin/dashboard")


class TestSafeHttpClient:
    async def test_forbids_unsafe_methods_and_out_of_scope_redirects(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/to-external":
                return httpx.Response(302, headers={"Location": "https://evil.attacker.invalid/steal"})
            if request.url.path == "/to-logout":
                return httpx.Response(302, headers={"Location": "/logout"})
            if request.url.path == "/big":
                return httpx.Response(200, content=b"A" * 5000, headers={"Content-Type": "text/plain"})
            return httpx.Response(200, content=b"ok", headers={"Content-Type": "text/plain"})

        scope = ScopePolicy(
            "https://app.example.com",
            config=ScopeConfig(requests_per_second=20.0, concurrency=4),
        )
        transport = httpx.MockTransport(handler)
        async with SafeHttpClient(scope, max_requests=3, max_response_bytes=1024, transport=transport) as client:
            for bad_method in ("POST", "PUT", "PATCH", "DELETE"):
                with pytest.raises(DisallowedMethodError):
                    await client.request(bad_method, "https://app.example.com/")

            with pytest.raises(OutOfScopeError):
                await client.get("https://other.example.com/")

            r_ext = await client.get("https://app.example.com/to-external")
            assert r_ext.blocked_redirect is not None
            assert "evil.attacker.invalid" in r_ext.blocked_redirect

            r_logout = await client.get("https://app.example.com/to-logout")
            assert r_logout.blocked_redirect is not None

            r_big = await client.get("https://app.example.com/big")
            assert r_big.truncated is True
            assert len(r_big.body) == 1024

            with pytest.raises(RequestBudgetExceededError):
                await client.get("https://app.example.com/over-budget")

    async def test_cooperative_cancellation(self) -> None:
        scope = ScopePolicy("https://app.example.com")
        transport = httpx.MockTransport(lambda req: httpx.Response(200, text="ok"))

        async def cancelled() -> bool:
            return True

        async with SafeHttpClient(scope, cancel_check=cancelled, transport=transport) as client:
            with pytest.raises(ScanCancelledError):
                await client.get("https://app.example.com/")


class TestSecretsAndRedaction:
    def test_distinguishes_supabase_anon_vs_service_role_and_masks(self) -> None:
        import base64
        import json

        def make_jwt(role: str) -> str:
            hdr = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
            body = (
                base64.urlsafe_b64encode(json.dumps({"iss": "supabase", "ref": "xyz", "role": role}).encode())
                .decode()
                .rstrip("=")
            )
            return f"{hdr}.{body}.signature_part_1234567890"

        anon = make_jwt("anon")
        service = make_jwt("service_role")
        stripe_raw = "sk" + "_live_" + "51H9abcDEFGHIJKLMNOPQRSTUV12345"
        js = f'const a = "{anon}"; const s = "{service}"; const k = "{stripe_raw}";'

        matches = detect_secrets(js, "/assets/app.js")
        by_name = {m.name: m for m in matches}
        assert "Supabase anon (public) key" in by_name
        assert by_name["Supabase anon (public) key"].severity == "info"
        assert by_name["Supabase anon (public) key"].kind == "public_identifier"

        assert "Supabase service_role key" in by_name
        assert by_name["Supabase service_role key"].severity == "critical"
        assert by_name["Supabase service_role key"].kind == "secret"

        assert "Stripe/Clerk secret key" in by_name
        assert by_name["Stripe/Clerk secret key"].severity == "critical"

        for m in matches:
            assert stripe_raw not in m.masked
            assert stripe_raw not in m.snippet
            assert service not in m.masked
            assert service not in m.snippet

        redacted = redact_text(f"Contact alice@example.com with key {stripe_raw}")
        assert stripe_raw not in redacted
        assert "alice@example.com" not in redacted
        assert mask_secret(stripe_raw) in redacted
