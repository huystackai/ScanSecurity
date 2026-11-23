"""Target ownership and authorization verification (DNS TXT, well-known file, HTML meta tag, lab attestation)."""

from __future__ import annotations

import asyncio
import datetime as dt

import dns.asyncresolver
import dns.exception
import httpx
from bs4 import BeautifulSoup

from app.config import Settings, get_settings
from app.db.base import utcnow
from app.db.models import AuthorizationStatus, Target, VerificationMethod
from app.scanner.http import SafeHttpClient, build_netguard_from_settings
from app.scanner.netguard import BlockedDestinationError, NetGuard
from app.scanner.scope import ScopeConfig, ScopePolicy

WELL_KNOWN_PATH = "/.well-known/vibescan-verify.txt"
META_NAME = "vibescan-verification"


def verification_instructions(target: Target, settings: Settings | None = None) -> dict:
    settings = settings or get_settings()
    token = target.verification_token
    base = target.base_url.rstrip("/")
    return {
        "token": token,
        "instructions": {
            "dns_txt": {
                "record_name": f"_vibescan.{target.primary_host}",
                "fallback_record_name": target.primary_host,
                "record_type": "TXT",
                "record_value": token,
            },
            "well_known": {
                "url": f"{base}{WELL_KNOWN_PATH}",
                "content": token,
            },
            "meta_tag": {
                "url": f"{base}/",
                "html": f'<meta name="{META_NAME}" content="{token}" />',
            },
        },
        "attestation_allowed": settings.attestation_allowed,
    }


def is_target_authorized(target: Target, settings: Settings | None = None) -> tuple[bool, str]:
    settings = settings or get_settings()
    if target.archived:
        return False, "Target is archived"
    if target.authorization_status == AuthorizationStatus.revoked.value:
        return False, "Target authorization has been revoked"
    if target.authorization_status == AuthorizationStatus.attested.value:
        if not settings.attestation_allowed:
            return False, "Attestation-only targets require lab_mode and allow_attestation_only"
        return True, "Authorized via lab attestation"
    if target.authorization_status != AuthorizationStatus.verified.value or not target.verified_at:
        return False, "Target ownership has not been verified"
    expiry = target.verified_at + dt.timedelta(days=settings.verification_validity_days)
    if utcnow() > expiry:
        return False, f"Target verification expired on {expiry.isoformat()}"
    return True, "Verified"


def verification_expires_at(target: Target, settings: Settings | None = None) -> dt.datetime | None:
    settings = settings or get_settings()
    if not target.verified_at:
        return None
    return target.verified_at + dt.timedelta(days=settings.verification_validity_days)


async def verify_dns_txt(host: str, expected_token: str, resolver: dns.asyncresolver.Resolver | None = None) -> tuple[bool, str]:
    res = resolver or dns.asyncresolver.Resolver()
    res.lifetime = 5.0
    candidates = [f"_vibescan.{host}", host]
    for qname in candidates:
        try:
            answer = await asyncio.wait_for(res.resolve(qname, "TXT"), timeout=5.0)
            for rdata in answer:
                txt = "".join(s.decode("utf-8", "replace") if isinstance(s, bytes) else str(s) for s in rdata.strings)
                if expected_token in txt.strip():
                    return True, f"Matched DNS TXT record on {qname}"
        except (dns.exception.DNSException, TimeoutError):
            continue
    return False, f"No matching TXT record found at _vibescan.{host} or {host}"


async def verify_well_known(
    target: Target,
    *,
    guard: NetGuard | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> tuple[bool, str]:
    scope = ScopePolicy(target.base_url, target.allowed_hosts, ScopeConfig(include_paths=["/"], max_pages=2))
    url = f"{target.base_url.rstrip('/')}{WELL_KNOWN_PATH}"
    try:
        async with SafeHttpClient(
            scope, guard or build_netguard_from_settings(), max_requests=3, max_response_bytes=16384, transport=transport
        ) as client:
            resp = await client.get(url, follow_redirects=False)
    except (BlockedDestinationError, httpx.HTTPError) as exc:
        return False, f"Verification request failed: {exc}"
    if resp.status_code != 200:
        return False, f"{url} returned HTTP {resp.status_code} (expected 200)"
    ct = (resp.content_type or "").lower()
    if "html" in ct:
        return False, f"{url} returned HTML (likely SPA fallback), expected plain text token"
    if target.verification_token in resp.text.strip():
        return True, f"Matched token at {url}"
    return False, f"Token not present in {url}"


async def verify_meta_tag(
    target: Target,
    *,
    guard: NetGuard | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> tuple[bool, str]:
    scope = ScopePolicy(target.base_url, target.allowed_hosts, ScopeConfig(include_paths=["/"], max_pages=2))
    url = f"{target.base_url.rstrip('/')}/"
    try:
        async with SafeHttpClient(
            scope, guard or build_netguard_from_settings(), max_requests=4, max_response_bytes=512 * 1024, transport=transport
        ) as client:
            resp = await client.get(url, follow_redirects=True)
    except (BlockedDestinationError, httpx.HTTPError) as exc:
        return False, f"Verification request failed: {exc}"
    if resp.status_code != 200:
        return False, f"{url} returned HTTP {resp.status_code}"
    soup = BeautifulSoup(resp.text, "lxml")
    for meta in soup.find_all("meta", attrs={"name": META_NAME}):
        content = (meta.get("content") or "").strip()
        if content == target.verification_token:
            return True, f"Matched <meta name='{META_NAME}'> on {resp.final_url}"
    return False, f"<meta name='{META_NAME}'> with matching token not found on {resp.final_url}"


async def perform_target_verification(
    target: Target,
    method: str,
    *,
    guard: NetGuard | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
    dns_resolver: dns.asyncresolver.Resolver | None = None,
) -> tuple[bool, str]:
    if method == VerificationMethod.dns_txt.value:
        ok, detail = await verify_dns_txt(target.primary_host, target.verification_token, resolver=dns_resolver)
    elif method == VerificationMethod.well_known.value:
        ok, detail = await verify_well_known(target, guard=guard, transport=transport)
    elif method == VerificationMethod.meta_tag.value:
        ok, detail = await verify_meta_tag(target, guard=guard, transport=transport)
    else:
        return False, f"Unsupported verification method {method!r}"
    if ok:
        target.authorization_status = AuthorizationStatus.verified.value
        target.verification_method = method
        target.verified_at = utcnow()
    return ok, detail
