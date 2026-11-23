"""Sensitive data, PII, and extended secret exposure detection (Module H).

Enforces strict evidence redaction and false-positive reduction:
- Payment Card Numbers (PAN) require valid Luhn checksum AND card-network prefix/length.
- Government IDs (Vietnamese CCCD/CMND, SSN, Tax ID) require explicit nearby context keywords.
- Personal email exposure ignores single public role addresses (support@, info@, contact@, etc.)
  and flags bulk disclosure (>= 5 distinct personal emails in a response).
- Raw PII/secrets are masked immediately and never leave this module.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.core.redaction import fingerprint, mask_secret, redact_text
from app.scanner.api_discovery import DiscoveredEndpoint
from app.scanner.config_exposure import RecoveredSourceFile
from app.scanner.crawler import CrawlOutcome
from app.scanner.findings import FindingDraft

# Payment card candidate (13-19 digits with optional spaces or hyphens, major networks: 3/4/5/6)
CARD_CANDIDATE_RE = re.compile(r"(?<!\d)(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))(?:[ -]?\d{4}){2,3}(?:[ -]?\d{1,3})?(?!\d)")

# Context-aware Government IDs (Vietnamese CCCD 12 digits / CMND 9 digits / US SSN)
VN_ID_CONTEXT_RE = re.compile(
    r"""(?i)(?:cccd|cmnd|can_?cuoc|chung_?minh|citizen_?id|national_?id|identity_?(?:number|no|card)|so_?cmnd|so_?cccd|id_?number)["']?\s*[:=]\s*["']?(\d{9}|\d{12})["']?"""
)
US_SSN_CONTEXT_RE = re.compile(
    r"""(?i)(?:ssn|social_?security(?:_?number)?)["']?\s*[:=]\s*["']?(\d{3}-\d{2}-\d{4})["']?"""
)

# Emails & role-based public addresses
EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-]{1,64})@([A-Za-z0-9.-]{1,128}\.[A-Za-z]{2,12})\b")
PUBLIC_EMAIL_PREFIXES: frozenset[str] = frozenset(
    {
        "info",
        "support",
        "contact",
        "hello",
        "help",
        "sales",
        "admin",
        "security",
        "privacy",
        "legal",
        "noreply",
        "no-reply",
        "donotreply",
        "press",
        "media",
        "careers",
        "jobs",
        "billing",
        "team",
        "office",
        "webmaster",
        "postmaster",
        "abuse",
        "example",
        "test",
    }
)
PLACEHOLDER_EMAIL_DOMAINS: frozenset[str] = frozenset(
    {"example.com", "example.org", "example.net", "test.com", "localhost.localdomain", "sentry.io", "w3.org"}
)

# Context-aware phone numbers in JSON/API payloads
JSON_PHONE_RE = re.compile(
    r"""(?i)"(?:phone|phone_?number|mobile|tel|telephone|sdt|so_?dien_?thoai|contact_?phone)"\s*:\s*"(\+?\d[\d\s().-]{7,18}\d)" """.strip()
)

# Extended cloud / platform secrets
GCP_SA_RE = re.compile(r'"type"\s*:\s*"service_account"[^}]{0,600}"private_key_id"\s*:\s*"([0-9a-f]{20,64})"', re.DOTALL)
AZURE_STORAGE_KEY_RE = re.compile(r"(AccountKey=[A-Za-z0-9+/]{40,}={0,2})")
TELEGRAM_BOT_RE = re.compile(r"\b(\d{8,12}:AA[A-Za-z0-9_-]{30,40})\b")
HARDCODED_AUTH_HEADER_RE = re.compile(
    r"""(?i)["']Authorization["']\s*[:=]\s*["']((?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{20,})["']"""
)

# Sensitive HTML comments
HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
SENSITIVE_COMMENT_HINT_RE = re.compile(
    r"(?i)\b(?:password|passwd|secret|api[_-]?key|token|default\s+login|admin\s+cred|select\s+.+\s+from|jdbc:|mongodb://|postgres://|staging\.|internal\.|TODO.*(?:auth|bypass|disable|remove\s+in\s+prod))\b"
)


def luhn_valid(digits: str) -> bool:
    """Validate a payment card number string (digits only) using the Luhn algorithm."""
    if not digits.isdigit() or not (13 <= len(digits) <= 19):
        return False
    # Reject all-identical digits (e.g. 0000... or 4444...)
    if len(set(digits)) <= 2:
        return False
    total = 0
    reverse_digits = digits[::-1]
    for i, ch in enumerate(reverse_digits):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def mask_pan(digits: str) -> str:
    if len(digits) < 10:
        return "*" * len(digits)
    return f"{digits[:4]}-****-****-{digits[-4:]}"


def mask_phone(phone: str) -> str:
    cleaned = re.sub(r"\s+", "", phone)
    if len(cleaned) <= 5:
        return "*" * len(cleaned)
    return f"{cleaned[:3]}***{cleaned[-2:]}"


@dataclass
class SensitiveDataOutcome:
    findings: list[FindingDraft] = field(default_factory=list)
    sources_scanned: int = 0


def run_sensitive_data_scan(
    crawl: CrawlOutcome,
    endpoints: list[DiscoveredEndpoint],
    recovered_sources: list[RecoveredSourceFile] | None = None,
) -> SensitiveDataOutcome:
    """Scan crawled pages, API responses, JS bundles, and recovered source maps for sensitive data & PII."""
    outcome = SensitiveDataOutcome()
    targets: list[tuple[str, str, str]] = []  # (location, kind, text)

    for url, resp in crawl.page_responses.items():
        ct = (resp.content_type or "").lower()
        if "html" in ct:
            targets.append((url, "html", resp.text))
        elif "json" in ct or "text" in ct:
            targets.append((url, "response", resp.text))

    for ep in endpoints:
        if ep.auth_observation == "public_content" and ep.sample_body:
            # Note: ep.sample_body is already truncated/redacted, so only check non-redacted structural signals if needed
            pass

    for url, asset in crawl.assets.items():
        if asset.kind == "js":
            targets.append((url, "js", asset.response.text))

    for rec in (recovered_sources or [])[:40]:
        targets.append((f"{rec.origin_map_url}::{rec.virtual_path}", "source", rec.content))

    for location, kind, text in targets:
        if not text:
            continue
        outcome.sources_scanned += 1
        _scan_payment_cards(location, text, outcome)
        _scan_government_ids(location, text, outcome)
        _scan_bulk_emails(location, kind, text, outcome)
        _scan_bulk_phones(location, text, outcome)
        _scan_extended_cloud_secrets(location, text, outcome)
        if kind == "html":
            _scan_sensitive_html_comments(location, text, outcome)

    return outcome


def _scan_payment_cards(location: str, text: str, outcome: SensitiveDataOutcome) -> None:
    seen_fps: set[str] = set()
    for m in CARD_CANDIDATE_RE.finditer(text):
        raw = m.group(0)
        digits = re.sub(r"[ -]", "", raw)
        if not luhn_valid(digits):
            continue
        fp = fingerprint(digits)
        if fp in seen_fps:
            continue
        seen_fps.add(fp)
        masked = mask_pan(digits)
        outcome.findings.append(
            FindingDraft(
                rule_id="DATA-CREDIT-CARD",
                title="Potential payment card number (PAN) exposed in public response",
                category="sensitive_data",
                severity="high",
                status="potential",
                confidence=0.82,
                affected=location,
                discriminator=fp,
                evidence=[
                    {
                        "type": "pii_pan",
                        "detail": f"Luhn-valid card number detected: {masked} (sha256:{fp})",
                        "location": location,
                    }
                ],
                detection_method="Payment card network prefix + length + Luhn checksum validation",
                impact="Exposure of payment card numbers violates PCI-DSS requirements and creates severe financial fraud risk.",
                reproduction=[f"Inspect {location} for unmasked payment card fields"],
                remediation="Never return raw Primary Account Numbers (PAN) in web responses or frontend bundles; tokenize payment data via a PCI-DSS compliant processor.",
            )
        )
        if len(seen_fps) >= 5:
            break


def _scan_government_ids(location: str, text: str, outcome: SensitiveDataOutcome) -> None:
    for pattern, label in ((VN_ID_CONTEXT_RE, "National ID / CCCD / CMND"), (US_SSN_CONTEXT_RE, "Social Security Number (SSN)")):
        seen_fps: set[str] = set()
        for m in pattern.finditer(text):
            val = m.group(1)
            if len(set(val.replace("-", ""))) <= 2:
                continue
            fp = fingerprint(val)
            if fp in seen_fps:
                continue
            seen_fps.add(fp)
            masked = mask_secret(val, keep_prefix=2, keep_suffix=2)
            outcome.findings.append(
                FindingDraft(
                    rule_id="DATA-GOV-ID",
                    title=f"Sensitive identity number ({label}) exposed in public content",
                    category="sensitive_data",
                    severity="high",
                    status="confirmed",
                    confidence=0.88,
                    affected=location,
                    discriminator=fp,
                    evidence=[
                        {
                            "type": "pii_gov_id",
                            "detail": f"{label} value detected in sensitive field context: {masked} (sha256:{fp})",
                            "location": location,
                        }
                    ],
                    detection_method="Context-aware regex matching sensitive identity field names and ID formats",
                    impact="Exposes regulated personally identifiable information (PII), risking identity theft and data protection violations.",
                    reproduction=[f"Inspect {location} for identity number fields"],
                    remediation="Require authentication and authorization before returning personal identity fields, and mask or omit government IDs from public responses.",
                )
            )
            if len(seen_fps) >= 5:
                break


def _scan_bulk_emails(location: str, kind: str, text: str, outcome: SensitiveDataOutcome) -> None:
    if kind == "js":
        # JS bundles frequently contain author/maintainer emails in package banners
        return
    personal_emails: dict[str, str] = {}
    for m in EMAIL_RE.finditer(text):
        local = m.group(1).lower()
        domain = m.group(2).lower()
        if local in PUBLIC_EMAIL_PREFIXES or domain in PLACEHOLDER_EMAIL_DOMAINS:
            continue
        if domain.endswith((".png", ".jpg", ".svg", ".css", ".js")):
            continue
        full = f"{local}@{domain}"
        if full not in personal_emails:
            tld = domain.rsplit(".", 1)[-1]
            personal_emails[full] = f"{local[0]}***@{domain[0]}***.{tld}"
        if len(personal_emails) >= 25:
            break

    if len(personal_emails) >= 5:
        sample_masked = ", ".join(list(personal_emails.values())[:5])
        outcome.findings.append(
            FindingDraft(
                rule_id="DATA-BULK-EMAIL-EXPOSURE",
                title=f"Bulk personal email addresses exposed ({len(personal_emails)}+ distinct addresses)",
                category="sensitive_data",
                severity="medium",
                status="confirmed",
                confidence=0.86,
                affected=location,
                evidence=[
                    {
                        "type": "pii_emails",
                        "detail": f"Found {len(personal_emails)} distinct non-role email addresses (masked sample: {sample_masked})",
                        "location": location,
                    }
                ],
                detection_method="Email extraction with role-account and placeholder filtering (threshold >= 5 distinct personal addresses)",
                impact="Unauthenticated bulk exposure of user emails enables targeted phishing, credential stuffing, and privacy compliance violations.",
                reproduction=[f"curl -s {location} | grep -Eo '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{{2,}}' | head"],
                remediation="Restrict user directory/listing endpoints to authorized roles and avoid embedding user email lists in public HTML or JSON responses.",
            )
        )


def _scan_bulk_phones(location: str, text: str, outcome: SensitiveDataOutcome) -> None:
    phones: dict[str, str] = {}
    for m in JSON_PHONE_RE.finditer(text):
        raw = m.group(1)
        digits = re.sub(r"\D", "", raw)
        if len(digits) < 9 or len(set(digits)) <= 2:
            continue
        if digits not in phones:
            phones[digits] = mask_phone(raw)
        if len(phones) >= 20:
            break

    if len(phones) >= 3:
        sample_masked = ", ".join(list(phones.values())[:5])
        outcome.findings.append(
            FindingDraft(
                rule_id="DATA-BULK-PHONE-EXPOSURE",
                title=f"Bulk phone numbers exposed in public JSON payload ({len(phones)}+ distinct numbers)",
                category="sensitive_data",
                severity="medium",
                status="confirmed",
                confidence=0.87,
                affected=location,
                evidence=[
                    {
                        "type": "pii_phones",
                        "detail": f"Found {len(phones)} distinct phone numbers in JSON fields (masked sample: {sample_masked})",
                        "location": location,
                    }
                ],
                detection_method="Context-aware JSON phone field extraction (threshold >= 3 distinct numbers)",
                impact="Exposes user contact phone numbers without authentication, enabling SMS phishing and privacy breaches.",
                reproduction=[f"Inspect JSON response at {location} for phone/mobile fields"],
                remediation="Require authentication and apply response DTO projections to omit user phone numbers from public endpoints.",
            )
        )


def _scan_extended_cloud_secrets(location: str, text: str, outcome: SensitiveDataOutcome) -> None:
    checks = (
        (
            "DATA-GCP-SERVICE-ACCOUNT",
            "Google Cloud Service Account JSON credentials exposed",
            GCP_SA_RE,
            "critical",
            "Service account credentials grant programmatic access to Google Cloud resources.",
            "Revoke the service account key in GCP IAM immediately and use Workload Identity or server-side secret management.",
        ),
        (
            "DATA-AZURE-STORAGE-KEY",
            "Azure Storage AccountKey exposed in public content",
            AZURE_STORAGE_KEY_RE,
            "critical",
            "An Azure Storage AccountKey grants full administrative access to the storage account blobs, queues, and tables.",
            "Rotate the storage account key in Azure Portal immediately and use managed identities or short-lived SAS tokens.",
        ),
        (
            "DATA-TELEGRAM-BOT-TOKEN",
            "Telegram Bot API token exposed in public content",
            TELEGRAM_BOT_RE,
            "high",
            "Anyone with the bot token can impersonate the bot, read incoming updates, and send messages to users/channels.",
            "Revoke the token via @BotFather (/revoke) and move bot API calls strictly to the backend.",
        ),
        (
            "DATA-HARDCODED-AUTH-HEADER",
            "Hard-coded Authorization (Bearer/Basic) header embedded in client asset",
            HARDCODED_AUTH_HEADER_RE,
            "high",
            "Hard-coded Authorization credentials in frontend code can be extracted by any visitor to call protected APIs.",
            "Remove static Authorization headers from client code and authenticate users via server-issued sessions or OAuth.",
        ),
    )

    for rule_id, title, pattern, severity, impact, remediation in checks:
        seen_fps: set[str] = set()
        for m in pattern.finditer(text):
            val = m.group(1)
            fp = fingerprint(val)
            if fp in seen_fps:
                continue
            seen_fps.add(fp)
            masked = mask_secret(val)
            outcome.findings.append(
                FindingDraft(
                    rule_id=rule_id,
                    title=title,
                    category="sensitive_data",
                    severity=severity,
                    status="confirmed",
                    confidence=0.93,
                    affected=location,
                    discriminator=fp,
                    evidence=[
                        {
                            "type": "extended_secret",
                            "detail": f"Detected {rule_id}: {masked} (sha256:{fp})",
                            "location": location,
                        }
                    ],
                    detection_method=f"Static pattern matching ({rule_id}) with immediate redaction",
                    impact=impact,
                    reproduction=[f"Inspect {location} for redacted credential pattern"],
                    remediation=remediation,
                )
            )


def _scan_sensitive_html_comments(location: str, text: str, outcome: SensitiveDataOutcome) -> None:
    hits: list[str] = []
    for m in HTML_COMMENT_RE.finditer(text):
        comment = m.group(1).strip()
        if len(comment) < 8 or len(comment) > 2000:
            continue
        if SENSITIVE_COMMENT_HINT_RE.search(comment):
            hits.append(redact_text(comment, max_len=160))
        if len(hits) >= 3:
            break

    if hits:
        outcome.findings.append(
            FindingDraft(
                rule_id="DATA-SENSITIVE-HTML-COMMENT",
                title="Potentially sensitive developer comment found in HTML response",
                category="sensitive_data",
                severity="low",
                status="potential",
                confidence=0.72,
                affected=location,
                evidence=[
                    {
                        "type": "html_comment",
                        "detail": f"Found {len(hits)} HTML comment(s) referencing credentials, internal URLs, or auth notes",
                        "location": location,
                        "snippet": " | ".join(hits[:2]),
                    }
                ],
                detection_method="HTML comment extraction filtered for credential, SQL, or internal-host keywords",
                impact="Developer comments can leak internal endpoints, authentication workarounds, or leftover test credentials.",
                reproduction=[f"curl -s {location} | grep -n '<!--'"],
                remediation="Strip HTML comments during production builds and never place credentials, SQL queries, or internal hostnames in template comments.",
            )
        )
