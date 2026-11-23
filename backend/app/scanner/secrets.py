"""Secret and credential detection rules shared by bundle, response and source-code analysis.

Detected values are masked immediately; only masked values + fingerprints leave this module.
"""

from __future__ import annotations

import base64
import json
import math
import re
from collections.abc import Callable
from dataclasses import dataclass, field

from app.core.redaction import fingerprint, mask_secret

PLACEHOLDER_HINTS = (
    "your",
    "xxxx",
    "changeme",
    "change_me",
    "example",
    "placeholder",
    "dummy",
    "sample",
    "insert",
    "process.env",
    "import.meta",
    "${",
    "<",
    "redacted",
    "*****",
    "todo",
    "test123",
    "password123",
    "secret123",
)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def looks_like_placeholder(value: str) -> bool:
    v = value.lower()
    if any(h in v for h in PLACEHOLDER_HINTS):
        return True
    return len(set(v)) <= 3


def decode_jwt_payload(token: str) -> dict | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
        return data if isinstance(data, dict) else None
    except (ValueError, UnicodeDecodeError):
        return None


@dataclass(frozen=True)
class Classification:
    severity: str
    kind: str  # secret | public_identifier | credential
    note: str = ""
    label: str | None = None


ClassifyFn = Callable[[str], Classification | None]


@dataclass(frozen=True)
class SecretRule:
    id: str
    name: str
    pattern: re.Pattern[str]
    severity: str
    kind: str
    description: str
    remediation: str
    value_group: int = 1
    classify: ClassifyFn | None = None


@dataclass
class SecretMatch:
    rule_id: str
    name: str
    severity: str
    kind: str
    masked: str
    fingerprint: str
    location: str
    line: int | None
    snippet: str
    note: str = ""
    description: str = ""
    remediation: str = ""
    extra: dict = field(default_factory=dict)


def _classify_jwt(token: str) -> Classification | None:
    payload = decode_jwt_payload(token)
    if not payload:
        return None
    role = str(payload.get("role", ""))
    iss = str(payload.get("iss", ""))
    is_supabase = "supabase" in iss or "ref" in payload
    if role == "service_role":
        return Classification(
            "critical",
            "secret",
            "JWT with role=service_role (Supabase service key) bypasses Row Level Security entirely.",
            "Supabase service_role key",
        )
    if role == "anon" and is_supabase:
        return Classification(
            "info",
            "public_identifier",
            "Supabase anon key is designed for client-side use; security depends on RLS policies.",
            "Supabase anon (public) key",
        )
    if role == "anon":
        return Classification("info", "public_identifier", "JWT with role=anon.", "Public anon JWT")
    if "exp" not in payload and ("sub" in payload or "user_id" in payload or "email" in payload):
        return Classification(
            "medium", "credential", "Hard-coded non-expiring user JWT found in client content.", "Hard-coded JWT"
        )
    return None


def _classify_stripe(value: str) -> Classification | None:
    if "_live_" in value:
        return Classification("critical", "secret", "Live secret key.", None)
    return Classification("high", "secret", "Test-mode secret key (still grants API access to test data).", None)


def _classify_generic(value: str) -> Classification | None:
    if looks_like_placeholder(value) or shannon_entropy(value) < 3.0:
        return None
    if value.startswith(("http://", "https://", "/", "./")):
        return None
    return Classification("medium", "credential", "Credential-like value assigned to a sensitive variable name.")


def _classify_conn_string(value: str) -> Classification | None:
    if looks_like_placeholder(value) or value in {"password", "pass", "postgres", "root"}:
        # Default creds in a connection string are still a finding but lower-severity (likely local dev).
        return Classification("low", "credential", "Connection string with a default/placeholder password.")
    return None  # use rule default


def _classify_google_key(value: str) -> Classification | None:
    return Classification(
        "low",
        "public_identifier",
        "Google API keys are often public (Firebase/Maps) but must be restricted by HTTP referrer and API scope.",
    )


SECRET_RULES: list[SecretRule] = [
    SecretRule(
        "SEC-PRIVATE-KEY",
        "Private key",
        re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----[A-Za-z0-9+/=\s\\n]{20,})"),
        "critical",
        "secret",
        "A PEM private key is embedded in publicly reachable content.",
        "Remove the key, rotate it immediately, and load it only on the server from a secret manager.",
    ),
    SecretRule(
        "SEC-AWS-ACCESS-KEY",
        "AWS access key ID",
        re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"),
        "high",
        "credential",
        "AWS access key identifier found; usually paired with a secret access key.",
        "Deactivate the key in IAM, rotate it, and never ship AWS credentials to the browser.",
    ),
    SecretRule(
        "SEC-AWS-SECRET-KEY",
        "AWS secret access key",
        re.compile(r"(?i)aws.{0,24}?(?:secret|private)[^'\"\n]{0,24}?['\"]([A-Za-z0-9/+=]{40})['\"]"),
        "critical",
        "secret",
        "AWS secret access key assignment found.",
        "Rotate the credential immediately and use server-side roles or a secret manager.",
    ),
    SecretRule(
        "SEC-STRIPE-SECRET",
        "Stripe/Clerk secret key",
        re.compile(r"\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{20,})\b"),
        "critical",
        "secret",
        "Secret API key (Stripe or Clerk format) found.",
        "Roll the key in the provider dashboard and only use it from server-side code.",
        classify=_classify_stripe,
    ),
    SecretRule(
        "SEC-OPENAI-KEY",
        "OpenAI API key",
        re.compile(r"\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}|sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,})\b"),
        "critical",
        "secret",
        "OpenAI API key found; anyone can use it to incur cost or access organization data.",
        "Revoke the key at platform.openai.com and proxy AI requests through your backend.",
    ),
    SecretRule(
        "SEC-ANTHROPIC-KEY",
        "Anthropic API key",
        re.compile(r"\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{60,})"),
        "critical",
        "secret",
        "Anthropic API key found.",
        "Revoke the key and proxy model calls through a server-side endpoint.",
    ),
    SecretRule(
        "SEC-GITHUB-TOKEN",
        "GitHub token",
        re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"),
        "critical",
        "secret",
        "GitHub access token found.",
        "Revoke the token in GitHub settings and audit repository access logs.",
    ),
    SecretRule(
        "SEC-GITLAB-TOKEN",
        "GitLab token",
        re.compile(r"\b(glpat-[A-Za-z0-9_-]{20,})\b"),
        "critical",
        "secret",
        "GitLab personal access token found.",
        "Revoke the token and audit access.",
    ),
    SecretRule(
        "SEC-SLACK-TOKEN",
        "Slack token",
        re.compile(r"\b(xox[abprs]-[A-Za-z0-9-]{10,})\b"),
        "high",
        "secret",
        "Slack API token found.",
        "Revoke the token in the Slack app configuration.",
    ),
    SecretRule(
        "SEC-SLACK-WEBHOOK",
        "Slack incoming webhook",
        re.compile(r"(https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]{16,})"),
        "medium",
        "secret",
        "Slack incoming webhook URL allows anyone to post messages to the channel.",
        "Regenerate the webhook and send notifications from the backend.",
    ),
    SecretRule(
        "SEC-DISCORD-WEBHOOK",
        "Discord webhook",
        re.compile(r"(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]{30,})"),
        "medium",
        "secret",
        "Discord webhook URL allows anyone to post to the channel.",
        "Delete and recreate the webhook; call it from server-side code only.",
    ),
    SecretRule(
        "SEC-SENDGRID-KEY",
        "SendGrid API key",
        re.compile(r"\b(SG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{30,64})\b"),
        "critical",
        "secret",
        "SendGrid API key allows sending email as your domain.",
        "Revoke the key and send email from the backend.",
    ),
    SecretRule(
        "SEC-RESEND-KEY",
        "Resend API key",
        re.compile(r"\b(re_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,})\b"),
        "high",
        "secret",
        "Resend API key allows sending email as your domain.",
        "Revoke the key and send email from the backend.",
    ),
    SecretRule(
        "SEC-TWILIO-KEY",
        "Twilio API key",
        re.compile(r"\b(SK[0-9a-fA-F]{32})\b"),
        "high",
        "secret",
        "Twilio API key SID found.",
        "Revoke the key in the Twilio console.",
    ),
    SecretRule(
        "SEC-MAILGUN-KEY",
        "Mailgun API key",
        re.compile(r"\b(key-[0-9a-f]{32})\b"),
        "high",
        "secret",
        "Mailgun API key found.",
        "Rotate the key and keep it server-side.",
    ),
    SecretRule(
        "SEC-SUPABASE-SECRET",
        "Supabase secret key",
        re.compile(r"\b(sb_secret_[A-Za-z0-9_-]{20,})\b"),
        "critical",
        "secret",
        "Supabase secret API key bypasses Row Level Security.",
        "Rotate the key in the Supabase dashboard and only use it on trusted servers.",
    ),
    SecretRule(
        "SEC-SUPABASE-PUBLISHABLE",
        "Supabase publishable key",
        re.compile(r"\b(sb_publishable_[A-Za-z0-9_-]{20,})\b"),
        "info",
        "public_identifier",
        "Supabase publishable key (client-safe by design; relies on RLS).",
        "No action needed for the key itself; ensure RLS is enabled with restrictive policies.",
    ),
    SecretRule(
        "SEC-JWT",
        "JSON Web Token",
        re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"),
        "info",
        "public_identifier",
        "JWT found in public content.",
        "Ensure no privileged or long-lived tokens are embedded in client code.",
        classify=_classify_jwt,
    ),
    SecretRule(
        "SEC-DB-CONNECTION",
        "Database connection string with credentials",
        re.compile(
            r"\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver)://[^\s:'\"/@]{1,64}:([^\s'\"@/]{3,128})@[^\s'\"/]{3,255})"
        ),
        "critical",
        "secret",
        "Database connection string with embedded password.",
        "Rotate the database password, restrict network access, and keep connection strings server-side.",
        value_group=2,
        classify=_classify_conn_string,
    ),
    SecretRule(
        "SEC-STRIPE-PUBLISHABLE",
        "Stripe publishable key",
        re.compile(r"\b(pk_(?:live|test)_[0-9a-zA-Z]{20,})\b"),
        "info",
        "public_identifier",
        "Publishable key (client-safe by design).",
        "No action needed.",
    ),
    SecretRule(
        "SEC-GOOGLE-API-KEY",
        "Google API key",
        re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b"),
        "low",
        "public_identifier",
        "Google API key found.",
        "Restrict the key by HTTP referrer and limit it to the specific APIs required.",
        classify=_classify_google_key,
    ),
    SecretRule(
        "SEC-GENERIC-ASSIGNMENT",
        "Hard-coded credential assignment",
        re.compile(
            r"""(?i)\b((?:[A-Z0-9_]*_)?(?:SECRET(?:_KEY)?|PRIVATE_KEY|PASSWORD|PASSWD|API_SECRET|CLIENT_SECRET|ACCESS_TOKEN|AUTH_TOKEN|SERVICE_ROLE(?:_KEY)?|JWT_SECRET|ADMIN_PASSWORD))["']?\s*[:=]\s*["'`]([^"'`\s]{8,200})["'`]"""
        ),
        "medium",
        "credential",
        "A credential-like literal is assigned to a sensitive variable name.",
        "Move the value to server-side environment configuration and rotate it.",
        value_group=2,
        classify=_classify_generic,
    ),
]


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _snippet(text: str, start: int, end: int, secret: str, radius: int = 60) -> str:
    from app.core.redaction import redact_text

    a = max(0, start - radius)
    b = min(len(text), end + radius)
    raw = text[a:b].replace(secret, mask_secret(secret))
    return redact_text(raw.replace("\n", " "), max_len=240)


def detect_secrets(text: str, location: str, max_findings: int = 50) -> list[SecretMatch]:
    """Scan ``text`` for secrets. Returned values are masked; raw secrets never leave this function."""
    results: list[SecretMatch] = []
    seen: set[tuple[str, str]] = set()
    consumed: list[tuple[int, int]] = []
    if not text:
        return results
    for rule in SECRET_RULES:
        for m in rule.pattern.finditer(text):
            try:
                value = m.group(rule.value_group) or m.group(0)
            except IndexError:
                value = m.group(0)
            start, end = m.span()
            if any(start < ce and end > cs for cs, ce in consumed):
                continue  # already reported by a more specific rule
            severity, kind, note, name = rule.severity, rule.kind, "", rule.name
            if rule.classify is not None:
                cls = rule.classify(value)
                if cls is None and rule.id in {"SEC-JWT", "SEC-GENERIC-ASSIGNMENT"}:
                    continue
                if cls is not None:
                    severity, kind, note = cls.severity, cls.kind, cls.note
                    name = cls.label or name
            fp = fingerprint(value)
            key = (rule.id, fp)
            if key in seen:
                continue
            seen.add(key)
            consumed.append((start, end))
            results.append(
                SecretMatch(
                    rule_id=rule.id,
                    name=name,
                    severity=severity,
                    kind=kind,
                    masked=mask_secret(value),
                    fingerprint=fp,
                    location=location,
                    line=_line_of(text, start),
                    snippet=_snippet(text, start, end, value),
                    note=note,
                    description=rule.description,
                    remediation=rule.remediation,
                )
            )
            if len(results) >= max_findings:
                return results
    return results
