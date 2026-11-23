"""Masking of secrets and personal data before anything is stored, reported or sent to an LLM."""

from __future__ import annotations

import hashlib
import re

EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9])[A-Za-z0-9.-]*\.([A-Za-z]{2,})\b")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
PHONE_RE = re.compile(r"(?<![\w.])\+?\d[\d\s().-]{8,}\d(?![\w.])")
MAX_SNIPPET = 400


def fingerprint(value: str) -> str:
    """Short, non-reversible fingerprint so identical secrets can be correlated without exposure."""
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]


def mask_secret(value: str, keep_prefix: int = 4, keep_suffix: int = 2) -> str:
    """Mask a secret. Never returns more than a short prefix/suffix of the original value."""
    if not value:
        return ""
    n = len(value)
    if n <= 8:
        return "*" * n
    keep_prefix = min(keep_prefix, n // 4)
    keep_suffix = min(keep_suffix, n // 8)
    hidden = n - keep_prefix - keep_suffix
    return f"{value[:keep_prefix]}{'*' * min(hidden, 16)}{value[n - keep_suffix:] if keep_suffix else ''}"


def describe_secret(value: str) -> str:
    return f"{mask_secret(value)} (len={len(value)}, sha256:{fingerprint(value)})"


def mask_email(match: re.Match[str]) -> str:
    return f"{match.group(1)}***@{match.group(2)}***.{match.group(3)}"


def redact_pii(text: str) -> str:
    text = EMAIL_RE.sub(mask_email, text)
    text = JWT_RE.sub(lambda m: mask_secret(m.group(0), 6, 0), text)
    return text


def redact_text(text: str, max_len: int = MAX_SNIPPET) -> str:
    """Redact secrets (all detector rules), JWTs and emails from an evidence snippet and truncate it."""
    from app.scanner.secrets import SECRET_RULES  # local import to avoid a cycle

    if not text:
        return ""
    if len(text) > max_len * 4:
        text = text[: max_len * 4]
    for rule in SECRET_RULES:
        text = rule.pattern.sub(lambda m, r=rule: _mask_match(m, r.value_group), text)
    text = redact_pii(text)
    text = text.replace("\r", "")
    if len(text) > max_len:
        text = text[:max_len] + "…"
    return text


def _mask_match(m: re.Match[str], group: int) -> str:
    full = m.group(0)
    try:
        secret = m.group(group)
    except IndexError:
        secret = full
    if not secret:
        return full
    return full.replace(secret, mask_secret(secret))
