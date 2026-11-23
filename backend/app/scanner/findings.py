"""Finding construction, deterministic finding_key generation, deduplication, and CVSS 4.0 scoring."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from cvss import CVSS4

from app.core.redaction import redact_text

OWASP_REFS: dict[str, list[dict[str, str]]] = {
    "access_control": [
        {
            "title": "OWASP Top 10 A01:2021 — Broken Access Control",
            "url": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        }
    ],
    "admin_surface": [
        {
            "title": "OWASP Top 10 A01:2021 — Broken Access Control",
            "url": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        }
    ],
    "configuration_exposure": [
        {
            "title": "OWASP Top 10 A05:2021 — Security Misconfiguration",
            "url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        }
    ],
    "secret_exposure": [
        {
            "title": "OWASP Top 10 A02:2021 — Cryptographic Failures / Secret Exposure",
            "url": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        }
    ],
    "api_security": [
        {
            "title": "OWASP API Security Top 10 (2023)",
            "url": "https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
        }
    ],
    "source_code": [
        {
            "title": "OWASP Top 10 A04:2021 — Insecure Design",
            "url": "https://owasp.org/Top10/A04_2021-Insecure_Design/",
        }
    ],
    "database_policy": [
        {
            "title": "Supabase Row Level Security (RLS) Documentation",
            "url": "https://supabase.com/docs/guides/database/postgres/row-level-security",
        }
    ],
    "security_headers": [
        {
            "title": "OWASP Secure Headers Project",
            "url": "https://owasp.org/www-project-secure-headers/",
        }
    ],
    "information_disclosure": [
        {
            "title": "OWASP Top 10 A05:2021 — Security Misconfiguration",
            "url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        }
    ],
    "pentest_security": [
        {
            "title": "OWASP Web Security Testing Guide (WSTG)",
            "url": "https://owasp.org/www-project-web-security-testing-guide/",
        }
    ],
    "sensitive_data": [
        {
            "title": "OWASP Top 10 A02:2021 — Cryptographic Failures / Sensitive Data Exposure",
            "url": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        }
    ],
}

# Rule-defined CVSS 4.0 vectors applied ONLY when a finding has status == "confirmed".
RULE_CVSS4_VECTORS: dict[str, str] = {
    "AC-UNAUTH-ADMIN-PAGE": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
    "AC-UNAUTH-ADMIN-API": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "AC-ROLE-BYPASS-ADMIN": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
    "AC-IDOR-CROSS-TENANT": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "AC-CLIENT-GUARD-UNPROTECTED-API": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "CFG-DOTENV-EXPOSED": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N",
    "CFG-GIT-EXPOSED": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "CFG-SOURCEMAP-EXPOSED": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "CFG-SUPABASE-ANON-TABLE-READ": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "SEC-CRITICAL-EXPOSED": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:N/SA:N",
    "SEC-HIGH-EXPOSED": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
    "API-CORS-CREDENTIALED-REFLECTION": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
    "PT-BACKUP-FILE-EXPOSED": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N",
    "PT-OPEN-REDIRECT": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N",
    "PT-CLICKJACKING-ADMIN": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
    "PT-INSECURE-FORM-ACTION": "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "PT-COOKIE-INSECURE": "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "PT-DIRECTORY-LISTING": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "PT-HOST-HEADER-REFLECTION": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N",
    "PT-CORS-NULL-ORIGIN": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
    "PT-CACHE-SENSITIVE-EXPOSURE": "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "PT-CSP-WEAK": "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "DATA-GOV-ID": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "DATA-BULK-EMAIL-EXPOSURE": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "DATA-BULK-PHONE-EXPOSURE": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "DATA-GCP-SERVICE-ACCOUNT": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:N/SA:N",
    "DATA-AZURE-STORAGE-KEY": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:N/SA:N",
    "DATA-TELEGRAM-BOT-TOKEN": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
    "DATA-HARDCODED-AUTH-HEADER": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
}


def compute_cvss4(vector: str | None) -> tuple[str | None, float | None]:
    if not vector:
        return None, None
    try:
        c = CVSS4(vector)
        return vector, float(c.base_score)
    except Exception:
        return None, None


def make_finding_key(rule_id: str, affected: str, discriminator: str = "") -> str:
    digest = hashlib.sha256(f"{rule_id}|{affected}|{discriminator}".encode()).hexdigest()[:6].upper()
    return f"VS-{digest}"


@dataclass
class FindingDraft:
    rule_id: str
    title: str
    category: str
    severity: str  # critical | high | medium | low | info
    status: str  # confirmed | potential | informational | false_positive | not_tested
    confidence: float
    affected: str
    evidence: list[dict]
    detection_method: str
    impact: str
    reproduction: list[str]
    remediation: str
    references: list[dict[str, str]] = field(default_factory=list)
    cvss_vector: str | None = None
    cvss_score: float | None = None
    discriminator: str = ""

    def finalize(self) -> dict:
        sanitized_evidence: list[dict] = []
        for ev in self.evidence:
            item = dict(ev)
            if "snippet" in item and item["snippet"]:
                item["snippet"] = redact_text(str(item["snippet"]), max_len=360)
            if "detail" in item and item["detail"]:
                item["detail"] = redact_text(str(item["detail"]), max_len=400)
            sanitized_evidence.append(item)

        refs = list(self.references) or list(OWASP_REFS.get(self.category, []))
        vec = self.cvss_vector
        if vec is None and self.status == "confirmed":
            vec = RULE_CVSS4_VECTORS.get(self.rule_id)
        cvss_vec, cvss_score = compute_cvss4(vec) if self.status == "confirmed" else (None, None)

        return {
            "finding_key": make_finding_key(self.rule_id, self.affected, self.discriminator),
            "rule_id": self.rule_id,
            "title": self.title[:300],
            "category": self.category,
            "severity": self.severity,
            "status": self.status,
            "confidence": round(min(1.0, max(0.0, self.confidence)), 2),
            "affected": self.affected[:2048],
            "evidence": sanitized_evidence,
            "detection_method": self.detection_method,
            "impact": self.impact,
            "reproduction": self.reproduction,
            "remediation": self.remediation,
            "references": refs,
            "cvss_vector": cvss_vec,
            "cvss_score": cvss_score,
        }


def deduplicate_findings(drafts: list[FindingDraft]) -> list[dict]:
    by_key: dict[str, dict] = {}
    for d in drafts:
        fin = d.finalize()
        key = fin["finding_key"]
        if key not in by_key:
            by_key[key] = fin
        else:
            existing = by_key[key]
            for ev in fin["evidence"]:
                if ev not in existing["evidence"]:
                    existing["evidence"].append(ev)
    return list(by_key.values())
