"""Pydantic schemas matching the REST API contract (docs/api-contract.md)."""

from __future__ import annotations

import datetime as dt
import re
import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.db.models import (
    AuthorizationStatus,
    FindingStatus,
    OperatorRole,
    ScanStatus,
    Severity,
    VerificationMethod,
    VerificationStatus,
)

EMAIL_VALIDATE_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


def _validate_operator_email(v: str) -> str:
    val = (v or "").strip()
    if not EMAIL_VALIDATE_RE.match(val) or len(val) > 320:
        raise ValueError("Invalid email address format")
    return val


class OperatorOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    display_name: str
    role: str
    is_active: bool
    created_at: dt.datetime
    last_login_at: dt.datetime | None = None


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=256)

    @field_validator("email")
    @classmethod
    def _check_email(cls, v: str) -> str:
        return _validate_operator_email(v)


class AuthSessionOut(BaseModel):
    operator: OperatorOut
    csrf_token: str


class OperatorCreateRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    display_name: str = Field(default="", max_length=120)
    password: str = Field(min_length=12, max_length=256)
    role: OperatorRole = OperatorRole.operator

    @field_validator("email")
    @classmethod
    def _check_email(cls, v: str) -> str:
        return _validate_operator_email(v)


class OperatorUpdateRequest(BaseModel):
    display_name: str | None = Field(default=None, max_length=120)
    role: OperatorRole | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=12, max_length=256)


class ScopeConfigSchema(BaseModel):
    include_paths: list[str] = Field(default_factory=lambda: ["/"])
    exclude_paths: list[str] = Field(default_factory=lambda: ["/logout", "/signout"])
    max_depth: int = Field(default=4, ge=0, le=16)
    max_pages: int = Field(default=150, ge=1, le=5000)
    requests_per_second: float = Field(default=5.0, ge=0.2, le=100.0)
    concurrency: int = Field(default=4, ge=1, le=50)
    respect_robots: bool = True
    enable_path_probing: bool = True
    render_js: bool = False
    request_timeout_seconds: float = Field(default=15.0, ge=2.0, le=60.0)


class AccessTestItem(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    owner_role: str = Field(min_length=1, max_length=64)
    description: str = Field(default="", max_length=300)


class SupabaseIntegrationInput(BaseModel):
    enabled: bool = False
    project_url: str | None = None
    anon_key: str | None = None


class TargetIntegrationsInput(BaseModel):
    supabase: SupabaseIntegrationInput | None = None


class TargetCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    base_url: str = Field(min_length=4, max_length=2048)
    allowed_hosts: list[str] | None = None
    scope_config: ScopeConfigSchema | None = None
    access_tests: list[AccessTestItem] | None = None


class TargetUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    allowed_hosts: list[str] | None = None
    scope_config: ScopeConfigSchema | None = None
    access_tests: list[AccessTestItem] | None = None
    integrations: TargetIntegrationsInput | None = None


class TargetOut(BaseModel):
    id: uuid.UUID
    name: str
    base_url: str
    primary_host: str
    allowed_hosts: list[str]
    scope_config: dict[str, Any]
    access_tests: list[dict[str, Any]]
    integrations: dict[str, Any]
    authorization_status: AuthorizationStatus
    verification_method: str | None
    verification_token: str
    verified_at: dt.datetime | None
    verification_expires_at: dt.datetime | None
    attestation: dict[str, Any] | None
    owner_operator_id: uuid.UUID
    created_at: dt.datetime
    last_scan_at: dt.datetime | None
    credential_roles: list[str] = Field(default_factory=list)


class VerifyTargetRequest(BaseModel):
    method: Literal[VerificationMethod.dns_txt, VerificationMethod.well_known, VerificationMethod.meta_tag]


class VerifyTargetResponse(BaseModel):
    verified: bool
    detail: str
    target: TargetOut


class AttestTargetRequest(BaseModel):
    statement: str = Field(min_length=15, max_length=1000)
    confirm: bool


class CredentialCreateRequest(BaseModel):
    role_name: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    auth_type: Literal["cookie", "bearer", "header"]
    header_name: str | None = Field(default=None, max_length=128)
    value: str = Field(min_length=1, max_length=8192)
    description: str | None = Field(default=None, max_length=500)


class CredentialOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    role_name: str
    auth_type: str
    header_name: str | None
    description: str | None
    created_at: dt.datetime


class SourceUploadOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    target_id: uuid.UUID
    filename: str
    sha256: str
    size_bytes: int
    file_count: int
    status: str
    created_at: dt.datetime


class ScanOptionsSchema(BaseModel):
    crawl: bool = True
    render_js: bool = False
    path_probing: bool = True
    access_control: bool = True
    config_exposure: bool = True
    api_discovery: bool = True
    pentest_checks: bool = True
    pentest_profile: Literal["standard", "deep", "enterprise"] = "standard"
    sensitive_data: bool = True
    source_analysis: bool = True
    ai_analysis: bool = False
    max_pages: int | None = Field(default=None, ge=1, le=5000)
    timeout_seconds: int = Field(default=900, ge=30, le=7200)
    source_upload_id: uuid.UUID | None = None


class ScanCreateRequest(BaseModel):
    target_id: uuid.UUID
    options: ScanOptionsSchema | None = None
    authorization_confirmed: bool = True
    authorization_statement: str = Field(
        default="I own or am explicitly authorized to perform a security assessment of this target.",
        min_length=5,
        max_length=1000,
    )


class ScanOut(BaseModel):
    id: uuid.UUID
    target_id: uuid.UUID
    target_name: str
    target_url: str
    operator_id: uuid.UUID
    status: ScanStatus
    options: dict[str, Any]
    progress: int
    current_phase: str | None
    phase_log: list[dict[str, Any]]
    stats: dict[str, Any]
    created_at: dt.datetime
    started_at: dt.datetime | None
    finished_at: dt.datetime | None
    error: str | None
    cancel_requested: bool


class TechnologyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    kind: str
    confidence: float
    evidence: list[dict[str, Any]]


class RouteOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    url: str
    path: str
    status_code: int | None
    title: str | None
    content_type: str | None
    auth_observation: str
    redirect_chain: list[dict[str, Any]]
    discovery_methods: list[str]
    admin_category: str
    is_admin_surface: bool
    confidence: float
    risk_level: str
    evidence: list[dict[str, Any]]
    created_at: dt.datetime


class ApiEndpointOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    url: str
    path_template: str
    methods: list[str]
    category: str
    sources: list[str]
    status_code: int | None
    auth_observation: str
    content_type: str | None
    cors: dict[str, Any]
    tested: bool
    test_note: str | None
    evidence: list[dict[str, Any]]
    created_at: dt.datetime


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    url: str
    kind: str
    size_bytes: int
    sha256: str | None
    source_map_url: str | None
    source_map_exposed: bool


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    finding_key: str
    rule_id: str
    title: str
    category: str
    severity: Severity
    status: FindingStatus
    confidence: float
    affected: str
    evidence: list[dict[str, Any]]
    detection_method: str
    impact: str
    reproduction: list[str]
    remediation: str
    references: list[dict[str, Any]]
    cvss_vector: str | None
    cvss_score: float | None
    verification_status: VerificationStatus
    operator_note: str | None
    created_at: dt.datetime


class FindingTriageRequest(BaseModel):
    verification_status: VerificationStatus
    operator_note: str | None = Field(default=None, max_length=2000)


class AIAnalysisOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    provider: str
    model: str | None
    status: str
    error: str | None
    created_at: dt.datetime
    output: dict[str, Any] | None
    grounding: dict[str, Any] | None


class ReportCreateRequest(BaseModel):
    format: Literal["html", "json", "pdf"]


class ReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    format: str
    size_bytes: int
    sha256: str
    created_at: dt.datetime


class AISettingsOut(BaseModel):
    provider: Literal["openai", "disabled"]
    model: str
    base_url: str
    api_key_set: bool
    auto_analyze: bool


class AISettingsUpdateRequest(BaseModel):
    provider: Literal["openai", "disabled"]
    model: str = Field(min_length=1, max_length=100)
    base_url: str = Field(min_length=4, max_length=500)
    api_key: str | None = None
    auto_analyze: bool = False


class PlatformSettingsOut(BaseModel):
    lab_mode: bool
    allow_attestation_only: bool
    allow_private_targets: bool
    max_scan_timeout_seconds: int
    semgrep_available: bool
    playwright_available: bool
    version: str


class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    operator_email: str | None
    action: str
    target_id: uuid.UUID | None
    scan_id: uuid.UUID | None
    ip: str | None
    details: dict[str, Any]
    created_at: dt.datetime
