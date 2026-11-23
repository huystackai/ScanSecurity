"""SQLAlchemy ORM models (PostgreSQL in production, SQLite supported for dev/tests)."""

from __future__ import annotations

import datetime as dt
import enum
import uuid
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, IdMixin, TimestampMixin, UTCDateTime


class StrEnum(enum.StrEnum):
    @classmethod
    def values(cls) -> list[str]:
        return [m.value for m in cls]


class OperatorRole(StrEnum):
    admin = "admin"
    operator = "operator"
    viewer = "viewer"


class AuthorizationStatus(StrEnum):
    pending = "pending"
    verified = "verified"
    attested = "attested"
    expired = "expired"
    revoked = "revoked"


class VerificationMethod(StrEnum):
    dns_txt = "dns_txt"
    well_known = "well_known"
    meta_tag = "meta_tag"
    attestation = "attestation"


class ScanStatus(StrEnum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"
    timed_out = "timed_out"

    @property
    def is_terminal(self) -> bool:
        return self in {ScanStatus.completed, ScanStatus.failed, ScanStatus.cancelled, ScanStatus.timed_out}


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

    @property
    def rank(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]


class FindingStatus(StrEnum):
    confirmed = "confirmed"
    potential = "potential"
    informational = "informational"
    false_positive = "false_positive"
    not_tested = "not_tested"


class VerificationStatus(StrEnum):
    unverified = "unverified"
    verified = "verified"
    false_positive = "false_positive"
    accepted_risk = "accepted_risk"
    fixed = "fixed"


def _enum_col(enum_cls: type[StrEnum], **kw: Any) -> Any:
    return mapped_column(sa.String(32), **kw)


class Operator(IdMixin, TimestampMixin, Base):
    __tablename__ = "operators"

    email: Mapped[str] = mapped_column(sa.String(320), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(sa.String(120), default="")
    password_hash: Mapped[str] = mapped_column(sa.String(255))
    role: Mapped[str] = _enum_col(OperatorRole, default=OperatorRole.operator.value)
    is_active: Mapped[bool] = mapped_column(sa.Boolean, default=True)
    last_login_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)


class Session(IdMixin, TimestampMixin, Base):
    __tablename__ = "sessions"

    operator_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("operators.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(sa.String(64), unique=True, index=True)
    csrf_token: Mapped[str] = mapped_column(sa.String(64))
    expires_at: Mapped[dt.datetime] = mapped_column(UTCDateTime)
    revoked_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)
    ip: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(sa.String(400), nullable=True)

    operator: Mapped[Operator] = relationship(lazy="joined")


class Target(IdMixin, TimestampMixin, Base):
    __tablename__ = "targets"

    name: Mapped[str] = mapped_column(sa.String(200))
    base_url: Mapped[str] = mapped_column(sa.String(2048))
    primary_host: Mapped[str] = mapped_column(sa.String(255), index=True)
    allowed_hosts: Mapped[list] = mapped_column(sa.JSON, default=list)
    scope_config: Mapped[dict] = mapped_column(sa.JSON, default=dict)
    access_tests: Mapped[list] = mapped_column(sa.JSON, default=list)
    integrations: Mapped[dict] = mapped_column(sa.JSON, default=dict)
    authorization_status: Mapped[str] = _enum_col(AuthorizationStatus, default=AuthorizationStatus.pending.value)
    verification_method: Mapped[str | None] = mapped_column(sa.String(32), nullable=True)
    verification_token: Mapped[str] = mapped_column(sa.String(128))
    verified_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)
    attestation: Mapped[dict | None] = mapped_column(sa.JSON, nullable=True)
    owner_operator_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("operators.id"), index=True)
    archived: Mapped[bool] = mapped_column(sa.Boolean, default=False)
    last_scan_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)

    credentials: Mapped[list[TargetCredential]] = relationship(
        back_populates="target", cascade="all, delete-orphan", lazy="selectin"
    )


class TargetCredential(IdMixin, TimestampMixin, Base):
    """Owner-supplied test-account session material (cookie / bearer / header). Encrypted at rest."""

    __tablename__ = "target_credentials"

    target_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    role_name: Mapped[str] = mapped_column(sa.String(64))
    auth_type: Mapped[str] = mapped_column(sa.String(16))  # cookie | bearer | header
    header_name: Mapped[str | None] = mapped_column(sa.String(128), nullable=True)
    encrypted_value: Mapped[str] = mapped_column(sa.Text)
    description: Mapped[str | None] = mapped_column(sa.String(500), nullable=True)

    target: Mapped[Target] = relationship(back_populates="credentials")


class SourceUpload(IdMixin, TimestampMixin, Base):
    __tablename__ = "source_uploads"

    target_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    operator_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("operators.id"))
    filename: Mapped[str] = mapped_column(sa.String(255))
    sha256: Mapped[str] = mapped_column(sa.String(64))
    size_bytes: Mapped[int] = mapped_column(sa.BigInteger)
    file_count: Mapped[int] = mapped_column(sa.Integer, default=0)
    storage_path: Mapped[str] = mapped_column(sa.String(1024))
    status: Mapped[str] = mapped_column(sa.String(32), default="ready")


class Scan(IdMixin, TimestampMixin, Base):
    __tablename__ = "scans"

    target_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("targets.id"), index=True)
    operator_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("operators.id"), index=True)
    status: Mapped[str] = _enum_col(ScanStatus, default=ScanStatus.queued.value, index=True)
    options: Mapped[dict] = mapped_column(sa.JSON, default=dict)
    authorization: Mapped[dict] = mapped_column(sa.JSON, default=dict)
    progress: Mapped[int] = mapped_column(sa.Integer, default=0)
    current_phase: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)
    phase_log: Mapped[list] = mapped_column(sa.JSON, default=list)
    stats: Mapped[dict] = mapped_column(sa.JSON, default=dict)
    baseline: Mapped[dict] = mapped_column(sa.JSON, default=dict)
    cancel_requested: Mapped[bool] = mapped_column(sa.Boolean, default=False)
    source_upload_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("source_uploads.id", ondelete="SET NULL"), nullable=True
    )
    started_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)
    finished_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)
    error: Mapped[str | None] = mapped_column(sa.Text, nullable=True)

    target: Mapped[Target] = relationship(lazy="joined")


class Route(IdMixin, TimestampMixin, Base):
    __tablename__ = "routes"

    scan_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    url: Mapped[str] = mapped_column(sa.String(2048))
    path: Mapped[str] = mapped_column(sa.String(2048))
    status_code: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    title: Mapped[str | None] = mapped_column(sa.String(500), nullable=True)
    content_type: Mapped[str | None] = mapped_column(sa.String(200), nullable=True)
    content_hash: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)
    auth_observation: Mapped[str] = mapped_column(sa.String(32), default="not_tested")
    redirect_chain: Mapped[list] = mapped_column(sa.JSON, default=list)
    discovery_methods: Mapped[list] = mapped_column(sa.JSON, default=list)
    admin_category: Mapped[str] = mapped_column(sa.String(32), default="none", index=True)
    is_admin_surface: Mapped[bool] = mapped_column(sa.Boolean, default=False, index=True)
    confidence: Mapped[float] = mapped_column(sa.Float, default=0.0)
    risk_level: Mapped[str] = mapped_column(sa.String(16), default="none")
    evidence: Mapped[list] = mapped_column(sa.JSON, default=list)


class ApiEndpoint(IdMixin, TimestampMixin, Base):
    __tablename__ = "api_endpoints"

    scan_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    url: Mapped[str] = mapped_column(sa.String(2048))
    path_template: Mapped[str] = mapped_column(sa.String(2048))
    methods: Mapped[list] = mapped_column(sa.JSON, default=list)
    category: Mapped[str] = mapped_column(sa.String(32), default="other")
    sources: Mapped[list] = mapped_column(sa.JSON, default=list)
    status_code: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    auth_observation: Mapped[str] = mapped_column(sa.String(32), default="not_tested")
    content_type: Mapped[str | None] = mapped_column(sa.String(200), nullable=True)
    cors: Mapped[dict] = mapped_column(sa.JSON, default=dict)
    tested: Mapped[bool] = mapped_column(sa.Boolean, default=False)
    test_note: Mapped[str | None] = mapped_column(sa.String(500), nullable=True)
    evidence: Mapped[list] = mapped_column(sa.JSON, default=list)


class Asset(IdMixin, TimestampMixin, Base):
    __tablename__ = "assets"

    scan_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    url: Mapped[str] = mapped_column(sa.String(2048))
    kind: Mapped[str] = mapped_column(sa.String(16))
    size_bytes: Mapped[int] = mapped_column(sa.Integer, default=0)
    sha256: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)
    source_map_url: Mapped[str | None] = mapped_column(sa.String(2048), nullable=True)
    source_map_exposed: Mapped[bool] = mapped_column(sa.Boolean, default=False)


class Technology(IdMixin, TimestampMixin, Base):
    __tablename__ = "technologies"

    scan_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(sa.String(64))
    kind: Mapped[str] = mapped_column(sa.String(32))
    confidence: Mapped[float] = mapped_column(sa.Float)
    evidence: Mapped[list] = mapped_column(sa.JSON, default=list)


class Finding(IdMixin, TimestampMixin, Base):
    __tablename__ = "findings"
    __table_args__ = (sa.UniqueConstraint("scan_id", "finding_key", name="uq_finding_scan_key"),)

    scan_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    finding_key: Mapped[str] = mapped_column(sa.String(32))
    rule_id: Mapped[str] = mapped_column(sa.String(64), index=True)
    title: Mapped[str] = mapped_column(sa.String(300))
    category: Mapped[str] = mapped_column(sa.String(48), index=True)
    severity: Mapped[str] = _enum_col(Severity, index=True)
    status: Mapped[str] = _enum_col(FindingStatus, index=True)
    confidence: Mapped[float] = mapped_column(sa.Float)
    affected: Mapped[str] = mapped_column(sa.String(2048))
    evidence: Mapped[list] = mapped_column(sa.JSON, default=list)
    detection_method: Mapped[str] = mapped_column(sa.Text)
    impact: Mapped[str] = mapped_column(sa.Text)
    reproduction: Mapped[list] = mapped_column(sa.JSON, default=list)
    remediation: Mapped[str] = mapped_column(sa.Text)
    references: Mapped[list] = mapped_column(sa.JSON, default=list)
    cvss_vector: Mapped[str | None] = mapped_column(sa.String(200), nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(sa.Float, nullable=True)
    verification_status: Mapped[str] = _enum_col(VerificationStatus, default=VerificationStatus.unverified.value)
    operator_note: Mapped[str | None] = mapped_column(sa.Text, nullable=True)


class AIAnalysis(IdMixin, TimestampMixin, Base):
    __tablename__ = "ai_analyses"

    scan_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(sa.String(32))
    model: Mapped[str | None] = mapped_column(sa.String(100), nullable=True)
    status: Mapped[str] = mapped_column(sa.String(16), default="pending")
    output: Mapped[dict | None] = mapped_column(sa.JSON, nullable=True)
    grounding: Mapped[dict | None] = mapped_column(sa.JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(sa.Text, nullable=True)


class Report(IdMixin, TimestampMixin, Base):
    __tablename__ = "reports"

    scan_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    operator_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("operators.id"))
    format: Mapped[str] = mapped_column(sa.String(8))
    path: Mapped[str] = mapped_column(sa.String(1024))
    size_bytes: Mapped[int] = mapped_column(sa.Integer)
    sha256: Mapped[str] = mapped_column(sa.String(64))


class AuditLog(IdMixin, TimestampMixin, Base):
    __tablename__ = "audit_logs"

    operator_id: Mapped[uuid.UUID | None] = mapped_column(sa.ForeignKey("operators.id"), nullable=True, index=True)
    operator_email: Mapped[str | None] = mapped_column(sa.String(320), nullable=True)
    action: Mapped[str] = mapped_column(sa.String(64), index=True)
    target_id: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid, nullable=True, index=True)
    scan_id: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid, nullable=True, index=True)
    ip: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)
    details: Mapped[dict] = mapped_column(sa.JSON, default=dict)


class AppSetting(Base):
    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(sa.String(64), primary_key=True)
    value: Mapped[dict] = mapped_column(sa.JSON, default=dict)
