import uuid
from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import JSON, Boolean, DateTime, Enum, Float, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from lsa.database import Base


def uuid_string() -> str:
    return str(uuid.uuid4())


def now_utc() -> datetime:
    return datetime.now(UTC)


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class FindingStatus(StrEnum):
    passed = "pass"
    failed = "fail"
    manual = "manual"
    not_applicable = "not_applicable"
    error = "error"


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    name: Mapped[str] = mapped_column(String(160), unique=True)
    slug: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)

    users: Mapped[list["User"]] = relationship(back_populates="tenant")
    hosts: Mapped[list["Host"]] = relationship(back_populates="tenant")


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(160))
    password_hash: Mapped[str] = mapped_column(String(300))
    role: Mapped[str] = mapped_column(String(30), default="admin")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)

    tenant: Mapped[Tenant] = relationship(back_populates="users")


class Host(Base):
    __tablename__ = "hosts"
    __table_args__ = (Index("ix_hosts_tenant_machine", "tenant_id", "machine_id_hash", unique=True),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    hostname: Mapped[str] = mapped_column(String(253), index=True)
    fqdn: Mapped[str | None] = mapped_column(String(253), nullable=True)
    machine_id_hash: Mapped[str] = mapped_column(String(80))
    operating_system: Mapped[str] = mapped_column(String(100))
    os_family: Mapped[str] = mapped_column(String(30), index=True)
    os_version: Mapped[str] = mapped_column(String(40))
    kernel: Mapped[str] = mapped_column(String(100))
    architecture: Mapped[str] = mapped_column(String(40))
    ip_addresses: Mapped[list[str]] = mapped_column(JSON, default=list)
    tags: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    compliance_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    security_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)

    tenant: Mapped[Tenant] = relationship(back_populates="hosts")
    reports: Mapped[list["Report"]] = relationship(back_populates="host")


class IngestionToken(Base):
    __tablename__ = "ingestion_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    host_id: Mapped[str | None] = mapped_column(ForeignKey("hosts.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(160))
    token_prefix: Mapped[str] = mapped_column(String(20), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class SigningKey(Base):
    __tablename__ = "signing_keys"
    __table_args__ = (Index("ix_signing_keys_tenant_fingerprint", "tenant_id", "fingerprint", unique=True),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    host_id: Mapped[str | None] = mapped_column(ForeignKey("hosts.id"), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(160))
    public_key: Mapped[str] = mapped_column(String(64))
    fingerprint: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    host_id: Mapped[str] = mapped_column(ForeignKey("hosts.id"), index=True)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    schema_version: Mapped[str] = mapped_column(String(20))
    scanner_name: Mapped[str] = mapped_column(String(100))
    scanner_version: Mapped[str] = mapped_column(String(40))
    profile: Mapped[str] = mapped_column(String(100))
    modules: Mapped[list[str]] = mapped_column(JSON, default=list)
    summary: Mapped[dict[str, int | float | None]] = mapped_column(JSON)
    compliance_score: Mapped[float] = mapped_column(Float)
    security_score: Mapped[float] = mapped_column(Float)
    artifact_name: Mapped[str | None] = mapped_column(String(300), nullable=True)
    checksum: Mapped[str | None] = mapped_column(String(64), nullable=True)
    signing_key_id: Mapped[str | None] = mapped_column(ForeignKey("signing_keys.id"), nullable=True)
    signature_verified: Mapped[bool] = mapped_column(Boolean, default=False)

    host: Mapped[Host] = relationship(back_populates="reports")
    findings: Mapped[list["Finding"]] = relationship(back_populates="report", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (Index("ix_findings_report_control", "report_id", "control_id", unique=True),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    host_id: Mapped[str] = mapped_column(ForeignKey("hosts.id"), index=True)
    report_id: Mapped[str] = mapped_column(ForeignKey("reports.id"), index=True)
    control_id: Mapped[str] = mapped_column(String(160), index=True)
    module: Mapped[str] = mapped_column(String(80), index=True)
    category: Mapped[str] = mapped_column(String(80), index=True)
    title: Mapped[str] = mapped_column(String(500))
    severity: Mapped[Severity] = mapped_column(Enum(Severity), index=True)
    status: Mapped[FindingStatus] = mapped_column(Enum(FindingStatus), index=True)
    lifecycle: Mapped[str] = mapped_column(String(30), default="new", index=True)
    expected: Mapped[str | None] = mapped_column(Text, nullable=True)
    actual: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence: Mapped[list[str]] = mapped_column(JSON, default=list)
    remediation_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation_commands: Mapped[list[str]] = mapped_column(JSON, default=list)
    verification_commands: Mapped[list[str]] = mapped_column(JSON, default=list)
    reboot_required: Mapped[bool] = mapped_column(Boolean, default=False)
    service_restart: Mapped[bool] = mapped_column(Boolean, default=False)

    report: Mapped[Report] = relationship(back_populates="findings")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    actor_type: Mapped[str] = mapped_column(String(30))
    actor_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    action: Mapped[str] = mapped_column(String(120), index=True)
    target_type: Mapped[str] = mapped_column(String(80))
    target_id: Mapped[str] = mapped_column(String(160))
    details: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
