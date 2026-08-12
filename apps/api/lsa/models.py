import uuid
from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
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


class PolicyMode(StrEnum):
    disabled = "disabled"
    audit = "audit"
    manual = "manual"
    remediate = "remediate"


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
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "identity_provider_id",
            "external_subject",
            name="uq_user_external_identity",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(160))
    password_hash: Mapped[str | None] = mapped_column(String(300), nullable=True)
    role: Mapped[str] = mapped_column(String(30), default="admin")
    role_source: Mapped[str] = mapped_column(String(30), default="manual")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    auth_source: Mapped[str] = mapped_column(String(30), default="local", index=True)
    identity_provider_id: Mapped[str | None] = mapped_column(
        ForeignKey("identity_providers.id"), nullable=True, index=True
    )
    external_subject: Mapped[str | None] = mapped_column(String(320), nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)

    tenant: Mapped[Tenant] = relationship(back_populates="users")


class IdentityProvider(Base):
    __tablename__ = "identity_providers"
    __table_args__ = (UniqueConstraint("tenant_id", "name", name="uq_identity_provider_name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    name: Mapped[str] = mapped_column(String(160))
    provider_type: Mapped[str] = mapped_column(String(30), index=True)
    issuer_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    client_id: Mapped[str | None] = mapped_column(String(320), nullable=True)
    secret_ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)
    config: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class UserSession(Base):
    __tablename__ = "user_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class AuthTransaction(Base):
    __tablename__ = "auth_transactions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    state_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    provider_id: Mapped[str] = mapped_column(ForeignKey("identity_providers.id"), index=True)
    nonce: Mapped[str] = mapped_column(String(160))
    code_verifier: Mapped[str] = mapped_column(String(160))
    redirect_uri: Mapped[str] = mapped_column(String(1000))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class TlsCertificate(Base):
    __tablename__ = "tls_certificates"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    certificate_chain_pem: Mapped[str] = mapped_column(Text)
    private_key_ciphertext: Mapped[str] = mapped_column(Text)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    subject: Mapped[str] = mapped_column(String(500))
    issuer: Mapped[str] = mapped_column(String(500))
    hostnames: Mapped[list[str]] = mapped_column(JSON, default=list)
    not_valid_before: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    not_valid_after: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    uploaded_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class Host(Base):
    __tablename__ = "hosts"
    __table_args__ = (
        Index("ix_hosts_tenant_machine", "tenant_id", "machine_id_hash", unique=True),
        Index("ix_hosts_tenant_active_hostname", "tenant_id", "deleted_at", "hostname"),
        Index("ix_hosts_tenant_active_score", "tenant_id", "deleted_at", "security_score"),
        Index("ix_hosts_tenant_active_scan", "tenant_id", "deleted_at", "last_scan_at"),
    )

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
    system_info: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    compliance_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    security_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)

    tenant: Mapped[Tenant] = relationship(back_populates="hosts")
    reports: Mapped[list["Report"]] = relationship(back_populates="host")


class HostApplication(Base):
    __tablename__ = "host_applications"
    __table_args__ = (
        Index("ix_host_applications_host_active", "host_id", "removed_at"),
        Index(
            "ix_host_applications_tenant_active_kind_name",
            "tenant_id",
            "removed_at",
            "kind",
            "name",
        ),
        UniqueConstraint("host_id", "inventory_key", name="uq_host_application_identity"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    host_id: Mapped[str] = mapped_column(ForeignKey("hosts.id"), index=True)
    inventory_key: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(20), index=True)
    name: Mapped[str] = mapped_column(String(300), index=True)
    version: Mapped[str | None] = mapped_column(String(300), nullable=True)
    architecture: Mapped[str | None] = mapped_column(String(80), nullable=True)
    source: Mapped[str] = mapped_column(String(30), index=True)
    source_package: Mapped[str | None] = mapped_column(String(300), nullable=True, index=True)
    source_version: Mapped[str | None] = mapped_column(String(300), nullable=True)
    purl: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    publisher: Mapped[str | None] = mapped_column(String(300), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(80))
    enabled: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    running: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[str] = mapped_column(String(160), primary_key=True)
    cve_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    aliases: Mapped[list[str]] = mapped_column(JSON, default=list)
    summary: Mapped[str] = mapped_column(String(1000), default="")
    details: Mapped[str] = mapped_column(Text, default="", deferred=True)
    severity: Mapped[str] = mapped_column(String(20), default="unknown", index=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    withdrawn_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    references: Mapped[list[dict[str, str]]] = mapped_column(JSON, default=list)
    fixed_versions: Mapped[list[str]] = mapped_column(JSON, default=list)
    source_data: Mapped[dict[str, object]] = mapped_column(JSON, default=dict, deferred=True)
    known_exploited: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    kev_date_added: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    kev_due_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    kev_vendor: Mapped[str | None] = mapped_column(String(300), nullable=True)
    kev_product: Mapped[str | None] = mapped_column(String(300), nullable=True)
    kev_required_action: Mapped[str | None] = mapped_column(Text, nullable=True)
    ransomware_use: Mapped[str | None] = mapped_column(String(40), nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class HostApplicationVulnerability(Base):
    __tablename__ = "host_application_vulnerabilities"
    __table_args__ = (
        UniqueConstraint(
            "host_application_id",
            "vulnerability_id",
            name="uq_host_application_vulnerability",
        ),
        Index(
            "ix_host_application_vulnerabilities_tenant_active",
            "tenant_id",
            "resolved_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    host_application_id: Mapped[str] = mapped_column(ForeignKey("host_applications.id"), index=True)
    vulnerability_id: Mapped[str] = mapped_column(ForeignKey("vulnerabilities.id"), index=True)
    matched_purl: Mapped[str] = mapped_column(String(1000))
    fixed_versions: Mapped[list[str]] = mapped_column(JSON, default=list)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class VulnerabilitySyncRun(Base):
    __tablename__ = "vulnerability_sync_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)
    trigger: Mapped[str] = mapped_column(String(20), default="manual")
    requested_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    packages_queried: Mapped[int] = mapped_column(default=0)
    vulnerabilities_found: Mapped[int] = mapped_column(default=0)
    matches_found: Mapped[int] = mapped_column(default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class AgentPolicy(Base):
    __tablename__ = "agent_policies"
    __table_args__ = (UniqueConstraint("tenant_id", "name", name="uq_agent_policy_name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    name: Mapped[str] = mapped_column(String(160))
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)

    versions: Mapped[list["AgentPolicyVersion"]] = relationship(
        back_populates="policy", cascade="all, delete-orphan"
    )


class AgentPolicyVersion(Base):
    __tablename__ = "agent_policy_versions"
    __table_args__ = (UniqueConstraint("policy_id", "version", name="uq_agent_policy_version"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    policy_id: Mapped[str] = mapped_column(ForeignKey("agent_policies.id"), index=True)
    version: Mapped[int] = mapped_column()
    default_mode: Mapped[PolicyMode] = mapped_column(Enum(PolicyMode), default=PolicyMode.audit)
    control_modes: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    settings: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    created_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)

    policy: Mapped[AgentPolicy] = relationship(back_populates="versions")


class AgentGroup(Base):
    __tablename__ = "agent_groups"
    __table_args__ = (UniqueConstraint("tenant_id", "name", name="uq_agent_group_name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    policy_id: Mapped[str] = mapped_column(ForeignKey("agent_policies.id"), index=True)
    name: Mapped[str] = mapped_column(String(160))
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class LinuxAgent(Base):
    __tablename__ = "linux_agents"
    __table_args__ = (
        Index("ix_linux_agents_tenant_fingerprint", "tenant_id", "fingerprint", unique=True),
        UniqueConstraint("host_id", name="uq_linux_agent_host"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    host_id: Mapped[str] = mapped_column(ForeignKey("hosts.id"), index=True)
    group_id: Mapped[str] = mapped_column(ForeignKey("agent_groups.id"), index=True)
    ingestion_token_id: Mapped[str] = mapped_column(ForeignKey("ingestion_tokens.id"), unique=True)
    signing_key_id: Mapped[str] = mapped_column(ForeignKey("signing_keys.id"), unique=True)
    name: Mapped[str] = mapped_column(String(253))
    public_key: Mapped[str] = mapped_column(String(64))
    fingerprint: Mapped[str] = mapped_column(String(64))
    agent_version: Mapped[str] = mapped_column(String(40), default="0.1.0")
    capabilities: Mapped[list[str]] = mapped_column(JSON, default=list)
    capabilities_attested_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    platform_command_key_id: Mapped[str | None] = mapped_column(
        ForeignKey("platform_command_signing_keys.id"), nullable=True, index=True
    )
    platform_command_key_fingerprint: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    platform_envelope_sequence: Mapped[int] = mapped_column(default=0)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_policy_version: Mapped[int | None] = mapped_column(nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class AgentTask(Base):
    __tablename__ = "agent_tasks"
    __table_args__ = (
        Index("ix_agent_tasks_agent_status_created", "agent_id", "status", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey("linux_agents.id"), index=True)
    task_type: Mapped[str] = mapped_column(String(30), default="audit")
    status: Mapped[str] = mapped_column(String(30), default="queued", index=True)
    requested_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    result: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AgentEnrollmentToken(Base):
    __tablename__ = "agent_enrollment_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    group_id: Mapped[str] = mapped_column(ForeignKey("agent_groups.id"), index=True)
    platform_command_key_id: Mapped[str | None] = mapped_column(
        ForeignKey("platform_command_signing_keys.id"), nullable=True, index=True
    )
    name: Mapped[str] = mapped_column(String(160))
    token_prefix: Mapped[str] = mapped_column(String(24), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    token_type: Mapped[str] = mapped_column(String(20), default="one_time", index=True)
    max_uses: Mapped[int | None] = mapped_column(nullable=True)
    use_count: Mapped[int] = mapped_column(default=0)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


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
    __table_args__ = (
        Index("ix_signing_keys_tenant_fingerprint", "tenant_id", "fingerprint", unique=True),
    )

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
    __table_args__ = (Index("ix_reports_artifact_object_key", "artifact_object_key", unique=True),)

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
    artifact_object_key: Mapped[str | None] = mapped_column(String(500), nullable=True)
    artifact_object_version: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    artifact_size_bytes: Mapped[int | None] = mapped_column(nullable=True)
    artifact_content_type: Mapped[str | None] = mapped_column(String(120), nullable=True)
    artifact_stored_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    artifact_retention_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    artifact_deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    signing_key_id: Mapped[str | None] = mapped_column(ForeignKey("signing_keys.id"), nullable=True)
    signature_verified: Mapped[bool] = mapped_column(Boolean, default=False)

    host: Mapped[Host] = relationship(back_populates="reports")
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="report", cascade="all, delete-orphan"
    )


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_report_control", "report_id", "control_id", unique=True),
        Index("ix_findings_report_category_severity", "report_id", "category", "severity"),
        Index("ix_findings_report_lifecycle", "report_id", "lifecycle"),
    )

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


class RemediationPlan(Base):
    __tablename__ = "remediation_plans"
    __table_args__ = (
        Index("ix_remediation_plans_tenant_status_created", "tenant_id", "status", "created_at"),
        Index("ix_remediation_plans_host_control", "host_id", "control_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), index=True)
    active_finding_id: Mapped[str | None] = mapped_column(
        ForeignKey("findings.id"), nullable=True, unique=True
    )
    host_id: Mapped[str] = mapped_column(ForeignKey("hosts.id"), index=True)
    report_id: Mapped[str] = mapped_column(ForeignKey("reports.id"), index=True)
    control_id: Mapped[str] = mapped_column(String(160), index=True)
    title: Mapped[str] = mapped_column(String(500))
    category: Mapped[str] = mapped_column(String(80))
    severity: Mapped[str] = mapped_column(String(20))
    current_state: Mapped[str | None] = mapped_column(Text, nullable=True)
    required_state: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation_summary: Mapped[str] = mapped_column(Text)
    affected_paths: Mapped[list[str]] = mapped_column(JSON, default=list)
    action_id: Mapped[str | None] = mapped_column(String(200), nullable=True, index=True)
    action_version: Mapped[int | None] = mapped_column(nullable=True)
    action_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    action_snapshot: Mapped[dict[str, object] | None] = mapped_column(JSON, nullable=True)
    action_catalog_status: Mapped[str] = mapped_column(String(30), default="not_cataloged")
    reboot_required: Mapped[bool] = mapped_column(Boolean, default=False)
    service_restart: Mapped[bool] = mapped_column(Boolean, default=False)
    rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="pending_approval", index=True)
    version: Mapped[int] = mapped_column(default=1)
    requested_by: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    approved_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rejected_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    rejected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rejection_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    canceled_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    canceled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cancellation_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class PlatformCommandSigningKey(Base):
    __tablename__ = "platform_command_signing_keys"
    __table_args__ = (
        Index(
            "ix_platform_command_signing_keys_tenant_fingerprint",
            "tenant_id",
            "fingerprint",
            unique=True,
        ),
        UniqueConstraint("tenant_id", "key_version", name="uq_platform_command_key_version"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    name: Mapped[str] = mapped_column(String(160))
    key_version: Mapped[int] = mapped_column(default=1)
    public_key: Mapped[str] = mapped_column(String(64))
    private_key_ciphertext: Mapped[str] = mapped_column(Text)
    fingerprint: Mapped[str] = mapped_column(String(64))
    supersedes_key_id: Mapped[str | None] = mapped_column(
        ForeignKey("platform_command_signing_keys.id"), nullable=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class PlatformChangeSigningKey(Base):
    __tablename__ = "platform_change_signing_keys"
    __table_args__ = (
        Index(
            "ix_platform_change_signing_keys_tenant_fingerprint",
            "tenant_id",
            "fingerprint",
            unique=True,
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    name: Mapped[str] = mapped_column(String(160))
    public_key: Mapped[str] = mapped_column(String(64))
    private_key_ciphertext: Mapped[str] = mapped_column(Text)
    fingerprint: Mapped[str] = mapped_column(String(64))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class RemediationChangeSet(Base):
    __tablename__ = "remediation_change_sets"
    __table_args__ = (
        Index(
            "ix_remediation_change_sets_tenant_status_created",
            "tenant_id",
            "status",
            "created_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    status: Mapped[str] = mapped_column(String(30), default="pending_authorization", index=True)
    payload_schema_version: Mapped[str] = mapped_column(String(20), default="1.0")
    payload: Mapped[dict[str, object]] = mapped_column(JSON)
    digest: Mapped[str] = mapped_column(String(64), index=True)
    signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    signing_key_id: Mapped[str | None] = mapped_column(
        ForeignKey("platform_change_signing_keys.id"), nullable=True, index=True
    )
    maintenance_window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    maintenance_window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    batch_size: Mapped[int] = mapped_column(default=1)
    batch_interval_minutes: Mapped[int] = mapped_column(default=15)
    requested_by: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    authorized_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    authorized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    canceled_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    canceled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cancellation_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class RemediationChangeSetPlan(Base):
    __tablename__ = "remediation_change_set_plans"
    __table_args__ = (UniqueConstraint("change_set_id", "plan_id", name="uq_change_set_plan"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    change_set_id: Mapped[str] = mapped_column(
        ForeignKey("remediation_change_sets.id", ondelete="CASCADE"), index=True
    )
    plan_id: Mapped[str] = mapped_column(ForeignKey("remediation_plans.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class RemediationChangeSetTarget(Base):
    __tablename__ = "remediation_change_set_targets"
    __table_args__ = (
        UniqueConstraint("change_set_id", "host_id", name="uq_change_set_target_host"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    change_set_id: Mapped[str] = mapped_column(
        ForeignKey("remediation_change_sets.id", ondelete="CASCADE"), index=True
    )
    host_id: Mapped[str] = mapped_column(ForeignKey("hosts.id"), index=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey("linux_agents.id"), index=True)
    rollout_phase: Mapped[str] = mapped_column(String(20), default="canary")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


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
