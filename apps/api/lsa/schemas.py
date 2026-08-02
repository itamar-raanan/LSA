from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


SeverityValue = Literal["critical", "high", "medium", "low", "info"]
FindingStatusValue = Literal["pass", "fail", "manual", "not_applicable", "error"]


class ScannerInfo(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    version: str = Field(min_length=1, max_length=40)


class SystemInfo(BaseModel):
    cpu_model: str | None = Field(default=None, max_length=300)
    cpu_cores: int | None = Field(default=None, ge=0)
    memory_mb: int | None = Field(default=None, ge=0)
    uptime_seconds: int | None = Field(default=None, ge=0)
    virtualization_type: str | None = Field(default=None, max_length=80)
    virtualization_role: str | None = Field(default=None, max_length=80)
    system_vendor: str | None = Field(default=None, max_length=200)
    product_name: str | None = Field(default=None, max_length=200)
    timezone: str | None = Field(default=None, max_length=80)


class HostInfo(BaseModel):
    host_id: UUID
    hostname: str = Field(min_length=1, max_length=253)
    fqdn: str | None = Field(default=None, max_length=253)
    machine_id_hash: str = Field(pattern=r"^sha256:[a-fA-F0-9]{64}$")
    operating_system: str
    os_family: Literal["debian", "ubuntu", "rhel"]
    os_version: str
    kernel: str
    architecture: str
    ip_addresses: list[str] = Field(default_factory=list, max_length=64)
    tags: dict[str, str] = Field(default_factory=dict)
    system_info: SystemInfo = Field(default_factory=SystemInfo)


class ScanInfo(BaseModel):
    profile: str
    modules: list[str] = Field(min_length=1)


class SummaryInfo(BaseModel):
    pass_count: int = Field(alias="pass", ge=0)
    fail: int = Field(ge=0)
    manual: int = Field(ge=0)
    not_applicable: int = Field(ge=0)
    error: int = Field(ge=0)
    compliance_score: float | None = Field(default=None, ge=0, le=100)
    security_score: float | None = Field(default=None, ge=0, le=100)

    model_config = ConfigDict(populate_by_name=True)


class FindingInput(BaseModel):
    control_id: str
    module: str
    category: str
    title: str
    severity: SeverityValue
    status: FindingStatusValue
    expected: str | None = None
    actual: str | None = None
    evidence: list[str] = Field(default_factory=list)
    remediation_summary: str | None = None
    remediation_commands: list[str] = Field(default_factory=list)
    verification_commands: list[str] = Field(default_factory=list)
    reboot_required: bool = False
    service_restart: bool = False


class ReportInput(BaseModel):
    schema_version: Literal["1.0"]
    report_id: UUID
    generated_at: datetime
    scanner: ScannerInfo
    host: HostInfo
    scan: ScanInfo
    summary: SummaryInfo
    findings: list[FindingInput] = Field(max_length=50000)


class IngestResponse(BaseModel):
    status: Literal["accepted"] = "accepted"
    report_id: str
    host_id: str
    findings_imported: int
    new_findings: int
    resolved_findings: int


class LoginRequest(BaseModel):
    email: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict[str, str]


class RadiusLoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=320)
    password: str = Field(min_length=1, max_length=1024)


class IdentityProviderCreate(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    provider_type: Literal["entra", "okta", "google", "adfs", "openid", "radius"]
    issuer_url: str | None = Field(default=None, max_length=500)
    client_id: str | None = Field(default=None, max_length=320)
    secret: str | None = Field(default=None, max_length=2048)
    config: dict[str, object] = Field(default_factory=dict)
    is_enabled: bool = False


class IdentityProviderUpdate(IdentityProviderCreate):
    secret: str | None = Field(default=None, max_length=2048)


class IdentityProviderResponse(BaseModel):
    id: str
    name: str
    provider_type: str
    issuer_url: str | None
    client_id: str | None
    config: dict[str, object]
    is_enabled: bool
    secret_configured: bool
    created_at: datetime
    updated_at: datetime


class PublicIdentityProvider(BaseModel):
    id: str
    name: str
    provider_type: str


class OidcStartResponse(BaseModel):
    authorization_url: str


class UserAdminResponse(BaseModel):
    id: str
    email: str
    name: str
    role: str
    is_active: bool
    auth_source: str
    provider_name: str | None = None
    last_login_at: datetime | None
    created_at: datetime


class UserCreate(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    display_name: str = Field(min_length=1, max_length=160)
    role: Literal["admin", "analyst", "auditor"] = "auditor"
    provider_id: str
    external_subject: str = Field(min_length=1, max_length=320)


class UserRoleUpdate(BaseModel):
    role: Literal["admin", "analyst", "auditor"]


class UserStatusUpdate(BaseModel):
    is_active: bool


class TlsCertificateResponse(BaseModel):
    id: str
    fingerprint: str
    subject: str
    issuer: str
    hostnames: list[str]
    not_valid_before: datetime
    not_valid_after: datetime
    is_active: bool
    created_at: datetime


class HostResponse(BaseModel):
    id: str
    hostname: str
    fqdn: str | None
    operating_system: str
    os_family: str
    os_version: str
    kernel: str
    architecture: str
    ip_addresses: list[str]
    tags: dict[str, str]
    system_info: dict[str, object]
    compliance_score: float | None
    security_score: float | None
    last_scan_at: datetime | None
    finding_counts: dict[str, int]


class HostCreate(BaseModel):
    hostname: str = Field(min_length=1, max_length=253)
    fqdn: str | None = Field(default=None, max_length=253)
    os_family: Literal["debian", "ubuntu", "rhel"]
    os_version: str = Field(min_length=1, max_length=40)
    ip_addresses: list[str] = Field(default_factory=list, max_length=64)
    tags: dict[str, str] = Field(default_factory=dict)


class TokenCreate(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    host_id: str | None = None
    expires_at: datetime | None = None


class TokenCreated(BaseModel):
    id: str
    name: str
    host_id: str | None
    token: str
    token_prefix: str
    expires_at: datetime | None


class TokenResponse(BaseModel):
    id: str
    name: str
    host_id: str | None
    token_prefix: str
    expires_at: datetime | None
    last_used_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime


class SigningKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    public_key: str = Field(min_length=1, max_length=128)
    host_id: str | None = None
    expires_at: datetime | None = None


class SigningKeyResponse(BaseModel):
    id: str
    name: str
    host_id: str | None
    public_key: str
    fingerprint: str
    expires_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime


class FindingResponse(BaseModel):
    id: str
    host_id: str
    hostname: str
    report_id: str
    control_id: str
    module: str
    category: str
    title: str
    severity: str
    status: str
    lifecycle: str
    expected: str | None
    actual: str | None
    remediation_summary: str | None
    remediation_commands: list[str]
    reboot_required: bool


class DashboardResponse(BaseModel):
    total_hosts: int
    healthy_hosts: int
    at_risk_hosts: int
    critical_hosts: int
    stale_hosts: int
    overall_security_score: float
    compliance_score: float
    finding_counts: dict[str, int]
    os_distribution: dict[str, int]
    highest_risk_hosts: list[HostResponse]


class ReportResponse(BaseModel):
    id: str
    host_id: str
    generated_at: datetime
    received_at: datetime
    scanner_version: str
    profile: str
    modules: list[str]
    summary: dict[str, int | float | None]
    compliance_score: float
    security_score: float
    artifact_name: str | None
    artifact_size_bytes: int | None
    artifact_stored_at: datetime | None
    artifact_retention_until: datetime | None
    artifact_available: bool
    signing_key_id: str | None
    signature_verified: bool
    finding_counts: dict[str, int]


class FindingDelta(BaseModel):
    control_id: str
    title: str
    severity: str


class ReportComparison(BaseModel):
    current_report_id: str
    previous_report_id: str | None
    new: list[FindingDelta]
    persistent: list[FindingDelta]
    resolved: list[FindingDelta]


class ArtifactPurgeResponse(BaseModel):
    deleted: int


PolicyModeValue = Literal["disabled", "audit", "manual", "remediate"]


class AgentPolicyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    description: str = Field(default="", max_length=4000)
    default_mode: PolicyModeValue = "audit"
    control_modes: dict[str, PolicyModeValue] = Field(default_factory=dict, max_length=5000)
    settings: dict[str, object] = Field(default_factory=dict)


class AgentPolicyUpdate(BaseModel):
    description: str = Field(default="", max_length=4000)
    default_mode: PolicyModeValue
    control_modes: dict[str, PolicyModeValue] = Field(default_factory=dict, max_length=5000)
    settings: dict[str, object] = Field(default_factory=dict)


class AgentPolicyResponse(BaseModel):
    id: str
    name: str
    description: str
    version: int
    default_mode: PolicyModeValue
    control_modes: dict[str, PolicyModeValue]
    settings: dict[str, object]
    assigned_groups: int
    created_at: datetime
    updated_at: datetime


class AgentGroupCreate(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    description: str = Field(default="", max_length=4000)
    policy_id: str


class AgentGroupUpdate(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    description: str = Field(default="", max_length=4000)
    policy_id: str


class AgentGroupResponse(BaseModel):
    id: str
    name: str
    description: str
    policy_id: str
    policy_name: str
    policy_version: int
    agent_count: int
    created_at: datetime
    updated_at: datetime


class AgentEnrollmentTokenCreate(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    group_id: str
    expires_at: datetime


class AgentEnrollmentTokenCreated(BaseModel):
    id: str
    name: str
    group_id: str
    token: str
    token_prefix: str
    expires_at: datetime


class AgentEnrollmentTokenResponse(BaseModel):
    id: str
    name: str
    group_id: str
    group_name: str
    token_prefix: str
    expires_at: datetime
    used_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime


class AgentEnrollmentRequest(BaseModel):
    name: str = Field(min_length=1, max_length=253)
    public_key: str = Field(min_length=1, max_length=128)
    agent_version: str = Field(min_length=1, max_length=40)
    capabilities: list[str] = Field(default_factory=lambda: ["audit"], max_length=32)
    hostname: str = Field(min_length=1, max_length=253)
    fqdn: str | None = Field(default=None, max_length=253)
    machine_id_hash: str = Field(pattern=r"^sha256:[a-fA-F0-9]{64}$")
    operating_system: str = Field(min_length=1, max_length=100)
    os_family: Literal["debian", "ubuntu", "rhel"]
    os_version: str = Field(min_length=1, max_length=40)
    kernel: str = Field(min_length=1, max_length=100)
    architecture: str = Field(min_length=1, max_length=40)
    ip_addresses: list[str] = Field(default_factory=list, max_length=64)
    tags: dict[str, str] = Field(default_factory=dict)
    system_info: dict[str, object] = Field(default_factory=dict)


class AgentEnrollmentResponse(BaseModel):
    agent_id: str
    host_id: str
    group_id: str
    ingestion_token: str
    signing_key_id: str
    policy_version: int


class AgentHeartbeatRequest(BaseModel):
    agent_version: str = Field(min_length=1, max_length=40)
    capabilities: list[str] = Field(default_factory=list, max_length=32)
    policy_version: int | None = Field(default=None, ge=1)


class AgentHeartbeatResponse(BaseModel):
    accepted_at: datetime
    policy_changed: bool
    policy_version: int


class AgentEffectivePolicyResponse(BaseModel):
    policy_id: str
    policy_name: str
    policy_version: int
    group_id: str
    group_name: str
    default_mode: PolicyModeValue
    control_modes: dict[str, PolicyModeValue]
    settings: dict[str, object]
    enforcement_enabled: bool = False


class LinuxAgentResponse(BaseModel):
    id: str
    host_id: str
    hostname: str
    group_id: str
    group_name: str
    policy_name: str
    policy_version: int
    agent_version: str
    capabilities: list[str]
    fingerprint: str
    last_seen_at: datetime | None
    last_policy_version: int | None
    revoked_at: datetime | None
    created_at: datetime


class AgentGroupAssignment(BaseModel):
    group_id: str


class ControlCatalogItem(BaseModel):
    control_id: str
    title: str
    category: str
    module: str
