from datetime import datetime
from typing import Any, Literal
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


class ApplicationInput(BaseModel):
    kind: Literal["package", "service"]
    name: str = Field(min_length=1, max_length=300)
    version: str | None = Field(default=None, max_length=300)
    architecture: str | None = Field(default=None, max_length=80)
    source: Literal["dpkg", "rpm", "systemd"]
    source_package: str | None = Field(default=None, max_length=300)
    source_version: str | None = Field(default=None, max_length=300)
    purl: str | None = Field(default=None, max_length=1000)
    publisher: str | None = Field(default=None, max_length=300)
    description: str | None = Field(default=None, max_length=1000)
    status: str = Field(min_length=1, max_length=80)
    enabled: bool | None = None
    running: bool | None = None


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
    applications: list[ApplicationInput] = Field(default_factory=list, max_length=20000)
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
    application_count: int
    finding_counts: dict[str, int]


class HostListFacets(BaseModel):
    total: int
    critical: int
    healthy: int
    stale: int


class ApplicationResponse(BaseModel):
    id: str
    host_id: str
    kind: str
    name: str
    version: str | None
    architecture: str | None
    source: str
    source_package: str | None
    source_version: str | None
    purl: str | None
    publisher: str | None
    description: str | None
    status: str
    enabled: bool | None
    running: bool | None
    first_seen_at: datetime
    last_seen_at: datetime
    removed_at: datetime | None


class ApplicationEstateMetrics(BaseModel):
    unique_applications: int
    package_count: int
    service_count: int
    installation_count: int
    reporting_hosts: int
    version_drift_count: int


class ApplicationEstateItem(BaseModel):
    kind: str
    name: str
    source: str
    publisher: str | None
    description: str | None
    host_count: int
    version_count: int
    running_host_count: int
    enabled_host_count: int
    vulnerability_count: int
    known_exploited_count: int
    first_seen_at: datetime
    last_seen_at: datetime


class ApplicationEstateResponse(BaseModel):
    metrics: ApplicationEstateMetrics
    applications: list[ApplicationEstateItem]


class ApplicationHostCorrelation(BaseModel):
    application_id: str
    host_id: str
    hostname: str
    fqdn: str | None
    os_family: str
    os_version: str
    environment: str | None
    security_score: float | None
    compliance_score: float | None
    version: str | None
    architecture: str | None
    status: str
    enabled: bool | None
    running: bool | None
    first_seen_at: datetime
    last_seen_at: datetime


class VulnerabilitySyncRunResponse(BaseModel):
    id: str
    status: str
    trigger: str
    packages_queried: int
    vulnerabilities_found: int
    matches_found: int
    error: str | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime


class VulnerabilitySummaryResponse(BaseModel):
    vulnerability_count: int
    exposure_count: int
    affected_hosts: int
    affected_applications: int
    known_exploited: int
    severity_counts: dict[str, int]
    intelligence_state: str
    last_sync: VulnerabilitySyncRunResponse | None


class ApplicationVulnerabilityResponse(BaseModel):
    id: str
    cve_id: str | None
    aliases: list[str]
    summary: str
    severity: str
    cvss_score: float | None
    known_exploited: bool
    fixed_versions: list[str]
    affected_hosts: int
    affected_host_ids: list[str]
    affected_versions: list[str]
    kev_due_date: datetime | None
    kev_required_action: str | None
    ransomware_use: str | None
    published_at: datetime | None
    modified_at: datetime | None
    references: list[dict[str, str]]


class HostVulnerabilityResponse(ApplicationVulnerabilityResponse):
    application_id: str
    application_name: str
    installed_version: str | None
    source_package: str | None
    matched_purl: str
    detected_at: datetime
    last_seen_at: datetime


class VulnerabilitySnapshotImportResponse(BaseModel):
    packages_imported: int
    vulnerabilities_found: int
    matches_found: int


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
    verification_commands: list[str]
    reboot_required: bool
    service_restart: bool


RemediationPlanStatusValue = Literal["pending_approval", "approved", "rejected", "canceled"]
RemediationCatalogStatusValue = Literal["matched", "not_cataloged", "unsupported_system"]


class RemediationCatalogModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RemediationSystemSupport(RemediationCatalogModel):
    family: str
    versions: list[str]


class RemediationActionParameter(RemediationCatalogModel):
    name: str
    type: Literal["boolean", "enum", "integer", "string"]
    required: bool
    default: bool | int | str | None = None
    allowed_values: list[bool | int | str] = Field(default_factory=list)
    minimum: int | None = None
    maximum: int | None = None
    description: str


class RemediationActionPrecondition(RemediationCatalogModel):
    kind: Literal["command_available", "host_role_not", "manual_confirmation", "package_present"]
    resource: str
    expected: str
    failure_mode: Literal["stop"] = "stop"
    description: str


class RemediationActionOperation(RemediationCatalogModel):
    kind: Literal[
        "config_setting",
        "restore_backup",
        "service_reload",
        "sysctl_reload",
        "sysctl_setting",
    ]
    resource: str
    path: str | None = None
    format: Literal["sshd_config", "sysctl"] | None = None
    key: str | None = None
    value_from: str | None = None
    backup_required: bool = False


class RemediationActionValidation(RemediationCatalogModel):
    kind: Literal["effective_setting", "sysctl_value"]
    resource: str
    key: str
    expected: bool | int | str


class RemediationActionImpact(RemediationCatalogModel):
    service_restart: bool
    reboot_required: bool
    availability: Literal["none", "brief_connection_risk", "role_dependent"]
    notes: str


class RemediationActionResponse(RemediationCatalogModel):
    action_id: str = Field(pattern=r"^linux\.[a-z0-9.-]+$", max_length=200)
    version: int = Field(ge=1)
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: Literal["reviewed"]
    control_ids: list[str]
    title: str
    description: str
    supported_systems: list[RemediationSystemSupport]
    risk: Literal["low", "medium", "high", "critical"]
    parameters: list[RemediationActionParameter]
    preconditions: list[RemediationActionPrecondition]
    operations: list[RemediationActionOperation]
    validation: list[RemediationActionValidation]
    rollback: list[RemediationActionOperation]
    impact: RemediationActionImpact
    execution_enabled: Literal[False] = False
    execution_status: Literal["catalog_only"] = "catalog_only"


class RemediationPlanCreate(BaseModel):
    finding_id: str = Field(min_length=1, max_length=36)
    rationale: str | None = Field(default=None, max_length=2000)


class RemediationPlanDecision(BaseModel):
    reason: str = Field(min_length=1, max_length=2000)


class RemediationPlanResponse(BaseModel):
    id: str
    finding_id: str
    host_id: str
    hostname: str
    report_id: str
    control_id: str
    title: str
    category: str
    severity: str
    current_state: str | None
    required_state: str | None
    remediation_summary: str
    affected_paths: list[str]
    reboot_required: bool
    service_restart: bool
    rationale: str | None
    status: RemediationPlanStatusValue
    version: int
    requested_by: str
    requested_by_name: str
    requested_at: datetime
    approved_by: str | None
    approved_by_name: str | None
    approved_at: datetime | None
    rejected_by: str | None
    rejected_by_name: str | None
    rejected_at: datetime | None
    rejection_reason: str | None
    canceled_by: str | None
    canceled_by_name: str | None
    canceled_at: datetime | None
    cancellation_reason: str | None
    source_is_current: bool
    finding_still_open: bool
    action_catalog_status: RemediationCatalogStatusValue = "not_cataloged"
    action: RemediationActionResponse | None = None
    execution_enabled: Literal[False] = False
    execution_status: Literal["not_supported"] = "not_supported"
    execution_reason: str = "This release records review decisions only and cannot change hosts."
    created_at: datetime
    updated_at: datetime


class FindingCategoryFacet(BaseModel):
    category: str
    count: int
    critical: int
    lifecycles: list[str]


class FindingListFacets(BaseModel):
    total: int
    critical: int
    affected_hosts: int
    categories: list[FindingCategoryFacet]


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


class PlatformCommandTrustResponse(BaseModel):
    key_id: str
    key_version: int
    algorithm: Literal["Ed25519"]
    public_key: str
    fingerprint: str


class AgentEnrollmentTokenCreate(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    group_id: str
    expires_at: datetime
    token_type: Literal["one_time", "reusable"] = "one_time"
    max_uses: int | None = Field(default=None, ge=2, le=100000)


class AgentEnrollmentTokenCreated(BaseModel):
    id: str
    name: str
    group_id: str
    token: str
    token_prefix: str
    expires_at: datetime
    token_type: Literal["one_time", "reusable"]
    max_uses: int | None
    use_count: int
    platform_trust: PlatformCommandTrustResponse


class AgentEnrollmentTokenResponse(BaseModel):
    id: str
    name: str
    group_id: str
    group_name: str
    token_prefix: str
    token_type: Literal["one_time", "reusable"]
    max_uses: int | None
    use_count: int
    expires_at: datetime
    used_at: datetime | None
    last_used_at: datetime | None
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
    platform_trust: PlatformCommandTrustResponse
    platform_envelope: dict[str, object]
    platform_signature: str


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
    platform_trust_status: Literal["pinned", "missing"]
    platform_command_key_fingerprint: str | None
    last_seen_at: datetime | None
    last_policy_version: int | None
    last_scan_at: datetime | None
    latest_task_status: str | None
    latest_task_created_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime


class AgentGroupAssignment(BaseModel):
    group_id: str


class AgentBulkSelection(BaseModel):
    agent_ids: list[str] = Field(min_length=1, max_length=1000)


class AgentBulkGroupAssignment(AgentBulkSelection):
    group_id: str


class AgentBulkResult(BaseModel):
    affected: int


class AgentTaskResponse(BaseModel):
    id: str
    agent_id: str
    task_type: Literal["audit"]
    status: Literal["queued", "dispatched", "completed", "failed", "cancelled"]
    result: dict[str, object]
    error: str | None
    created_at: datetime
    dispatched_at: datetime | None
    completed_at: datetime | None


class AgentTaskCompletion(BaseModel):
    status: Literal["completed", "failed"]
    result: dict[str, object] = Field(default_factory=dict)
    error: str | None = Field(default=None, max_length=4000)


class AgentPolicyVersionResponse(BaseModel):
    version: int
    default_mode: PolicyModeValue
    control_modes: dict[str, PolicyModeValue]
    settings: dict[str, object]
    created_by_name: str | None
    created_at: datetime


class AgentPolicyRestoreRequest(BaseModel):
    version: int = Field(ge=1)


class ControlCatalogItem(BaseModel):
    control_id: str
    title: str
    category: str
    module: str


class AgentPackageResponse(BaseModel):
    id: str
    version: str
    filename: str
    content_type: str
    operating_system: str
    architecture: str
    package_format: Literal["deb", "rpm", "tar.gz"]
    release_channel: Literal["stable"]
    audit_only: bool
    size_bytes: int
    sha256: str


class AgentConnectivityResponse(BaseModel):
    public_url: str
    platform_trust: PlatformCommandTrustResponse


ChangeSetStatusValue = Literal["pending_authorization", "authorized", "canceled"]


class RemediationChangeSetCreate(BaseModel):
    plan_ids: list[str] = Field(min_length=1, max_length=25)
    canary_host_ids: list[str] = Field(min_length=1, max_length=5)
    maintenance_window_start: datetime
    maintenance_window_end: datetime
    batch_size: int = Field(default=1, ge=1, le=25)
    batch_interval_minutes: int = Field(default=15, ge=15, le=1440)


class RemediationChangeSetDecision(BaseModel):
    reason: str = Field(min_length=3, max_length=4000)


class RemediationChangeSetGate(BaseModel):
    code: Literal[
        "action_integrity",
        "agent_attestation",
        "canary_scope",
        "evidence_freshness",
        "four_eyes",
        "maintenance_window",
        "policy_authorization",
        "rate_limit",
        "rollback_checkpoint",
    ]
    status: Literal["passed", "blocked"]
    detail: str


class RemediationChangeSetPlanResponse(BaseModel):
    plan_id: str
    hostname: str
    host_id: str
    control_id: str
    title: str
    action_id: str
    action_version: int
    action_digest: str
    plan_approved_by: str


class RemediationChangeSetTargetResponse(BaseModel):
    host_id: str
    hostname: str
    agent_id: str
    group_id: str
    group_name: str
    policy_id: str
    policy_name: str
    policy_version: int
    rollout_phase: Literal["canary", "deferred"]
    required_capability: str
    capability_attested: bool


class RemediationChangeSetResponse(BaseModel):
    id: str
    status: ChangeSetStatusValue
    payload_schema_version: Literal["1.0"] = "1.0"
    payload: dict[str, Any]
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    signature: str | None
    signing_key_id: str | None
    signing_key_fingerprint: str | None
    signing_public_key: str | None
    maintenance_window_start: datetime
    maintenance_window_end: datetime
    batch_size: int
    batch_interval_minutes: int
    plans: list[RemediationChangeSetPlanResponse]
    targets: list[RemediationChangeSetTargetResponse]
    gates: list[RemediationChangeSetGate]
    requested_by: str
    requested_by_name: str
    requested_at: datetime
    authorized_by: str | None
    authorized_by_name: str | None
    authorized_at: datetime | None
    canceled_by: str | None
    canceled_by_name: str | None
    canceled_at: datetime | None
    cancellation_reason: str | None
    execution_enabled: Literal[False] = False
    execution_status: Literal["not_supported"] = "not_supported"
    execution_reason: str = (
        "Signed change sets are governance records only; no agent execution path exists."
    )
    created_at: datetime
    updated_at: datetime
