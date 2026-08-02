from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


SeverityValue = Literal["critical", "high", "medium", "low", "info"]
FindingStatusValue = Literal["pass", "fail", "manual", "not_applicable", "error"]


class ScannerInfo(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    version: str = Field(min_length=1, max_length=40)


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
