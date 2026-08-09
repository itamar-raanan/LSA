export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface User {
  id: string
  email: string
  name: string
  role: string
}

export interface Host {
  id: string
  hostname: string
  fqdn: string | null
  operating_system: string
  os_family: string
  os_version: string
  kernel: string
  architecture: string
  ip_addresses: string[]
  tags: Record<string, string>
  system_info?: Record<string, string | number | boolean | null>
  application_count?: number
  compliance_score: number | null
  security_score: number | null
  last_scan_at: string | null
  finding_counts: Record<Severity, number>
}

export interface HostListFacets {
  total: number
  critical: number
  healthy: number
  stale: number
}

export interface FindingCategoryFacet {
  category: string
  count: number
  critical: number
  lifecycles: string[]
}

export interface FindingListFacets {
  total: number
  critical: number
  affected_hosts: number
  categories: FindingCategoryFacet[]
}

export interface PagedResult<T> {
  rows: T[]
  total: number
  page: number
  pageSize: number
}

export interface ApplicationInventoryItem {
  id: string
  host_id: string
  kind: 'package' | 'service'
  name: string
  version: string | null
  architecture: string | null
  source: 'dpkg' | 'rpm' | 'systemd'
  source_package: string | null
  source_version: string | null
  purl: string | null
  publisher: string | null
  description: string | null
  status: string
  enabled: boolean | null
  running: boolean | null
  first_seen_at: string
  last_seen_at: string
  removed_at: string | null
}

export interface ApplicationEstateMetrics {
  unique_applications: number
  package_count: number
  service_count: number
  installation_count: number
  reporting_hosts: number
  version_drift_count: number
}

export interface ApplicationEstateItem {
  kind: 'package' | 'service'
  name: string
  source: 'dpkg' | 'rpm' | 'systemd'
  publisher: string | null
  description: string | null
  host_count: number
  version_count: number
  running_host_count: number
  enabled_host_count: number
  vulnerability_count: number
  known_exploited_count: number
  first_seen_at: string
  last_seen_at: string
}

export interface ApplicationEstateResponse {
  metrics: ApplicationEstateMetrics
  applications: ApplicationEstateItem[]
}

export interface ApplicationHostCorrelation {
  application_id: string
  host_id: string
  hostname: string
  fqdn: string | null
  os_family: string
  os_version: string
  environment: string | null
  security_score: number | null
  compliance_score: number | null
  version: string | null
  architecture: string | null
  status: string
  enabled: boolean | null
  running: boolean | null
  first_seen_at: string
  last_seen_at: string
}

export interface VulnerabilitySyncRun {
  id: string
  status: 'queued' | 'running' | 'succeeded' | 'failed'
  trigger: 'manual' | 'scheduled' | 'offline'
  packages_queried: number
  vulnerabilities_found: number
  matches_found: number
  error: string | null
  started_at: string | null
  completed_at: string | null
  created_at: string
}

export interface VulnerabilitySummary {
  vulnerability_count: number
  exposure_count: number
  affected_hosts: number
  affected_applications: number
  known_exploited: number
  severity_counts: Record<string, number>
  intelligence_state: 'never' | 'fresh' | 'stale' | 'refreshing' | 'failed'
  last_sync: VulnerabilitySyncRun | null
}

export interface ApplicationVulnerability {
  id: string
  cve_id: string | null
  aliases: string[]
  summary: string
  severity: Severity | 'unknown'
  cvss_score: number | null
  known_exploited: boolean
  fixed_versions: string[]
  affected_hosts: number
  affected_host_ids: string[]
  affected_versions: string[]
  kev_due_date: string | null
  kev_required_action: string | null
  ransomware_use: string | null
  published_at: string | null
  modified_at: string | null
  references: Array<Record<string, string>>
}

export interface HostVulnerability extends ApplicationVulnerability {
  application_id: string
  application_name: string
  installed_version: string | null
  source_package: string | null
  matched_purl: string
  detected_at: string
  last_seen_at: string
}

export interface Finding {
  id: string
  host_id: string
  hostname: string
  report_id: string
  control_id: string
  module: string
  category: string
  title: string
  severity: Severity
  status: string
  lifecycle: string
  expected: string | null
  actual: string | null
  remediation_summary: string | null
  remediation_commands: string[]
  verification_commands: string[]
  reboot_required: boolean
  service_restart: boolean
}

export interface DashboardData {
  total_hosts: number
  healthy_hosts: number
  at_risk_hosts: number
  critical_hosts: number
  stale_hosts: number
  overall_security_score: number
  compliance_score: number
  finding_counts: Record<Severity, number>
  os_distribution: Record<string, number>
  highest_risk_hosts: Host[]
}

export interface ReportSummary {
  id: string
  host_id: string
  generated_at: string
  received_at: string
  scanner_version: string
  profile: string
  modules: string[]
  summary: Record<string, number | null>
  compliance_score: number
  security_score: number
  artifact_name: string | null
  artifact_size_bytes: number | null
  artifact_stored_at: string | null
  artifact_retention_until: string | null
  artifact_available: boolean
  signing_key_id: string | null
  signature_verified: boolean
  finding_counts: Record<Severity, number>
}

export interface FindingDelta {
  control_id: string
  title: string
  severity: Severity
}

export interface ReportComparison {
  current_report_id: string
  previous_report_id: string | null
  new: FindingDelta[]
  persistent: FindingDelta[]
  resolved: FindingDelta[]
}

export interface TokenCreated {
  id: string
  name: string
  host_id: string | null
  token: string
  token_prefix: string
  expires_at: string | null
}

export interface IngestionToken {
  id: string
  name: string
  host_id: string | null
  token_prefix: string
  expires_at: string | null
  last_used_at: string | null
  revoked_at: string | null
  created_at: string
}

export interface SigningKey {
  id: string
  name: string
  host_id: string | null
  public_key: string
  fingerprint: string
  expires_at: string | null
  revoked_at: string | null
  created_at: string
}

export type ProviderType = 'entra' | 'okta' | 'google' | 'adfs' | 'openid' | 'radius'

export interface IdentityProvider {
  id: string
  name: string
  provider_type: ProviderType
  issuer_url: string | null
  client_id: string | null
  config: Record<string, unknown>
  is_enabled: boolean
  secret_configured: boolean
  created_at: string
  updated_at: string
}

export interface PublicIdentityProvider {
  id: string
  name: string
  provider_type: ProviderType
}

export interface ManagedUser extends User {
  is_active: boolean
  auth_source: string
  provider_name: string | null
  last_login_at: string | null
  created_at: string
}

export interface ManagedUserCreate {
  email: string
  display_name: string
  role: 'admin' | 'analyst' | 'auditor'
  provider_id: string
  external_subject: string
}

export interface TlsCertificate {
  id: string
  fingerprint: string
  subject: string
  issuer: string
  hostnames: string[]
  not_valid_before: string
  not_valid_after: string
  is_active: boolean
  created_at: string
}

export type PolicyMode = 'disabled' | 'audit' | 'manual' | 'remediate'

export interface AgentPolicy {
  id: string
  name: string
  description: string
  version: number
  default_mode: PolicyMode
  control_modes: Record<string, PolicyMode>
  settings: Record<string, unknown>
  assigned_groups: number
  created_at: string
  updated_at: string
}

export interface AgentPolicyVersion {
  version: number
  default_mode: PolicyMode
  control_modes: Record<string, PolicyMode>
  settings: Record<string, unknown>
  created_by_name: string | null
  created_at: string
}

export interface AgentGroup {
  id: string
  name: string
  description: string
  policy_id: string
  policy_name: string
  policy_version: number
  agent_count: number
  created_at: string
  updated_at: string
}

export interface LinuxAgent {
  id: string
  host_id: string
  hostname: string
  group_id: string
  group_name: string
  policy_name: string
  policy_version: number
  agent_version: string
  capabilities: string[]
  fingerprint: string
  last_seen_at: string | null
  last_policy_version: number | null
  last_scan_at: string | null
  latest_task_status: 'queued' | 'dispatched' | 'completed' | 'failed' | 'cancelled' | null
  latest_task_created_at: string | null
  revoked_at: string | null
  created_at: string
}

export interface AgentTask {
  id: string
  agent_id: string
  task_type: 'audit'
  status: 'queued' | 'dispatched' | 'completed' | 'failed' | 'cancelled'
  result: Record<string, unknown>
  error: string | null
  created_at: string
  dispatched_at: string | null
  completed_at: string | null
}

export interface ControlCatalogItem {
  control_id: string
  title: string
  category: string
  module: string
}

export interface AgentEnrollmentTokenCreated {
  id: string
  name: string
  group_id: string
  token: string
  token_prefix: string
  expires_at: string
}

export interface AgentEnrollmentToken {
  id: string
  name: string
  group_id: string
  group_name: string
  token_prefix: string
  expires_at: string
  used_at: string | null
  revoked_at: string | null
  created_at: string
}

export interface AgentPackage {
  id: string
  version: string
  filename: string
  content_type: string
  operating_system: string
  architecture: string
  package_format: 'deb' | 'rpm' | 'tar.gz'
  release_channel: 'stable'
  audit_only: boolean
  size_bytes: number
  sha256: string
}

export interface AgentConnectivity {
  public_url: string
}
