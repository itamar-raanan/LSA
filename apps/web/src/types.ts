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

export interface VulnerabilityEstateItem extends ApplicationVulnerability {
  exposure_count: number
  affected_applications: number
  application_names: string[]
}

export interface VulnerabilityExposure {
  id: string
  host_id: string
  hostname: string
  os_family: string
  os_version: string
  environment: string | null
  application_id: string
  application_name: string
  application_source: string
  installed_version: string | null
  fixed_versions: string[]
  detected_at: string
  last_seen_at: string
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

export type RemediationPlanStatus = 'pending_approval' | 'approved' | 'rejected' | 'canceled'
export type RemediationCatalogStatus = 'matched' | 'not_cataloged' | 'unsupported_system'

export interface RemediationActionOperation {
  kind: 'config_setting' | 'restore_backup' | 'service_reload' | 'sysctl_reload' | 'sysctl_setting'
  resource: string
  path: string | null
  format: 'sshd_config' | 'sysctl' | null
  key: string | null
  value_from: string | null
  backup_required: boolean
}

export interface RemediationAction {
  action_id: string
  version: number
  digest: string
  status: 'reviewed'
  control_ids: string[]
  title: string
  description: string
  supported_systems: Array<{ family: string; versions: string[] }>
  risk: 'low' | 'medium' | 'high' | 'critical'
  parameters: Array<{ name: string; type: 'boolean' | 'enum' | 'integer' | 'string'; required: boolean; default: boolean | number | string | null; allowed_values: Array<boolean | number | string>; minimum: number | null; maximum: number | null; description: string }>
  preconditions: Array<{ kind: 'command_available' | 'host_role_not' | 'manual_confirmation' | 'package_present'; resource: string; expected: string; failure_mode: 'stop'; description: string }>
  operations: RemediationActionOperation[]
  validation: Array<{ kind: 'effective_setting' | 'sysctl_value'; resource: string; key: string; expected: boolean | number | string }>
  rollback: RemediationActionOperation[]
  impact: { service_restart: boolean; reboot_required: boolean; availability: 'none' | 'brief_connection_risk' | 'role_dependent'; notes: string }
  execution_enabled: false
  execution_status: 'catalog_only'
}

export interface RemediationPlan {
  id: string
  finding_id: string
  host_id: string
  hostname: string
  report_id: string
  control_id: string
  title: string
  category: string
  severity: Severity
  current_state: string | null
  required_state: string | null
  remediation_summary: string
  affected_paths: string[]
  reboot_required: boolean
  service_restart: boolean
  rationale: string | null
  status: RemediationPlanStatus
  version: number
  requested_by: string
  requested_by_name: string
  requested_at: string
  approved_by: string | null
  approved_by_name: string | null
  approved_at: string | null
  rejected_by: string | null
  rejected_by_name: string | null
  rejected_at: string | null
  rejection_reason: string | null
  canceled_by: string | null
  canceled_by_name: string | null
  canceled_at: string | null
  cancellation_reason: string | null
  source_is_current: boolean
  finding_still_open: boolean
  action_catalog_status: RemediationCatalogStatus
  action: RemediationAction | null
  execution_enabled: false
  execution_status: 'not_supported'
  execution_reason: string
  created_at: string
  updated_at: string
}

export type RemediationChangeSetStatus = 'pending_authorization' | 'authorized' | 'canceled'

export interface RemediationChangeSetGate {
  code: 'action_integrity' | 'agent_attestation' | 'canary_scope' | 'evidence_freshness' | 'four_eyes' | 'maintenance_window' | 'policy_authorization' | 'rate_limit' | 'rollback_checkpoint'
  status: 'passed' | 'blocked'
  detail: string
}

export interface RemediationChangeSetPlan {
  plan_id: string
  hostname: string
  host_id: string
  control_id: string
  title: string
  action_id: string
  action_version: number
  action_digest: string
  plan_approved_by: string
}

export interface RemediationChangeSetTarget {
  host_id: string
  hostname: string
  agent_id: string
  group_id: string
  group_name: string
  policy_id: string
  policy_name: string
  policy_version: number
  rollout_phase: 'canary' | 'deferred'
  required_capability: string
  capability_attested: boolean
}

export interface RemediationChangeSet {
  id: string
  status: RemediationChangeSetStatus
  payload_schema_version: '1.0'
  payload: Record<string, unknown>
  digest: string
  signature: string | null
  signing_key_id: string | null
  signing_key_fingerprint: string | null
  signing_public_key: string | null
  maintenance_window_start: string
  maintenance_window_end: string
  batch_size: number
  batch_interval_minutes: number
  plans: RemediationChangeSetPlan[]
  targets: RemediationChangeSetTarget[]
  gates: RemediationChangeSetGate[]
  requested_by: string
  requested_by_name: string
  requested_at: string
  authorized_by: string | null
  authorized_by_name: string | null
  authorized_at: string | null
  canceled_by: string | null
  canceled_by_name: string | null
  canceled_at: string | null
  cancellation_reason: string | null
  execution_enabled: false
  execution_status: 'not_supported'
  execution_reason: string
  created_at: string
  updated_at: string
}

export type RemediationValidationStatus = 'queued' | 'delivered' | 'ready' | 'blocked' | 'expired' | 'canceled'

export interface RemediationValidationCheck {
  code: string
  status: 'passed' | 'blocked'
  detail: string
}

export interface RemediationValidationActionResult {
  plan_id: string
  action_digest: string
  status: 'ready' | 'blocked'
  checks: RemediationValidationCheck[]
}

export interface RemediationRecoveryEntry {
  checkpoint_id: string
  plan_id: string
  action_digest: string
  operation_index: number
  rollback_index: number
  path: string
  source_state: 'regular_file' | 'absent' | 'blocked'
  source_digest: string | null
  size_bytes: number | null
  mode: string | null
  uid: number | null
  gid: number | null
  status: 'ready' | 'blocked'
  detail: string
  backup_created: false
}

export interface RemediationRecoveryPlan {
  schema_version: '1.0'
  kind: 'remediation-recovery-plan'
  status: 'ready' | 'blocked'
  backup_before_write: true
  automatic_rollback_required: true
  stop_on_failure: true
  journal_state: 'planned'
  entries: RemediationRecoveryEntry[]
  rollback_order: string[]
  execution_enabled: false
  changes_applied: false
}

export interface RemediationValidationReceipt {
  schema_version: '1.0'
  kind: 'remediation-validation-receipt'
  validation_id: string
  change_set_id: string
  contract_digest: string
  agent_id: string
  host_id: string
  status: 'ready' | 'blocked'
  evaluated_at: string
  execution_enabled: false
  changes_applied: false
  agent_version: string
  agent_integrity_digest: string
  action_results: RemediationValidationActionResult[]
  recovery_plan: RemediationRecoveryPlan | null
  error: string | null
}

export interface RemediationValidationJob {
  id: string
  change_set_id: string
  host_id: string
  agent_id: string
  status: RemediationValidationStatus
  contract_digest: string
  contract: Record<string, unknown> | null
  requested_by: string
  requested_by_name: string
  requested_at: string
  delivered_at: string | null
  lease_expires_at: string | null
  completed_at: string | null
  receipt: RemediationValidationReceipt | null
  receipt_signature: string | null
  error: string | null
  execution_enabled: false
  changes_applied: false
}

export interface RemediationCheckpointResult {
  checkpoint_id: string
  source_state: 'regular_file' | 'absent'
  status: 'ready' | 'blocked'
  backup_created: boolean
  encrypted_blob_digest: string | null
  encrypted_size_bytes: number | null
  error: string | null
}

export interface RemediationCheckpointReceipt {
  schema_version: '1.0'
  kind: 'remediation-checkpoint-receipt'
  checkpoint_job_id: string
  validation_id: string
  change_set_id: string
  contract_digest: string
  agent_id: string
  host_id: string
  status: 'ready' | 'blocked'
  journal_state: 'checkpointed' | 'blocked'
  journal_digest: string
  storage_scope: 'agent_local_encrypted'
  encryption: 'AES-256-GCM'
  prepared_at: string
  agent_version: string
  agent_integrity_digest: string
  checkpoint_results: RemediationCheckpointResult[]
  error: string | null
  execution_enabled: false
  changes_applied: false
}

export interface RemediationCheckpointJob {
  id: string
  change_set_id: string
  validation_job_id: string
  host_id: string
  agent_id: string
  status: RemediationValidationStatus
  contract_digest: string
  requested_by: string
  requested_by_name: string
  requested_at: string
  delivered_at: string | null
  lease_expires_at: string | null
  completed_at: string | null
  receipt: RemediationCheckpointReceipt | null
  receipt_signature: string | null
  error: string | null
  execution_enabled: false
  changes_applied: false
}

export interface RemediationRecoveryVerificationResult {
  checkpoint_id: string
  source_state: 'regular_file' | 'absent'
  status: 'verified' | 'blocked'
  encrypted_blob_digest: string | null
  encrypted_size_bytes: number | null
  error: string | null
}

export interface RemediationRecoveryVerificationReceipt {
  schema_version: '1.0'
  kind: 'remediation-recovery-verification-receipt'
  verification_job_id: string
  checkpoint_job_id: string
  validation_id: string
  change_set_id: string
  contract_digest: string
  checkpoint_journal_digest: string
  agent_id: string
  host_id: string
  status: 'ready' | 'blocked'
  verification_state: 'verified' | 'blocked'
  verified_at: string
  agent_version: string
  agent_integrity_digest: string
  verification_results: RemediationRecoveryVerificationResult[]
  error: string | null
  execution_enabled: false
  changes_applied: false
}

export interface RemediationRecoveryVerificationJob {
  id: string
  change_set_id: string
  checkpoint_job_id: string
  validation_job_id: string
  host_id: string
  agent_id: string
  status: 'queued' | 'delivered' | 'ready' | 'blocked' | 'expired' | 'canceled'
  contract_digest: string
  checkpoint_journal_digest: string
  requested_by: string
  requested_by_name: string
  requested_at: string
  delivered_at: string | null
  lease_expires_at: string | null
  completed_at: string | null
  receipt: RemediationRecoveryVerificationReceipt | null
  receipt_signature: string | null
  error: string | null
  execution_enabled: false
  changes_applied: false
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
  platform_trust_status: 'pinned' | 'missing'
  platform_command_key_fingerprint: string | null
  last_seen_at: string | null
  last_policy_version: number | null
  last_scan_at: string | null
  latest_task_status: 'queued' | 'dispatched' | 'completed' | 'failed' | 'cancelled' | null
  latest_task_created_at: string | null
  revoked_at: string | null
  created_at: string
}

export interface AgentEnrollmentRecovery {
  agent_id: string
  host_id: string
  hostname: string
  agent_version: string
  fingerprint: string
  reason: 'host_deleted' | 'credentials_revoked' | 'inventory_incomplete'
  last_seen_at: string | null
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
  token_type: 'one_time' | 'reusable'
  max_uses: number | null
  use_count: number
  platform_trust: PlatformCommandTrust
}

export interface AgentEnrollmentToken {
  id: string
  name: string
  group_id: string
  group_name: string
  token_prefix: string
  token_type: 'one_time' | 'reusable'
  max_uses: number | null
  use_count: number
  expires_at: string
  used_at: string | null
  last_used_at: string | null
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

export interface OfflineScannerPackage {
  version: string
  filename: string
  size_bytes: number
  sha256: string
  audit_only: true
}

export interface PlatformCommandTrust {
  key_id: string
  key_version: number
  algorithm: 'Ed25519'
  public_key: string
  fingerprint: string
}

export interface AgentConnectivity {
  public_url: string
  platform_trust: PlatformCommandTrust
  key_rotation: PlatformCommandKeyRotation | null
}

export interface PlatformCommandKeyRotation {
  status: 'staged' | 'ready'
  current_key: PlatformCommandTrust
  next_key: PlatformCommandTrust
  eligible_agents: number
  acknowledged_agents: number
  blocking_agents: number
  staged_at: string
}
