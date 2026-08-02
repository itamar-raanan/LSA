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
  compliance_score: number | null
  security_score: number | null
  last_scan_at: string | null
  finding_counts: Record<Severity, number>
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
  reboot_required: boolean
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
