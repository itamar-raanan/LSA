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

