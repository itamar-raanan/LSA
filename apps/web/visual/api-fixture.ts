const now = '2026-08-20T12:00:00Z'
const host = {
  id: 'host-1', hostname: 'web-01', fqdn: 'web-01.example.com', operating_system: 'Debian GNU/Linux', os_family: 'debian', os_version: '13', kernel: '6.12.0-amd64', architecture: 'x86_64', ip_addresses: ['10.24.8.20'], tags: { environment: 'production', owner: 'Platform' }, compliance_score: 89.6, security_score: 82, last_scan_at: now,
  finding_counts: { critical: 1, high: 3, medium: 8, low: 4, info: 0 }, system_info: { cpu_model: 'Intel Xeon Gold', cpu_cores: 8, memory_mb: 16384, uptime_seconds: 432000, virtualization_type: 'kvm', virtualization_role: 'guest', system_vendor: 'QEMU', product_name: 'Standard PC', timezone: 'UTC' }, application_count: 127,
}
const host2 = { ...host, id: 'host-2', hostname: 'db-01', fqdn: 'db-01.example.com', ip_addresses: ['10.24.8.31'], security_score: 64, compliance_score: 72.4, finding_counts: { critical: 2, high: 5, medium: 11, low: 2, info: 0 }, tags: { environment: 'production', owner: 'Database' } }
const finding = { id: 'finding-1', host_id: host.id, hostname: host.hostname, report_id: 'report-1', control_id: 'CIS-DEBIAN13-5.1.20', module: 'cis', category: 'ssh', title: 'Disable Direct Root SSH Login', severity: 'critical', status: 'fail', lifecycle: 'new', expected: 'PermitRootLogin no', actual: 'PermitRootLogin yes', remediation_summary: 'Disable direct root SSH access after confirming administrative sudo access.', remediation_commands: [], verification_commands: [], reboot_required: false, service_restart: true }
const policies = [{ id: 'policy-1', name: 'Monitor (Audit Only)', description: 'Collect and report posture without changing host configuration.', version: 4, default_mode: 'audit', control_modes: {}, settings: { schedule_minutes: 60 }, assigned_groups: 1, created_at: now, updated_at: now }]
const groups = [{ id: 'group-1', name: 'Default Linux Fleet', description: 'Production Linux servers monitored by the platform team.', policy_id: 'policy-1', policy_name: 'Monitor (Audit Only)', policy_version: 4, agent_count: 2, created_at: now, updated_at: now }]
const agents = [
  { id: 'agent-1', host_id: host.id, hostname: host.hostname, group_id: 'group-1', group_name: groups[0].name, policy_name: policies[0].name, policy_version: 4, agent_version: '0.4.1', capabilities: ['audit'], fingerprint: 'agent-web-01', platform_trust_status: 'pinned', platform_command_key_fingerprint: 'f'.repeat(64), last_seen_at: now, last_policy_version: 4, last_scan_at: now, latest_task_status: 'completed', latest_task_created_at: now, revoked_at: null, created_at: now },
  { id: 'agent-2', host_id: host2.id, hostname: host2.hostname, group_id: 'group-1', group_name: groups[0].name, policy_name: policies[0].name, policy_version: 4, agent_version: '0.4.1', capabilities: ['audit'], fingerprint: 'agent-db-01', platform_trust_status: 'pinned', platform_command_key_fingerprint: 'f'.repeat(64), last_seen_at: now, last_policy_version: 4, last_scan_at: now, latest_task_status: 'completed', latest_task_created_at: now, revoked_at: null, created_at: now },
]
const users = [
  { id: 'user-1', email: 'admin@lsa.local', name: 'Security Administrator', role: 'admin', is_active: true, auth_source: 'local', provider_name: null, last_login_at: now, created_at: now },
  { id: 'user-2', email: 'analyst@example.com', name: 'Security Analyst', role: 'analyst', is_active: true, auth_source: 'oidc', provider_name: 'Corporate Entra ID', last_login_at: now, created_at: now },
  { id: 'user-3', email: 'audit@example.com', name: 'Compliance Auditor', role: 'auditor', is_active: true, auth_source: 'radius', provider_name: 'Corporate RADIUS', last_login_at: null, created_at: now },
]

export class ApiError extends Error { status = 500 }
export const SESSION_INVALID_EVENT = 'lsa-session-invalid'

const fixture = {
  publicProviders: async () => [], startOidc: () => undefined,
  dashboard: async () => ({ total_hosts: 18, healthy_hosts: 11, at_risk_hosts: 7, critical_hosts: 2, stale_hosts: 1, overall_security_score: 78.4, compliance_score: 84.7, finding_counts: { critical: 3, high: 12, medium: 28, low: 41, info: 9 }, os_distribution: { Debian: 12, Ubuntu: 6 }, highest_risk_hosts: [host2, host] }),
  hostPage: async (options: Record<string, unknown> = {}) => ({ rows: [host2, host], total: 2, page: Number(options.page ?? 0), pageSize: Number(options.pageSize ?? 10) }),
  hostFacets: async () => ({ total: 18, critical: 2, healthy: 11, stale: 1 }), host: async () => host,
  findings: async () => [finding], hostVulnerabilities: async () => [], applications: async () => [], reports: async () => [],
  findingPage: async () => ({ rows: [finding, { ...finding, id: 'finding-2', host_id: host2.id, hostname: host2.hostname, control_id: 'CIS-DEBIAN13-1.5.1', title: 'Restrict Core Dumps', severity: 'high', lifecycle: 'persistent' }], total: 2, page: 0, pageSize: 10 }),
  applicationEstatePage: async () => ({ rows: [], total: 0, page: 0, pageSize: 10 }),
  agents: async () => agents, agentGroups: async () => groups, agentPolicies: async () => policies,
  controlCatalog: async () => [{ control_id: 'CIS-DEBIAN13-5.1.20', title: 'Ensure SSH Root Login Is Disabled', category: 'ssh', module: 'cis_debian13' }, { control_id: 'CIS-DEBIAN13-1.5.1', title: 'Ensure Core Dumps Are Restricted', category: 'kernel', module: 'cis_debian13' }],
  agentEnrollmentTokens: async () => [], agentPackages: async () => [{ id: 'linux-deb', version: '0.4.1', filename: 'lsa-agent_0.4.1_all.deb', content_type: 'application/vnd.debian.binary-package', operating_system: 'Debian 13 / Ubuntu 24.04+', architecture: 'noarch', package_format: 'deb', release_channel: 'stable', audit_only: true, size_bytes: 204800, sha256: 'a'.repeat(64) }],
  agentConnectivity: async () => ({ public_url: 'https://lsa.internal:8444', platform_trust: { key_id: 'platform-key-1', key_version: 1, algorithm: 'Ed25519', public_key: 'cHVibGljLWtleQ==', fingerprint: 'f'.repeat(64) }, key_rotation: null }),
  offlineScannerPackage: async () => ({ version: '0.6.1', filename: 'lsa-offline-scanner-0.6.1.zip', size_bytes: 786432, sha256: 'd'.repeat(64), audit_only: true }),
  agentPolicyVersions: async () => [{ version: 4, default_mode: 'audit', control_modes: {}, settings: { schedule_minutes: 60 }, created_by_name: 'Security Administrator', created_at: now }],
  users: async () => users, providers: async () => [{ id: 'provider-1', name: 'Corporate Entra ID', provider_type: 'entra', issuer_url: 'https://login.example.com/tenant', client_id: 'lsa', config: {}, is_enabled: true, secret_configured: true, created_at: now, updated_at: now }],
}

export const api = new Proxy(fixture as Record<string, (...args: never[]) => unknown>, {
  get(target, property: string) { return target[property] ?? (async () => undefined) },
})
