import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { vi } from 'vitest'
import { api } from '../api/client'
import { AppShell } from '../components/AppShell'
import { AgentsSettingsPage } from './settings/AgentsSettingsPage'

vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({ user: { id: 'user-1', email: 'admin@lsa.local', name: 'Security Administrator', role: 'admin' }, logout: vi.fn() }),
}))

vi.mock('../api/client', () => ({
  api: {
    agents: vi.fn().mockResolvedValue([]),
    agentGroups: vi.fn().mockResolvedValue([
      { id: 'group-1', name: 'Default Linux Fleet', description: '', policy_id: 'policy-1', policy_name: 'Monitor (Audit Only)', policy_version: 1, agent_count: 0, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z' },
      { id: 'group-2', name: 'Production Servers', description: '', policy_id: 'policy-2', policy_name: 'Production Baseline', policy_version: 3, agent_count: 0, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z' },
    ]),
    agentPolicies: vi.fn().mockResolvedValue([
      { id: 'policy-1', name: 'Monitor (Audit Only)', description: '', version: 1, default_mode: 'audit', control_modes: {}, settings: { schedule_minutes: 60 }, assigned_groups: 1, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z' },
      { id: 'policy-2', name: 'Production Baseline', description: '', version: 3, default_mode: 'audit', control_modes: {}, settings: { schedule_minutes: 15 }, assigned_groups: 1, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z' },
    ]),
    controlCatalog: vi.fn().mockResolvedValue([{ control_id: 'CIS-DEBIAN13-1.1.1', title: 'Disable unused filesystem', category: 'filesystem', module: 'cis_debian13' }]),
    agentEnrollmentTokens: vi.fn().mockResolvedValue([]),
    createAgentEnrollmentToken: vi.fn().mockResolvedValue({ token: 'lsa_enroll_test_token' }),
    agentConnectivity: vi.fn().mockResolvedValue({ public_url: 'https://lsa.example.test:8444' }),
    agentPackages: vi.fn().mockResolvedValue([
      { id: 'linux-deb', version: '0.4.1', filename: 'lsa-agent_0.4.1_all.deb', content_type: 'application/vnd.debian.binary-package', operating_system: 'Debian 13 / Ubuntu 24.04+', architecture: 'noarch', package_format: 'deb', release_channel: 'stable', audit_only: true, size_bytes: 204800, sha256: 'a'.repeat(64) },
      { id: 'linux-rpm', version: '0.4.1', filename: 'lsa-agent-0.4.1-1.noarch.rpm', content_type: 'application/x-rpm', operating_system: 'RHEL / Rocky / AlmaLinux 9+', architecture: 'noarch', package_format: 'rpm', release_channel: 'stable', audit_only: true, size_bytes: 204800, sha256: 'b'.repeat(64) },
      { id: 'linux-universal', version: '0.4.1', filename: 'lsa-agent-0.4.1-linux-universal.tar.gz', content_type: 'application/gzip', operating_system: 'Linux (Debian, Ubuntu, RHEL)', architecture: 'x86_64 / arm64', package_format: 'tar.gz', release_channel: 'stable', audit_only: true, size_bytes: 204800, sha256: 'c'.repeat(64) },
    ]),
    downloadAgentPackage: vi.fn(),
    agentPolicyVersions: vi.fn().mockResolvedValue([
      { version: 1, default_mode: 'audit', control_modes: {}, settings: { schedule_minutes: 60 }, created_by_name: 'Security Administrator', created_at: '2026-01-01T00:00:00Z' },
    ]),
    restoreAgentPolicy: vi.fn(),
    runAgentAudits: vi.fn(),
    bulkAssignAgentGroup: vi.fn(),
    bulkRevokeAgents: vi.fn(),
    revokeAgent: vi.fn().mockResolvedValue(undefined),
    assignAgentGroup: vi.fn(),
  },
}))

describe('Agents', () => {
  it('places endpoint operations in primary navigation outside Administration', () => {
    render(<MemoryRouter initialEntries={['/agents']}><Routes><Route element={<AppShell />}><Route path="agents" element={<div>Agent route</div>} /></Route></Routes></MemoryRouter>)

    const navigation = within(screen.getByRole('navigation', { name: 'Primary navigation' }))
    expect(navigation.getByRole('link', { name: 'Agents & groups' })).toHaveAttribute('href', '/agents')
    expect(navigation.getByRole('link', { name: 'Agents & groups' })).toHaveAttribute('aria-current', 'page')
    expect(navigation.getByRole('link', { name: 'Applications' })).toHaveAttribute('href', '/applications')
    expect(navigation.queryByRole('link', { name: 'Certificates' })).not.toBeInTheDocument()
    expect(navigation.getByRole('link', { name: 'Administration' })).toHaveAttribute('href', '/settings')
  })

  it('opens with all hosts and scopes categorized policy controls by group', async () => {
    render(<MemoryRouter><AgentsSettingsPage /></MemoryRouter>)

    expect(await screen.findByRole('heading', { name: 'Agents' })).toBeInTheDocument()
    const groupNavigation = screen.getByRole('navigation', { name: 'Fleet groups' })
    expect(within(groupNavigation).getByRole('button', { name: /All Agents/ })).toBeInTheDocument()
    const groupButton = within(groupNavigation).getByRole('button', { name: /Default Linux Fleet/ })
    const createGroupToggle = screen.getByRole('button', { name: 'Create group' })
    fireEvent.click(createGroupToggle)
    expect(screen.getByRole('textbox', { name: 'Group name' }).closest('form')).toHaveClass('min-w-0')
    fireEvent.click(createGroupToggle)
    expect(screen.getByRole('heading', { name: 'All Agents' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Hosts' })).toBeEnabled()
    expect(screen.getByRole('button', { name: 'Deployment' })).toBeEnabled()
    expect(screen.queryByRole('button', { name: 'Policy' })).not.toBeInTheDocument()

    fireEvent.click(groupButton)
    expect(screen.getByRole('button', { name: 'Policy' })).toBeEnabled()
    fireEvent.click(screen.getByRole('button', { name: 'Policy' }))
    expect(screen.getByRole('heading', { name: 'Monitor (Audit Only)' })).toBeInTheDocument()
    expect(screen.getByText(/Audit-Only Safety Lock Is Active/)).toBeInTheDocument()
    expect(screen.getByText('Apply another policy').parentElement).toHaveClass('min-w-0')
    expect(screen.getByRole('navigation', { name: 'Policy categories' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /filesystem/ }))
    expect(screen.getByText('CIS-DEBIAN13-1.1.1')).toBeInTheDocument()
    expect(screen.getByText('CIS-DEBIAN13-1.1.1').parentElement).toHaveClass('min-w-0')
    expect(screen.getByText('CIS-DEBIAN13-1.1.1').parentElement?.className).toContain('2xl:grid-cols')
    expect(screen.getByRole('combobox', { name: 'Mode for CIS-DEBIAN13-1.1.1' })).toBeEnabled()

    fireEvent.click(within(groupNavigation).getByRole('button', { name: /Production Servers/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Policy' }))
    expect(screen.getByRole('heading', { name: 'Production Baseline' })).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /Deploy agent/ }))
    fireEvent.change(screen.getByRole('textbox', { name: 'Token name' }), { target: { value: 'Production Deployment' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create enrollment token' }))
    fireEvent.click(await screen.findByRole('button', { name: /Continue to installation/ }))
    expect(screen.getByRole('heading', { name: 'Install the unified Linux agent' })).toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: 'Download Package' })).toHaveLength(1)
    expect(screen.getByText(/sudo apt install .*lsa-agent_0.4.1_all.deb/)).toBeInTheDocument()
    expect(screen.getByText(/--platform-url 'https:\/\/lsa.example.test:8444'/)).toBeInTheDocument()
    fireEvent.change(screen.getByRole('combobox', { name: 'Agent package' }), { target: { value: 'linux-rpm' } })
    expect(screen.getByText(/sudo dnf install .*lsa-agent-0.4.1-1.noarch.rpm/)).toBeInTheDocument()
    expect(screen.getAllByText(/SHA-256/)).toHaveLength(1)
  })

  it('separates connection and report freshness and explains agent revocation', async () => {
    vi.mocked(api.agents).mockResolvedValueOnce([{
      id: 'agent-1', host_id: 'host-1', hostname: 'web-01', group_id: 'group-1', group_name: 'Default Linux Fleet', policy_name: 'Monitor (Audit Only)', policy_version: 1, agent_version: '0.4.1', capabilities: ['audit'], fingerprint: 'fingerprint', last_seen_at: new Date().toISOString(), last_policy_version: 1, last_scan_at: new Date().toISOString(), latest_task_status: 'completed', latest_task_created_at: new Date().toISOString(), revoked_at: null, created_at: '2026-01-01T00:00:00Z',
    }])
    render(<MemoryRouter><AgentsSettingsPage /></MemoryRouter>)

    const row = (await screen.findByText('web-01')).closest('tr')
    expect(row).not.toBeNull()
    expect(screen.getByRole('columnheader', { name: 'Connection' })).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: 'Report freshness' })).toBeInTheDocument()
    expect(within(row!).getByText('online')).toBeInTheDocument()
    expect(within(row!).getByText('fresh')).toBeInTheDocument()

    fireEvent.click(within(row!).getByRole('button', { name: 'Revoke web-01' }))
    expect(screen.getByRole('dialog', { name: 'Revoke web-01?' })).toHaveTextContent('cannot reconnect or submit new evidence')
    expect(api.revokeAgent).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Revoke agent' }))
    await waitFor(() => expect(api.revokeAgent).toHaveBeenCalledWith('agent-1'))
  })
})
