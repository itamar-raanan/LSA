import { fireEvent, render, screen, within } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { vi } from 'vitest'
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
    agentPackages: vi.fn().mockResolvedValue([
      { id: 'linux-deb', version: '0.4.0', filename: 'lsa-agent_0.4.0_all.deb', content_type: 'application/vnd.debian.binary-package', operating_system: 'Debian 13 / Ubuntu 24.04+', architecture: 'noarch', package_format: 'deb', release_channel: 'stable', audit_only: true, size_bytes: 204800, sha256: 'a'.repeat(64) },
      { id: 'linux-rpm', version: '0.4.0', filename: 'lsa-agent-0.4.0-1.noarch.rpm', content_type: 'application/x-rpm', operating_system: 'RHEL / Rocky / AlmaLinux 9+', architecture: 'noarch', package_format: 'rpm', release_channel: 'stable', audit_only: true, size_bytes: 204800, sha256: 'b'.repeat(64) },
      { id: 'linux-universal', version: '0.4.0', filename: 'lsa-agent-0.4.0-linux-universal.tar.gz', content_type: 'application/gzip', operating_system: 'Linux (Debian, Ubuntu, RHEL)', architecture: 'x86_64 / arm64', package_format: 'tar.gz', release_channel: 'stable', audit_only: true, size_bytes: 204800, sha256: 'c'.repeat(64) },
    ]),
    downloadAgentPackage: vi.fn(),
    agentPolicyVersions: vi.fn().mockResolvedValue([
      { version: 1, default_mode: 'audit', control_modes: {}, settings: { schedule_minutes: 60 }, created_by_name: 'Security Administrator', created_at: '2026-01-01T00:00:00Z' },
    ]),
    restoreAgentPolicy: vi.fn(),
    runAgentAudits: vi.fn(),
    bulkAssignAgentGroup: vi.fn(),
    bulkRevokeAgents: vi.fn(),
  },
}))

describe('Agents', () => {
  it('places endpoint operations in primary navigation outside Administration', () => {
    render(<MemoryRouter initialEntries={['/agents']}><Routes><Route element={<AppShell />}><Route path="agents" element={<div>Agent route</div>} /></Route></Routes></MemoryRouter>)

    const navigation = within(screen.getByRole('navigation', { name: 'Primary navigation' }))
    expect(navigation.getByRole('link', { name: 'Endpoints' })).toHaveAttribute('href', '/agents')
    expect(navigation.getByRole('link', { name: 'Endpoints' })).toHaveAttribute('aria-current', 'page')
  })

  it('opens with all hosts and scopes categorized policy controls by group', async () => {
    render(<MemoryRouter><AgentsSettingsPage /></MemoryRouter>)

    expect(await screen.findByRole('heading', { name: 'Agents' })).toBeInTheDocument()
    expect(screen.getByText(/Audit-only safety lock is active/)).toBeInTheDocument()
    const groupNavigation = screen.getByRole('navigation', { name: 'Fleet groups' })
    expect(within(groupNavigation).getByRole('button', { name: /All hosts/ })).toBeInTheDocument()
    const groupButton = within(groupNavigation).getByRole('button', { name: /Default Linux Fleet/ })
    expect(screen.getByRole('heading', { name: 'All hosts' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Hosts' })).toBeEnabled()
    expect(screen.queryByRole('button', { name: 'Policy' })).not.toBeInTheDocument()

    fireEvent.click(groupButton)
    expect(screen.getByRole('button', { name: 'Policy' })).toBeEnabled()
    fireEvent.click(screen.getByRole('button', { name: 'Policy' }))
    expect(screen.getByRole('heading', { name: 'Monitor (Audit Only)' })).toBeInTheDocument()
    expect(screen.getByRole('navigation', { name: 'Policy categories' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /filesystem/ }))
    expect(screen.getByText('CIS-DEBIAN13-1.1.1')).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: 'Mode for CIS-DEBIAN13-1.1.1' })).toBeEnabled()

    fireEvent.click(within(groupNavigation).getByRole('button', { name: /Production Servers/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Policy' }))
    expect(screen.getByRole('heading', { name: 'Production Baseline' })).toBeInTheDocument()

    expect(screen.getByRole('button', { name: /Enrollment token/ })).toBeEnabled()
    expect(screen.getByRole('button', { name: /Install agent/ })).toBeEnabled()

    fireEvent.click(screen.getByRole('button', { name: /Install agent/ }))
    expect(screen.getByRole('heading', { name: 'Install the unified Linux agent' })).toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: 'Download package' })).toHaveLength(3)
    expect(screen.getByText(/sudo apt install .*lsa-agent_0.4.0_all.deb/)).toBeInTheDocument()
    fireEvent.click(screen.getAllByRole('button', { name: /Install steps/ })[0])
    expect(screen.getByText(/sudo dnf install .*lsa-agent-0.4.0-1.noarch.rpm/)).toBeInTheDocument()
    expect(screen.getAllByText(/SHA-256/)).toHaveLength(3)
  })
})
