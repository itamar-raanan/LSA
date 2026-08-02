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
    agentPackages: vi.fn().mockResolvedValue([{ id: 'linux-universal', version: '0.1.0', filename: 'lsa-agent-0.1.0-linux-universal.tar.gz', content_type: 'application/gzip', operating_system: 'Linux (Debian, Ubuntu, RHEL)', architecture: 'x86_64 / arm64', size_bytes: 204800, sha256: 'a'.repeat(64) }]),
    downloadAgentPackage: vi.fn(),
  },
}))

describe('Agents', () => {
  it('places Agents in primary navigation outside Settings', () => {
    render(<MemoryRouter initialEntries={['/agents']}><Routes><Route element={<AppShell />}><Route path="agents" element={<div>Agent route</div>} /></Route></Routes></MemoryRouter>)

    const navigation = within(screen.getByRole('navigation', { name: 'Primary navigation' }))
    expect(navigation.getByRole('link', { name: 'Agents' })).toHaveAttribute('href', '/agents')
    expect(navigation.getByRole('link', { name: 'Agents' })).toHaveAttribute('aria-current', 'page')
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
    expect(screen.getByRole('button', { name: 'Download package' })).toBeEnabled()
    expect(screen.getByText(/SHA-256/)).toBeInTheDocument()
  })
})
