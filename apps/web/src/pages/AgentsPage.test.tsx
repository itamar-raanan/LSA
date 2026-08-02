import { render, screen, within } from '@testing-library/react'
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
    agentGroups: vi.fn().mockResolvedValue([{ id: 'group-1', name: 'Default Linux Fleet', description: '', policy_id: 'policy-1', policy_name: 'Monitor (Audit Only)', policy_version: 1, agent_count: 0, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z' }]),
    agentPolicies: vi.fn().mockResolvedValue([{ id: 'policy-1', name: 'Monitor (Audit Only)', description: '', version: 1, default_mode: 'audit', control_modes: {}, settings: { schedule_minutes: 60 }, assigned_groups: 1, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z' }]),
    controlCatalog: vi.fn().mockResolvedValue([{ control_id: 'CIS-DEBIAN13-1.1.1', title: 'Disable unused filesystem', category: 'filesystem', module: 'cis_debian13' }]),
    agentEnrollmentTokens: vi.fn().mockResolvedValue([]),
  },
}))

describe('Agents', () => {
  it('places Agents in primary navigation outside Settings', () => {
    render(<MemoryRouter initialEntries={['/agents']}><Routes><Route element={<AppShell />}><Route path="agents" element={<div>Agent route</div>} /></Route></Routes></MemoryRouter>)

    const navigation = within(screen.getByRole('navigation', { name: 'Primary navigation' }))
    expect(navigation.getByRole('link', { name: 'Agents' })).toHaveAttribute('href', '/agents')
    expect(navigation.getByRole('link', { name: 'Agents' })).toHaveAttribute('aria-current', 'page')
  })

  it('shows agent groups and policies as a top-level console page', async () => {
    render(<MemoryRouter><AgentsSettingsPage /></MemoryRouter>)

    expect(await screen.findByRole('heading', { name: 'Agents, groups & policies' })).toBeInTheDocument()
    expect(screen.getByText(/Audit-only safety lock is active/)).toBeInTheDocument()
    expect(screen.getByText('Default Linux Fleet')).toBeInTheDocument()
    expect(screen.getByText('Monitor (Audit Only)')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Enrollment token/ })).toBeEnabled()
  })
})
