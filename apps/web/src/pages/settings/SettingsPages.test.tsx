import { fireEvent, render, screen, within } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { vi } from 'vitest'
import { AuthenticationSettingsPage } from './AuthenticationSettingsPage'
import { CertificatesSettingsPage } from './CertificatesSettingsPage'
import { SettingsLayout } from './SettingsLayout'
import { SettingsOverviewPage } from './SettingsOverviewPage'
import { UsersSettingsPage } from './UsersSettingsPage'
import { AgentsSettingsPage } from './AgentsSettingsPage'

vi.mock('../../auth/useAuth', () => ({
  useAuth: () => ({ user: { id: 'user-1', email: 'admin@lsa.local', name: 'Security Administrator', role: 'admin' } }),
}))

vi.mock('../../api/client', () => ({
  api: {
    providers: vi.fn().mockResolvedValue([]),
    users: vi.fn().mockResolvedValue([{ id: 'user-1', email: 'admin@lsa.local', name: 'Security Administrator', role: 'admin', is_active: true, auth_source: 'local', provider_name: null, last_login_at: null, created_at: '2026-01-01T00:00:00Z' }]),
    tlsCertificate: vi.fn().mockResolvedValue({ id: 'cert-1', fingerprint: 'ab'.repeat(32), subject: 'CN=localhost', issuer: 'CN=localhost', hostnames: ['localhost'], not_valid_before: '2026-01-01T00:00:00Z', not_valid_after: '2027-01-01T00:00:00Z', is_active: true, created_at: '2026-01-01T00:00:00Z' }),
    agents: vi.fn().mockResolvedValue([]),
    agentGroups: vi.fn().mockResolvedValue([{ id: 'group-1', name: 'Default Linux Fleet', description: '', policy_id: 'policy-1', policy_name: 'Monitor (Audit Only)', policy_version: 1, agent_count: 0, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z' }]),
    agentPolicies: vi.fn().mockResolvedValue([{ id: 'policy-1', name: 'Monitor (Audit Only)', description: '', version: 1, default_mode: 'audit', control_modes: {}, settings: { schedule_minutes: 60 }, assigned_groups: 1, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z' }]),
    controlCatalog: vi.fn().mockResolvedValue([{ control_id: 'CIS-DEBIAN13-1.1.1', title: 'Disable unused filesystem', category: 'filesystem', module: 'cis_debian13' }]),
    agentEnrollmentTokens: vi.fn().mockResolvedValue([]),
  },
}))

function renderSettings() {
  return render(
    <MemoryRouter initialEntries={['/settings']}>
      <Routes>
        <Route path="settings" element={<SettingsLayout />}>
          <Route index element={<SettingsOverviewPage />} />
          <Route path="users" element={<UsersSettingsPage />} />
          <Route path="authentication" element={<AuthenticationSettingsPage />} />
          <Route path="agents" element={<AgentsSettingsPage />} />
          <Route path="certificates" element={<CertificatesSettingsPage />} />
        </Route>
      </Routes>
    </MemoryRouter>,
  )
}

function settingsNavigation() {
  return within(screen.getByRole('navigation', { name: 'Settings sections' }))
}

describe('Settings', () => {
  it('organizes administration controls and navigates to authentication', async () => {
    renderSettings()

    expect(screen.getByRole('heading', { name: 'Settings' })).toBeInTheDocument()
    expect(screen.getByText('Recommended next controls')).toBeInTheDocument()
    fireEvent.click(settingsNavigation().getByRole('link', { name: /Authentication/ }))

    expect(screen.getByRole('heading', { name: 'Authentication' })).toBeInTheDocument()
    expect(await screen.findByText('No identity providers')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Add provider/ })).toBeInTheDocument()
  })

  it('shows JIT users and the enforced role model', async () => {
    renderSettings()
    fireEvent.click(settingsNavigation().getByRole('link', { name: /Users & access/ }))

    expect(screen.getByRole('heading', { name: 'Users, roles & permissions' })).toBeInTheDocument()
    expect(await screen.findByText('Emergency local')).toBeInTheDocument()
    expect(screen.getByText('Enforced permission model')).toBeInTheDocument()
  })

  it('shows the active certificate and enables secure rotation', async () => {
    renderSettings()
    fireEvent.click(settingsNavigation().getByRole('link', { name: /TLS certificates/ }))

    expect(screen.getByRole('heading', { name: 'TLS certificates' })).toBeInTheDocument()
    expect(await screen.findByText('Active certificate')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Install certificate' })).toBeEnabled()
  })

  it('shows audit-locked agent groups and versioned policies', async () => {
    renderSettings()
    fireEvent.click(settingsNavigation().getByRole('link', { name: /Agents & policies/ }))

    expect(await screen.findByRole('heading', { name: 'Agents, groups & policies' })).toBeInTheDocument()
    expect(await screen.findByText(/Audit-only safety lock is active/)).toBeInTheDocument()
    expect(screen.getByText('Default Linux Fleet')).toBeInTheDocument()
    expect(screen.getByText('Monitor (Audit Only)')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Enrollment token/ })).toBeEnabled()
  })
})
