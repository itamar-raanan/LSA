import { fireEvent, render, screen, within } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { vi } from 'vitest'
import { AuthenticationSettingsPage } from './AuthenticationSettingsPage'
import { CertificatesSettingsPage } from './CertificatesSettingsPage'
import { SettingsLayout } from './SettingsLayout'
import { SettingsOverviewPage } from './SettingsOverviewPage'
import { UsersSettingsPage } from './UsersSettingsPage'

vi.mock('../../auth/useAuth', () => ({
  useAuth: () => ({ user: { id: 'user-1', email: 'admin@lsa.local', name: 'Security Administrator', role: 'admin' } }),
}))

vi.mock('../../api/client', () => ({
  api: {
    providers: vi.fn().mockResolvedValue([]),
    users: vi.fn().mockResolvedValue([{ id: 'user-1', email: 'admin@lsa.local', name: 'Security Administrator', role: 'admin', is_active: true, auth_source: 'local', provider_name: null, last_login_at: null, created_at: '2026-01-01T00:00:00Z' }]),
    tlsCertificate: vi.fn().mockResolvedValue({ id: 'cert-1', fingerprint: 'ab'.repeat(32), subject: 'CN=localhost', issuer: 'CN=localhost', hostnames: ['localhost'], not_valid_before: '2026-01-01T00:00:00Z', not_valid_after: '2027-01-01T00:00:00Z', is_active: true, created_at: '2026-01-01T00:00:00Z' }),
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
})
