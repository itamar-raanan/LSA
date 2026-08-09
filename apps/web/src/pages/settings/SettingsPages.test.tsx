import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter, Navigate, Route, Routes } from 'react-router-dom'
import { beforeEach, vi } from 'vitest'
import { api } from '../../api/client'
import { AuthenticationSettingsPage } from './AuthenticationSettingsPage'
import { CertificatesSettingsPage } from './CertificatesSettingsPage'
import { CredentialsTrustPage } from './CredentialsTrustPage'
import { SettingsLayout } from './SettingsLayout'
import { UsersSettingsPage } from './UsersSettingsPage'

vi.mock('../../auth/useAuth', () => ({
  useAuth: () => ({ user: { id: 'user-1', email: 'admin@lsa.local', name: 'Security Administrator', role: 'admin' } }),
}))

vi.mock('../../api/client', () => ({
  api: {
    providers: vi.fn().mockResolvedValue([]),
    deleteProvider: vi.fn().mockResolvedValue(undefined),
    updateUserRole: vi.fn().mockResolvedValue(undefined),
    updateUserStatus: vi.fn().mockResolvedValue(undefined),
    users: vi.fn().mockResolvedValue([{ id: 'user-1', email: 'admin@lsa.local', name: 'Security Administrator', role: 'admin', is_active: true, auth_source: 'local', provider_name: null, last_login_at: null, created_at: '2026-01-01T00:00:00Z' }]),
    tlsCertificate: vi.fn().mockResolvedValue({ id: 'cert-1', fingerprint: 'ab'.repeat(32), subject: 'CN=localhost', issuer: 'CN=localhost', hostnames: ['localhost'], not_valid_before: '2026-01-01T00:00:00Z', not_valid_after: '2027-01-01T00:00:00Z', is_active: true, created_at: '2026-01-01T00:00:00Z' }),
    tokens: vi.fn().mockResolvedValue([]),
    signingKeys: vi.fn().mockResolvedValue([]),
    hosts: vi.fn().mockResolvedValue([]),
  },
}))

function renderSettings(initialEntry = '/settings') {
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <Routes>
        <Route path="settings" element={<SettingsLayout />}>
          <Route index element={<Navigate to="users" replace />} />
          <Route path="users" element={<UsersSettingsPage />} />
          <Route path="authentication" element={<AuthenticationSettingsPage />} />
          <Route path="credentials" element={<CredentialsTrustPage />} />
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
  beforeEach(() => {
    vi.mocked(api.providers).mockResolvedValue([])
    vi.mocked(api.users).mockResolvedValue([{ id: 'user-1', email: 'admin@lsa.local', name: 'Security Administrator', role: 'admin', is_active: true, auth_source: 'local', provider_name: null, last_login_at: null, created_at: '2026-01-01T00:00:00Z' }])
    vi.mocked(api.deleteProvider).mockReset()
    vi.mocked(api.deleteProvider).mockResolvedValue(undefined)
    vi.mocked(api.updateUserRole).mockReset()
    vi.mocked(api.updateUserRole).mockResolvedValue({ id: 'user-2', email: 'user@example.test', name: 'Managed User', role: 'admin', is_active: true, auth_source: 'oidc', provider_name: 'Corporate Entra ID', last_login_at: null, created_at: '2026-01-01T00:00:00Z' })
    vi.mocked(api.updateUserStatus).mockReset()
    vi.mocked(api.updateUserStatus).mockResolvedValue({ id: 'user-2', email: 'user@example.test', name: 'Managed User', role: 'analyst', is_active: false, auth_source: 'oidc', provider_name: 'Corporate Entra ID', last_login_at: null, created_at: '2026-01-01T00:00:00Z' })
  })

  it('organizes administration controls and navigates to authentication', async () => {
    renderSettings()

    expect(await screen.findByRole('heading', { name: 'Users, roles & permissions' })).toBeInTheDocument()
    expect(settingsNavigation().getByRole('link', { name: /Users & access/ })).toHaveAttribute('aria-current', 'page')
    fireEvent.click(settingsNavigation().getByRole('link', { name: /Authentication/ }))

    expect(screen.getByRole('heading', { name: 'Authentication' })).toBeInTheDocument()
    expect(await screen.findByText('No identity providers')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Add Provider' })).toBeInTheDocument()
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

  it('consolidates ingestion tokens and signing keys into one trust workspace', async () => {
    renderSettings()
    const navigation = settingsNavigation()
    expect(navigation.getByRole('link', { name: /Credentials & Trust/ })).toBeInTheDocument()
    expect(navigation.queryByRole('link', { name: /^Tokens/ })).not.toBeInTheDocument()
    expect(navigation.queryByRole('link', { name: /^Signing keys/ })).not.toBeInTheDocument()

    fireEvent.click(navigation.getByRole('link', { name: /Credentials & Trust/ }))
    expect(await screen.findByRole('heading', { name: 'Credentials & Trust' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Ingestion Tokens' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /Signing Keys/ }))
    expect(await screen.findByRole('heading', { name: 'Signing Keys' })).toBeInTheDocument()
  })

  it('opens token creation from an Evidence Intake prerequisite link', async () => {
    renderSettings('/settings/credentials?view=tokens&action=create')
    expect(await screen.findByRole('dialog', { name: 'Issue ingestion token' })).toBeInTheDocument()
  })

  it('requires explicit confirmation before deleting an authentication provider', async () => {
    vi.mocked(api.providers).mockResolvedValue([{
      id: 'provider-1',
      name: 'Corporate Entra ID',
      provider_type: 'entra',
      issuer_url: 'https://login.example.test/tenant',
      client_id: 'client-id',
      config: {},
      is_enabled: true,
      secret_configured: true,
      created_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-01-01T00:00:00Z',
    }])
    renderSettings()
    fireEvent.click(settingsNavigation().getByRole('link', { name: /Authentication/ }))

    expect(await screen.findByText('Corporate Entra ID')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Delete Corporate Entra ID' }))
    expect(screen.getByRole('dialog', { name: 'Delete Corporate Entra ID?' })).toBeInTheDocument()
    expect(api.deleteProvider).not.toHaveBeenCalled()

    fireEvent.click(screen.getByRole('button', { name: 'Delete provider' }))
    await waitFor(() => expect(api.deleteProvider).toHaveBeenCalledWith('provider-1'))
  })

  it('explains the impact before disabling a user', async () => {
    vi.mocked(api.users).mockResolvedValue([
      { id: 'user-1', email: 'admin@lsa.local', name: 'Security Administrator', role: 'admin', is_active: true, auth_source: 'local', provider_name: null, last_login_at: null, created_at: '2026-01-01T00:00:00Z' },
      { id: 'user-2', email: 'analyst@example.test', name: 'Security Analyst', role: 'analyst', is_active: true, auth_source: 'oidc', provider_name: 'Corporate Entra ID', last_login_at: null, created_at: '2026-01-01T00:00:00Z' },
    ])
    renderSettings()

    const row = (await screen.findByText('Security Analyst')).closest('tr')
    expect(row).not.toBeNull()
    fireEvent.click(within(row!).getByRole('button', { name: 'Disable' }))
    expect(screen.getByRole('dialog', { name: 'Disable Security Analyst?' })).toHaveTextContent('every active browser session will be revoked')
    expect(api.updateUserStatus).not.toHaveBeenCalled()

    fireEvent.click(screen.getByRole('button', { name: 'Disable user' }))
    await waitFor(() => expect(api.updateUserStatus).toHaveBeenCalledWith('user-2', false))
  })

  it('explains elevated access before assigning the administrator role', async () => {
    vi.mocked(api.users).mockResolvedValue([
      { id: 'user-1', email: 'admin@lsa.local', name: 'Security Administrator', role: 'admin', is_active: true, auth_source: 'local', provider_name: null, last_login_at: null, created_at: '2026-01-01T00:00:00Z' },
      { id: 'user-2', email: 'auditor@example.test', name: 'Compliance Auditor', role: 'auditor', is_active: true, auth_source: 'oidc', provider_name: 'Corporate Entra ID', last_login_at: null, created_at: '2026-01-01T00:00:00Z' },
    ])
    renderSettings()

    const row = (await screen.findByText('Compliance Auditor')).closest('tr')
    expect(row).not.toBeNull()
    fireEvent.change(within(row!).getByRole('combobox'), { target: { value: 'admin' } })
    expect(screen.getByRole('dialog', { name: "Change Compliance Auditor's role?" })).toHaveTextContent('manage users, authentication, credentials, agents, and evidence')
    expect(api.updateUserRole).not.toHaveBeenCalled()

    fireEvent.click(screen.getByRole('button', { name: 'Change role' }))
    await waitFor(() => expect(api.updateUserRole).toHaveBeenCalledWith('user-2', 'admin'))
  })

})
