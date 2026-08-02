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
  it('organizes administration controls and navigates to authentication', () => {
    renderSettings()

    expect(screen.getByRole('heading', { name: 'Settings' })).toBeInTheDocument()
    expect(screen.getByText('Recommended next controls')).toBeInTheDocument()
    fireEvent.click(settingsNavigation().getByRole('link', { name: /Authentication/ }))

    expect(screen.getByRole('heading', { name: 'Authentication' })).toBeInTheDocument()
    expect(screen.getByText('OpenID Connect / SAML SSO')).toBeInTheDocument()
    expect(screen.getByText('RADIUS')).toBeInTheDocument()
  })

  it('shows the proposed role model without presenting it as active', () => {
    renderSettings()
    fireEvent.click(settingsNavigation().getByRole('link', { name: /Users & access/ }))

    expect(screen.getByRole('heading', { name: 'Users, roles & permissions' })).toBeInTheDocument()
    expect(screen.getAllByText('Backend required').length).toBeGreaterThan(0)
    expect(screen.getByText('Proposed permission model')).toBeInTheDocument()
  })

  it('keeps certificate upload disabled until secure storage exists', () => {
    renderSettings()
    fireEvent.click(settingsNavigation().getByRole('link', { name: /TLS certificates/ }))

    expect(screen.getByRole('heading', { name: 'TLS certificates' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Choose certificate files' })).toBeDisabled()
  })
})
