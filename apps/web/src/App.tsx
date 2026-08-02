import { Navigate, Route, Routes } from 'react-router-dom'
import { useAuth } from './auth/useAuth'
import { AppShell } from './components/AppShell'
import { DashboardPage } from './pages/DashboardPage'
import { FindingsPage } from './pages/FindingsPage'
import { HostDetailPage } from './pages/HostDetailPage'
import { HostsPage } from './pages/HostsPage'
import { LoginPage } from './pages/LoginPage'
import { ReportsPage } from './pages/ReportsPage'
import { AuthenticationSettingsPage } from './pages/settings/AuthenticationSettingsPage'
import { CertificatesSettingsPage } from './pages/settings/CertificatesSettingsPage'
import { SettingsLayout } from './pages/settings/SettingsLayout'
import { SettingsOverviewPage } from './pages/settings/SettingsOverviewPage'
import { UsersSettingsPage } from './pages/settings/UsersSettingsPage'
import { AgentsSettingsPage } from './pages/settings/AgentsSettingsPage'
import { SigningKeysPage } from './pages/SigningKeysPage'
import { TokensPage } from './pages/TokensPage'

function ProtectedShell() {
  const { user } = useAuth()
  return user ? <AppShell /> : <Navigate to="/login" replace />
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route element={<ProtectedShell />}>
        <Route index element={<DashboardPage />} />
        <Route path="hosts" element={<HostsPage />} />
        <Route path="hosts/:hostId" element={<HostDetailPage />} />
        <Route path="findings" element={<FindingsPage />} />
        <Route path="reports" element={<ReportsPage />} />
        <Route path="agents" element={<AgentsSettingsPage />} />
        <Route path="settings" element={<SettingsLayout />}>
          <Route index element={<SettingsOverviewPage />} />
          <Route path="users" element={<UsersSettingsPage />} />
          <Route path="agents" element={<Navigate to="/agents" replace />} />
          <Route path="authentication" element={<AuthenticationSettingsPage />} />
          <Route path="tokens" element={<TokensPage />} />
          <Route path="signing-keys" element={<SigningKeysPage />} />
          <Route path="certificates" element={<CertificatesSettingsPage />} />
        </Route>
        <Route path="tokens" element={<Navigate to="/settings/tokens" replace />} />
        <Route path="signing-keys" element={<Navigate to="/settings/signing-keys" replace />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
