import { lazy } from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'
import { useAuth } from './auth/useAuth'
import { AppShell } from './components/AppShell'
import { DashboardPage } from './pages/DashboardPage'
import { LoginPage } from './pages/LoginPage'

const FindingsPage = lazy(() => import('./pages/FindingsPage').then((module) => ({ default: module.FindingsPage })))
const HostDetailPage = lazy(() => import('./pages/HostDetailPage').then((module) => ({ default: module.HostDetailPage })))
const HostsPage = lazy(() => import('./pages/HostsPage').then((module) => ({ default: module.HostsPage })))
const EvidenceIntakePage = lazy(() => import('./pages/ReportsPage').then((module) => ({ default: module.ReportsPage })))
const ApplicationsPage = lazy(() => import('./pages/ApplicationsPage').then((module) => ({ default: module.ApplicationsPage })))
const HowToPage = lazy(() => import('./pages/HowToPage').then((module) => ({ default: module.HowToPage })))
const NotFoundPage = lazy(() => import('./pages/NotFoundPage').then((module) => ({ default: module.NotFoundPage })))
const AuthenticationSettingsPage = lazy(() => import('./pages/settings/AuthenticationSettingsPage').then((module) => ({ default: module.AuthenticationSettingsPage })))
const CertificatesSettingsPage = lazy(() => import('./pages/settings/CertificatesSettingsPage').then((module) => ({ default: module.CertificatesSettingsPage })))
const SettingsLayout = lazy(() => import('./pages/settings/SettingsLayout').then((module) => ({ default: module.SettingsLayout })))
const UsersSettingsPage = lazy(() => import('./pages/settings/UsersSettingsPage').then((module) => ({ default: module.UsersSettingsPage })))
const AgentsSettingsPage = lazy(() => import('./pages/settings/AgentsSettingsPage').then((module) => ({ default: module.AgentsSettingsPage })))
const CredentialsTrustPage = lazy(() => import('./pages/settings/CredentialsTrustPage').then((module) => ({ default: module.CredentialsTrustPage })))

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
        <Route path="applications" element={<ApplicationsPage />} />
        <Route path="findings" element={<FindingsPage />} />
        <Route path="evidence" element={<EvidenceIntakePage />} />
        <Route path="how-to" element={<HowToPage />} />
        <Route path="reports" element={<Navigate to="/evidence" replace />} />
        <Route path="agents" element={<AgentsSettingsPage />} />
        <Route path="policies" element={<Navigate to="/agents" replace />} />
        <Route path="settings" element={<SettingsLayout />}>
          <Route index element={<Navigate to="users" replace />} />
          <Route path="users" element={<UsersSettingsPage />} />
          <Route path="agents" element={<Navigate to="/agents" replace />} />
          <Route path="authentication" element={<AuthenticationSettingsPage />} />
          <Route path="credentials" element={<CredentialsTrustPage />} />
          <Route path="tokens" element={<Navigate to="/settings/credentials?view=tokens" replace />} />
          <Route path="signing-keys" element={<Navigate to="/settings/credentials?view=signing-keys" replace />} />
          <Route path="certificates" element={<CertificatesSettingsPage />} />
        </Route>
        <Route path="tokens" element={<Navigate to="/settings/credentials?view=tokens" replace />} />
        <Route path="signing-keys" element={<Navigate to="/settings/credentials?view=signing-keys" replace />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  )
}
