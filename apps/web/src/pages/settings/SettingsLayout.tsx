import {
  Certificate,
  Fingerprint,
  GearSix,
  Key,
  LockKey,
  UsersThree,
  DesktopTower,
} from '@phosphor-icons/react'
import { NavLink, Outlet } from 'react-router-dom'
import { useAuth } from '../../auth/useAuth'
import { ErrorState } from '../../components/StatePanel'

const sections = [
  { to: '/settings', label: 'Overview', detail: 'Platform configuration', icon: GearSix, end: true },
  { to: '/settings/users', label: 'Users & access', detail: 'Roles and permissions', icon: UsersThree },
  { to: '/settings/agents', label: 'Agents & policies', detail: 'Groups and audit scope', icon: DesktopTower },
  { to: '/settings/authentication', label: 'Authentication', detail: 'SSO and RADIUS', icon: LockKey },
  { to: '/settings/tokens', label: 'Tokens', detail: 'Scanner credentials', icon: Key },
  { to: '/settings/signing-keys', label: 'Signing keys', detail: 'Evidence trust', icon: Fingerprint },
  { to: '/settings/certificates', label: 'TLS certificates', detail: 'HTTPS identity', icon: Certificate },
]

export function SettingsLayout() {
  const { user } = useAuth()
  if (user?.role !== 'admin') return <ErrorState message="Administrator role required" retry={() => window.location.assign('/')} />

  return (
    <div className="grid gap-8 lg:grid-cols-[230px_minmax(0,1fr)] lg:gap-10">
      <aside className="lg:sticky lg:top-24 lg:self-start">
        <div className="mb-4 px-2">
          <p className="section-label">Administration</p>
          <p className="mt-2 text-xs leading-5 text-stone-600">Identity, trust, and platform policy.</p>
        </div>
        <nav className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-1" aria-label="Settings sections">
          {sections.map(({ to, label, detail, icon: Icon, end }) => (
            <NavLink key={to} to={to} end={end} className={({ isActive }) => `settings-nav-item ${isActive ? 'settings-nav-item-active' : ''}`}>
              <Icon size={17} weight="duotone" />
              <span className="min-w-0"><strong>{label}</strong><small>{detail}</small></span>
            </NavLink>
          ))}
        </nav>
      </aside>
      <section className="min-w-0"><Outlet /></section>
    </div>
  )
}
