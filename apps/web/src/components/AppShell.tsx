import {
  Bell,
  ChartDonut,
  GearSix,
  HardDrives,
  ListMagnifyingGlass,
  SignOut,
  UploadSimple,
  DesktopTower,
  CaretRight,
  Pulse,
} from '@phosphor-icons/react'
import { NavLink, Outlet, useLocation } from 'react-router-dom'
import { useAuth } from '../auth/useAuth'
import { BrandMark } from './BrandMark'

const navigation = [
  { to: '/', label: 'Overview', icon: ChartDonut, end: true, adminOnly: false },
  { to: '/hosts', label: 'Hosts', icon: HardDrives, adminOnly: false },
  { to: '/findings', label: 'Findings', icon: ListMagnifyingGlass, adminOnly: false },
  { to: '/reports', label: 'Reports', icon: UploadSimple, adminOnly: false },
  { to: '/agents', label: 'Agents', icon: DesktopTower, adminOnly: true },
  { to: '/settings', label: 'Settings', icon: GearSix, adminOnly: true },
]

export function AppShell() {
  const { user, logout } = useAuth()
  const location = useLocation()
  const visibleNavigation = navigation.filter((item) => !item.adminOnly || user?.role === 'admin')
  const current = [...navigation].reverse().find((item) => item.to === '/' ? location.pathname === '/' : location.pathname.startsWith(item.to))
  const initials = (user?.name || user?.email || 'LSA').split(/\s+|@/).filter(Boolean).slice(0, 2).map((part) => part[0]).join('').toUpperCase()
  return (
    <div className="min-h-[100dvh] text-stone-100">
      <a href="#main-content" className="skip-link">Skip to content</a>
      <aside className="app-sidebar fixed inset-y-0 left-0 z-30 hidden w-[256px] flex-col border-r border-white/[.06] p-5 lg:flex">
        <BrandMark />
        <div className="mt-11 px-3"><p className="section-label">Workspace</p></div>
        <nav className="mt-3 space-y-1" aria-label="Primary navigation">
          {visibleNavigation.map(({ to, label, icon: Icon, end }) => (
            <NavLink key={to} to={to} end={end} className={({ isActive }) => `nav-item ${isActive ? 'nav-item-active' : ''}`}>
              <Icon size={18} weight="duotone" />
              <span className="flex-1">{label}</span>
              <CaretRight size={12} className="opacity-30" />
            </NavLink>
          ))}
        </nav>
        <div className="mt-auto space-y-3">
          <div className="flex items-center gap-3 border-y border-white/[.06] py-4 text-[11px] text-stone-500"><span className="status-pulse" /><span className="flex-1">Platform operational</span><Pulse size={15} /></div>
          <div className="user-card">
            <div className="flex items-center gap-3">
              <div className="grid size-8 shrink-0 place-items-center rounded-[9px] border border-emerald-800/40 bg-emerald-950/30 text-[10px] font-semibold text-emerald-200">{initials}</div>
              <div className="min-w-0 flex-1"><p className="truncate text-xs font-medium text-stone-300">{user?.name}</p><p className="mt-1 truncate font-mono text-[9px] text-stone-600">{user?.role}</p></div>
              <button className="grid size-8 place-items-center rounded-lg text-stone-600 transition hover:bg-white/[.04] hover:text-stone-200" onClick={logout} aria-label="Sign out"><SignOut size={15} /></button>
            </div>
          </div>
        </div>
      </aside>

      <div className="lg:pl-[256px]">
        <header className="app-topbar sticky top-0 z-20 flex h-[70px] items-center justify-between border-b border-white/[.06] px-4 backdrop-blur-xl md:px-8 lg:px-10">
          <div className="lg:hidden"><BrandMark compact /></div>
          <div className="topbar-context hidden lg:flex">
            <span>LSA</span><CaretRight size={11} /><strong>{current?.label ?? 'Console'}</strong>
          </div>
          <div className="flex items-center gap-2">
            <button className="icon-button" aria-label="Notifications"><Bell size={18} /></button>
            <div className="grid size-9 place-items-center rounded-[10px] border border-emerald-800/30 bg-emerald-950/30 text-[10px] font-semibold text-emerald-200">{initials}</div>
          </div>
        </header>

        <main id="main-content" className="mx-auto max-w-[1500px] px-4 pb-24 pt-8 md:px-8 lg:px-10 lg:pb-14 lg:pt-10">
          <Outlet />
        </main>

        <nav className="fixed inset-x-0 bottom-0 z-20 flex justify-around border-t border-white/[.08] bg-[#0c100d]/95 px-2 py-2 backdrop-blur-xl lg:hidden" aria-label="Mobile navigation">
          {visibleNavigation.map(({ to, label, icon: Icon, end }) => (
            <NavLink key={to} to={to} end={end} className={({ isActive }) => `mobile-nav ${isActive ? 'text-emerald-300' : 'text-stone-600'}`}>
              <Icon size={19} weight="duotone" /><span>{label}</span>
            </NavLink>
          ))}
        </nav>
      </div>
    </div>
  )
}
