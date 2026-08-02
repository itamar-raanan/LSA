import {
  Bell,
  ChartDonut,
  HardDrives,
  ListMagnifyingGlass,
  SignOut,
  UploadSimple,
} from '@phosphor-icons/react'
import { NavLink, Outlet } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext'
import { BrandMark } from './BrandMark'

const navigation = [
  { to: '/', label: 'Overview', icon: ChartDonut, end: true },
  { to: '/hosts', label: 'Hosts', icon: HardDrives },
  { to: '/findings', label: 'Findings', icon: ListMagnifyingGlass },
  { to: '/reports', label: 'Reports', icon: UploadSimple },
]

export function AppShell() {
  const { user, logout } = useAuth()
  return (
    <div className="min-h-[100dvh] bg-[#111512] text-stone-100">
      <aside className="fixed inset-y-0 left-0 hidden w-[252px] flex-col border-r border-stone-800/80 bg-[#111512] p-5 lg:flex">
        <BrandMark />
        <nav className="mt-12 space-y-1" aria-label="Primary navigation">
          {navigation.map(({ to, label, icon: Icon, end }) => (
            <NavLink key={to} to={to} end={end} className={({ isActive }) => `nav-item ${isActive ? 'nav-item-active' : ''}`}>
              <Icon size={18} weight="duotone" />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="mt-auto border-t border-stone-800 pt-5">
          <p className="truncate text-xs font-medium text-stone-300">{user?.name}</p>
          <p className="mt-1 truncate font-mono text-[10px] text-stone-600">{user?.email}</p>
          <button className="mt-4 flex items-center gap-2 text-xs text-stone-500 transition hover:text-stone-200" onClick={logout}>
            <SignOut size={16} /> Sign out
          </button>
        </div>
      </aside>

      <div className="lg:pl-[252px]">
        <header className="sticky top-0 z-20 flex h-16 items-center justify-between border-b border-stone-800/80 bg-[#111512]/90 px-4 backdrop-blur-xl md:px-8 lg:px-10">
          <div className="lg:hidden"><BrandMark compact /></div>
          <div className="hidden items-center gap-2 font-mono text-[10px] uppercase tracking-[0.16em] text-stone-500 lg:flex">
            <span className="status-pulse" /> Platform operational
          </div>
          <div className="flex items-center gap-2">
            <button className="icon-button" aria-label="Notifications"><Bell size={18} /></button>
            <div className="grid size-8 place-items-center rounded-full bg-emerald-900/50 text-[11px] font-semibold text-emerald-200">SA</div>
          </div>
        </header>

        <main className="mx-auto max-w-[1480px] px-4 pb-24 pt-7 md:px-8 lg:px-10 lg:pb-12">
          <Outlet />
        </main>

        <nav className="fixed inset-x-0 bottom-0 z-20 grid grid-cols-4 border-t border-stone-800 bg-[#111512]/95 px-2 py-2 backdrop-blur-xl lg:hidden" aria-label="Mobile navigation">
          {navigation.map(({ to, label, icon: Icon, end }) => (
            <NavLink key={to} to={to} end={end} className={({ isActive }) => `mobile-nav ${isActive ? 'text-emerald-300' : 'text-stone-600'}`}>
              <Icon size={19} weight="duotone" /><span>{label}</span>
            </NavLink>
          ))}
        </nav>
      </div>
    </div>
  )
}

