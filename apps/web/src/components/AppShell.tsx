import * as DropdownMenu from '@radix-ui/react-dropdown-menu'
import {
  Bell, Building2, ChevronDown, ChevronLeft, ChevronRight, CircleHelp, FileBarChart, FileKey2,
  Gauge, LogOut, Menu, MonitorCog, Plus, Search, Server, Settings, ShieldAlert, ShieldCheck, SlidersHorizontal,
} from 'lucide-react'
import { Suspense, useEffect, useState } from 'react'
import { Link, Outlet, useLocation } from 'react-router-dom'
import { useAuth } from '../auth/useAuth'
import { cn } from '../lib/utils'
import { BrandMark } from './BrandMark'
import { CommandPalette } from './CommandPalette'
import { StatusBadge } from './security/StatusBadge'
import { Button } from './ui/Button'
import { Tooltip, TooltipProvider } from './ui/Tooltip'

interface NavigationItem { to: string; label: string; icon: typeof Gauge; end?: boolean; adminOnly?: boolean }
interface NavigationGroup { label: string; items: NavigationItem[] }

const navigation: NavigationGroup[] = [
  { label: 'Operations', items: [
    { to: '/', label: 'Dashboard', icon: Gauge, end: true },
    { to: '/hosts', label: 'Assets', icon: Server },
    { to: '/agents', label: 'Endpoints', icon: MonitorCog, adminOnly: true },
  ] },
  { label: 'Exposure management', items: [
    { to: '/findings', label: 'Vulnerabilities', icon: ShieldAlert },
    { to: '/settings/certificates', label: 'Certificates', icon: ShieldCheck, adminOnly: true },
    { to: '/policies', label: 'Policies', icon: SlidersHorizontal, adminOnly: true },
  ] },
  { label: 'Intelligence', items: [
    { to: '/reports', label: 'Reports', icon: FileBarChart },
  ] },
  { label: 'Platform', items: [
    { to: '/settings', label: 'Administration', icon: Settings, adminOnly: true },
  ] },
]

export function AppShell() {
  const { user, logout } = useAuth()
  const location = useLocation()
  const [collapsed, setCollapsed] = useState(false)
  const [commandOpen, setCommandOpen] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)
  const visibleNavigation = navigation.map((group) => ({ ...group, items: group.items.filter((item) => !item.adminOnly || user?.role === 'admin') })).filter((group) => group.items.length)
  const flatNavigation = visibleNavigation.flatMap((group) => group.items)
  const current = [...flatNavigation].reverse().find((item) => item.to === '/' ? location.pathname === '/' : location.pathname.startsWith(item.to))
  const initials = (user?.name || user?.email || 'LSA').split(/\s+|@/).filter(Boolean).slice(0, 2).map((part) => part[0]).join('').toUpperCase()

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); setCommandOpen((value) => !value) }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [])

  useEffect(() => setMobileOpen(false), [location.pathname])

  const navigationMarkup = <nav className="soc-navigation" aria-label="Primary navigation">
    {visibleNavigation.map((group) => <div key={group.label} className="soc-nav-group">
      {!collapsed && <p className="soc-nav-label">{group.label}</p>}
      {group.items.map(({ to, label, icon: Icon, end }) => { const isActive = end ? location.pathname === to : location.pathname.startsWith(to); return <Tooltip key={`${label}-${to}`} content={label} side="right">
        <Link to={to} aria-current={isActive ? 'page' : undefined} aria-label={collapsed ? label : undefined} className={cn('soc-nav-item', isActive && 'soc-nav-item-active', collapsed && 'soc-nav-item-collapsed')}>
          <Icon size={17} strokeWidth={1.8} /><span>{label}</span>{!collapsed && <ChevronRight className="nav-caret" size={13} />}
        </Link>
      </Tooltip> })}
    </div>)}
  </nav>

  return <TooltipProvider>
    <div className="min-h-[100dvh] text-slate-100">
      <a href="#main-content" className="skip-link">Skip to content</a>
      <aside className={cn('soc-sidebar hidden lg:flex', collapsed && 'soc-sidebar-collapsed')}>
        <div className="soc-logo-row"><BrandMark compact={collapsed} />{!collapsed && <span className="soc-edition">ENTERPRISE</span>}</div>
        {navigationMarkup}
        <div className="mt-auto space-y-2">
          {!collapsed && <div className="soc-sensor-state"><StatusBadge label="Platform operational" tone="online" pulse /><span>v0.4</span></div>}
          <div className={cn('soc-user-card', collapsed && 'soc-user-card-collapsed')}>
            <span className="soc-avatar">{initials}</span>{!collapsed && <span className="min-w-0 flex-1"><strong>{user?.name}</strong><small>{user?.role}</small></span>}
            {!collapsed && <button onClick={logout} aria-label="Sign out"><LogOut size={15} /></button>}
          </div>
        </div>
        <button className="sidebar-collapse" onClick={() => setCollapsed((value) => !value)} aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}>{collapsed ? <ChevronRight size={14} /> : <ChevronLeft size={14} />}</button>
      </aside>

      {mobileOpen && <button className="mobile-sidebar-backdrop lg:hidden" aria-label="Close navigation" onClick={() => setMobileOpen(false)} />}
      <aside aria-hidden={!mobileOpen} className={cn('mobile-sidebar lg:hidden', mobileOpen && 'mobile-sidebar-open')}><div className="soc-logo-row"><BrandMark /></div>{navigationMarkup}</aside>

      <div className={cn('soc-workspace', collapsed && 'soc-workspace-expanded')}>
        <header className="soc-topbar">
          <button className="soc-icon-button lg:hidden" onClick={() => setMobileOpen(true)} aria-label="Open navigation"><Menu size={18} /></button>
          <div className="soc-breadcrumbs"><span>LSA</span><ChevronRight size={12} /><strong>{current?.label ?? 'Console'}</strong></div>
          <button className="global-search-trigger" onClick={() => setCommandOpen(true)}><Search size={15} /><span>Search the console</span><kbd>⌘ K</kbd></button>
          <div className="soc-topbar-actions">
            <DropdownMenu.Root>
              <DropdownMenu.Trigger asChild><Button className="environment-trigger" size="sm"><Building2 size={14} /><span className="hidden sm:inline">Production</span><ChevronDown size={12} /></Button></DropdownMenu.Trigger>
              <DropdownMenu.Portal><DropdownMenu.Content align="end" className="soc-menu-content"><DropdownMenu.Label className="soc-menu-label">Environment</DropdownMenu.Label><DropdownMenu.Item className="soc-menu-item"><span className="soc-menu-check">✓</span>Production</DropdownMenu.Item></DropdownMenu.Content></DropdownMenu.Portal>
            </DropdownMenu.Root>
            <DropdownMenu.Root>
              <DropdownMenu.Trigger asChild><Button variant="primary" size="sm" className="hidden md:inline-flex"><Plus size={14} />Quick action<ChevronDown size={12} /></Button></DropdownMenu.Trigger>
              <DropdownMenu.Portal><DropdownMenu.Content align="end" className="soc-menu-content"><DropdownMenu.Item asChild className="soc-menu-item"><Link to="/reports"><FileBarChart size={14} />Import evidence report</Link></DropdownMenu.Item><DropdownMenu.Item asChild className="soc-menu-item"><Link to="/settings/tokens"><FileKey2 size={14} />Create ingestion token</Link></DropdownMenu.Item></DropdownMenu.Content></DropdownMenu.Portal>
            </DropdownMenu.Root>
            <button className="soc-icon-button" aria-label="Help"><CircleHelp size={17} /></button>
            <button className="soc-icon-button notification-button" aria-label="Notifications"><Bell size={17} /><span /></button>
            <DropdownMenu.Root>
              <DropdownMenu.Trigger className="soc-avatar soc-avatar-button" aria-label="User menu">{initials}</DropdownMenu.Trigger>
              <DropdownMenu.Portal><DropdownMenu.Content align="end" className="soc-menu-content"><DropdownMenu.Label className="soc-profile-label"><strong>{user?.name}</strong><span>{user?.email}</span></DropdownMenu.Label><DropdownMenu.Separator className="soc-menu-separator" /><DropdownMenu.Item className="soc-menu-item" onSelect={logout}><LogOut size={14} />Sign out</DropdownMenu.Item></DropdownMenu.Content></DropdownMenu.Portal>
            </DropdownMenu.Root>
          </div>
        </header>
        <main id="main-content" className="soc-main"><Suspense fallback={<div className="route-loading route-loading-contained" aria-label="Loading console view"><span /><span /><span /></div>}><Outlet /></Suspense></main>
      </div>
      <CommandPalette open={commandOpen} onOpenChange={setCommandOpen} />
    </div>
  </TooltipProvider>
}
