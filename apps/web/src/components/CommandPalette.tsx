import * as Dialog from '@radix-ui/react-dialog'
import { BookOpen, Boxes, Bug, CornerDownLeft, FileUp, LayoutDashboard, MonitorCog, Search, Server, Settings, ShieldAlert, ShieldCheck, X } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { useEffect, useMemo, useRef, useState, type KeyboardEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api/client'
import { useAuth } from '../auth/useAuth'

interface CommandResult {
  id: string
  label: string
  detail: string
  path: string
  icon: LucideIcon
  keywords?: string
  group: 'Navigate' | 'Assets' | 'Applications' | 'Findings'
  adminOnly?: boolean
}

const commands: CommandResult[] = [
  { id: 'overview', label: 'Security Overview', detail: 'Review fleet posture and critical exposure', path: '/', icon: LayoutDashboard, keywords: 'overview home metrics', group: 'Navigate' },
  { id: 'assets', label: 'Asset Inventory', detail: 'Search reporting Linux systems', path: '/hosts', icon: Server, keywords: 'hosts servers assets', group: 'Navigate' },
  { id: 'applications', label: 'Application Inventory', detail: 'Correlate packages, services, versions, and hosts', path: '/applications', icon: Boxes, keywords: 'applications packages services software versions', group: 'Navigate' },
  { id: 'vulnerabilities', label: 'Vulnerabilities', detail: 'Prioritize CVEs, known exploitation, affected hosts, and fixes', path: '/vulnerabilities', icon: Bug, keywords: 'cve vulnerabilities osv kev cvss exploits patches fixes', group: 'Navigate' },
  { id: 'agents', label: 'Agents & Groups', detail: 'Manage agents, enrollment, and fleet groups', path: '/agents', icon: MonitorCog, keywords: 'agents groups endpoints enrollment', group: 'Navigate', adminOnly: true },
  { id: 'findings', label: 'Security Findings', detail: 'Triage findings by control category', path: '/findings', icon: ShieldAlert, keywords: 'findings risk vulnerabilities', group: 'Navigate' },
  { id: 'remediation', label: 'Remediation Review', detail: 'Review requested changes and approval history', path: '/findings?view=remediation', icon: ShieldCheck, keywords: 'remediation changes approvals review', group: 'Navigate' },
  { id: 'change-sets', label: 'Signed Change Sets', detail: 'Review readiness gates, canaries, and independent authorization', path: '/findings?view=change-sets', icon: ShieldCheck, keywords: 'remediation signed change sets canary authorization', group: 'Navigate' },
  { id: 'evidence', label: 'Evidence Intake', detail: 'Upload an offline evidence bundle', path: '/evidence', icon: FileUp, keywords: 'offline upload report evidence intake', group: 'Navigate' },
  { id: 'how-to', label: 'How To Use LSA', detail: 'Learn collection, investigation, and evidence workflows', path: '/how-to', icon: BookOpen, keywords: 'help guide getting started analyst secops agent offline ansible', group: 'Navigate' },
  { id: 'credentials', label: 'Administration · Credentials & Trust', detail: 'Manage ingestion tokens and signing keys', path: '/settings/credentials', icon: ShieldCheck, keywords: 'administration tokens signing keys credentials trust', group: 'Navigate', adminOnly: true },
  { id: 'certificates', label: 'Administration · TLS Certificates', detail: 'Review the console HTTPS identity', path: '/settings/certificates', icon: ShieldCheck, keywords: 'administration tls https certificate', group: 'Navigate', adminOnly: true },
  { id: 'administration', label: 'Administration', detail: 'Identity, trust, users, and access', path: '/settings', icon: Settings, keywords: 'settings admin users tokens', group: 'Navigate', adminOnly: true },
]

const groupOrder: CommandResult['group'][] = ['Navigate', 'Assets', 'Applications', 'Findings']

export function CommandPalette({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const { user } = useAuth()
  const [query, setQuery] = useState('')
  const [entities, setEntities] = useState<CommandResult[]>([])
  const [loading, setLoading] = useState(false)
  const [searchError, setSearchError] = useState('')
  const [activeIndex, setActiveIndex] = useState(0)
  const itemRefs = useRef(new Map<string, HTMLButtonElement>())
  const requestSequence = useRef(0)
  const navigate = useNavigate()
  const needle = query.toLowerCase().trim()
  const staticResults = useMemo(() => commands
    .filter((command) => !command.adminOnly || user?.role === 'admin')
    .filter((command) => !needle || `${command.label} ${command.detail} ${command.keywords}`.toLowerCase().includes(needle)), [needle, user?.role])
  const results = useMemo(() => [...staticResults, ...entities], [entities, staticResults])
  const activeResult = results[Math.min(activeIndex, Math.max(results.length - 1, 0))]

  useEffect(() => {
    if (!open) {
      setQuery('')
      setEntities([])
      setSearchError('')
      return
    }
    setActiveIndex(0)
  }, [open])

  useEffect(() => {
    setActiveIndex(0)
    if (!open || needle.length < 2) {
      setEntities([])
      setLoading(false)
      setSearchError('')
      return
    }
    const sequence = ++requestSequence.current
    const timer = window.setTimeout(async () => {
      setLoading(true)
      setSearchError('')
      try {
        const [hosts, applications, findings] = await Promise.all([
          api.hostPage({ search: needle, page: 0, pageSize: 4, sort: 'asset', direction: 'asc' }),
          api.applicationEstatePage({ search: needle, page: 0, pageSize: 4, sort: 'application', direction: 'asc' }),
          api.findingPage({ search: needle, page: 0, pageSize: 5, sort: 'severity', direction: 'asc' }),
        ])
        if (sequence !== requestSequence.current) return
        setEntities([
          ...hosts.rows.map((host): CommandResult => ({ id: `host:${host.id}`, label: host.hostname, detail: `${host.operating_system} ${host.os_version} · ${host.ip_addresses[0] ?? 'No Address Reported'}`, path: `/hosts?host=${encodeURIComponent(host.id)}`, icon: Server, group: 'Assets' })),
          ...applications.data.applications.map((application): CommandResult => ({ id: `application:${application.kind}:${application.source}:${application.name}`, label: application.name, detail: `${application.kind} · ${application.host_count} Host${application.host_count === 1 ? '' : 's'} · ${application.vulnerability_count} Advisories`, path: `/applications?search=${encodeURIComponent(application.name)}&application=${encodeURIComponent(`${application.kind}:${application.source}:${application.name}`)}`, icon: Boxes, group: 'Applications' })),
          ...findings.rows.map((finding): CommandResult => ({ id: `finding:${finding.id}`, label: finding.title, detail: `${finding.hostname} · ${finding.control_id} · ${finding.severity}`, path: `/findings?category=${encodeURIComponent(finding.category)}&finding=${encodeURIComponent(finding.id)}`, icon: ShieldAlert, group: 'Findings' })),
        ])
      } catch (reason) {
        if (sequence !== requestSequence.current) return
        setEntities([])
        setSearchError(reason instanceof Error ? reason.message : 'Entity Search Failed')
      } finally {
        if (sequence === requestSequence.current) setLoading(false)
      }
    }, 220)
    return () => { window.clearTimeout(timer); requestSequence.current += 1 }
  }, [needle, open])

  useEffect(() => {
    if (activeResult) itemRefs.current.get(activeResult.id)?.scrollIntoView?.({ block: 'nearest' })
  }, [activeResult])

  function select(result: CommandResult) {
    navigate(result.path)
    onOpenChange(false)
    setQuery('')
  }

  function handleKeyDown(event: KeyboardEvent<HTMLInputElement>) {
    if (!results.length) return
    if (event.key === 'ArrowDown') {
      event.preventDefault()
      setActiveIndex((index) => (index + 1) % results.length)
    } else if (event.key === 'ArrowUp') {
      event.preventDefault()
      setActiveIndex((index) => (index - 1 + results.length) % results.length)
    } else if (event.key === 'Home') {
      event.preventDefault()
      setActiveIndex(0)
    } else if (event.key === 'End') {
      event.preventDefault()
      setActiveIndex(results.length - 1)
    } else if (event.key === 'Enter' && activeResult) {
      event.preventDefault()
      select(activeResult)
    }
  }

  return <Dialog.Root open={open} onOpenChange={onOpenChange}>
    <Dialog.Portal>
      <Dialog.Overlay className="command-overlay" />
      <Dialog.Content className="command-palette" aria-describedby="command-palette-help">
        <Dialog.Title className="sr-only">Global Search</Dialog.Title>
        <div className="command-search"><Search size={18} /><input autoFocus role="combobox" aria-label="Global Search" aria-autocomplete="list" aria-expanded="true" aria-controls="command-results" aria-activedescendant={activeResult ? `command-${activeResult.id.replaceAll(':', '-')}` : undefined} value={query} onChange={(event) => setQuery(event.target.value)} onKeyDown={handleKeyDown} placeholder="Search assets, applications, findings, or destinations…" /><Dialog.Close className="command-close" aria-label="Close Search"><X size={16} /></Dialog.Close></div>
        <div id="command-results" className="command-results" role="listbox" aria-label="Search Results" aria-busy={loading}>
          {groupOrder.map((group) => {
            const grouped = results.filter((result) => result.group === group)
            if (!grouped.length) return null
            return <section key={group} aria-label={group}><p className="command-group-label">{group}</p>{grouped.map((result) => {
              const Icon = result.icon
              const index = results.indexOf(result)
              const active = index === activeIndex
              const itemId = `command-${result.id.replaceAll(':', '-')}`
              return <button id={itemId} key={result.id} ref={(node) => { if (node) itemRefs.current.set(result.id, node); else itemRefs.current.delete(result.id) }} role="option" aria-selected={active} className={active ? 'command-item command-item-active' : 'command-item'} onMouseMove={() => setActiveIndex(index)} onClick={() => select(result)}><span className="command-item-icon"><Icon size={16} /></span><span className="min-w-0 flex-1 text-left"><strong>{result.label}</strong><small>{result.detail}</small></span><CornerDownLeft className="command-enter" size={14} aria-hidden="true" /></button>
            })}</section>
          })}
          {loading && <div className="command-search-state"><span className="command-search-spinner" />Searching Console Entities</div>}
          {searchError && <div className="command-search-state command-search-error" role="status">Entity Search Unavailable · {searchError}</div>}
          {!loading && !searchError && !results.length && <div className="command-search-state">No Console Destination Or Entity Matches “{query}”.</div>}
        </div>
        <div id="command-palette-help" className="command-footer"><span><kbd>↑</kbd><kbd>↓</kbd> Navigate</span><span><kbd>↵</kbd> Open</span><span><kbd>esc</kbd> Close</span></div>
      </Dialog.Content>
    </Dialog.Portal>
  </Dialog.Root>
}
