import { Plus, Server } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api } from '../api/client'
import { EnrollHostPanel } from '../components/EnrollHostPanel'
import { HostQuickView } from '../components/HostQuickView'
import { PageHeader } from '../components/PageHeader'
import { RiskScore } from '../components/security/RiskScore'
import { type SecurityColumn, SecurityTable } from '../components/security/SecurityTable'
import { StatusBadge } from '../components/security/StatusBadge'
import { EmptyState, ErrorState, LoadingState } from '../components/StatePanel'
import { Button } from '../components/ui/Button'
import { useApi } from '../hooks/useApi'
import { useSecurityTableUrlState } from '../hooks/useSecurityTableUrlState'
import { formatDateTime } from '../lib/dateTime'
import type { Host } from '../types'

function hostStatus(host: Host) {
  if (!host.last_scan_at) return { label: 'No Report', tone: 'offline' as const }
  const age = Date.now() - new Date(host.last_scan_at).getTime()
  if (age > 7 * 86_400_000) return { label: 'Stale', tone: 'warning' as const }
  return { label: 'Current', tone: 'online' as const }
}

export function HostsPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const requestedRisk = searchParams.get('risk')
  const initialRisk = requestedRisk === 'critical' || requestedRisk === 'healthy' || requestedRisk === 'stale' ? requestedRisk : 'all'
  const [risk, setRisk] = useState<'all' | 'critical' | 'healthy' | 'stale'>(initialRisk)
  const [enrolling, setEnrolling] = useState(false)
  const [selected, setSelected] = useState<Host | null>(null)
  const tableState = useSecurityTableUrlState({ clearOnSearch: ['host'] })
  const [serverSearch, setServerSearch] = useState(tableState.query)
  const facets = useApi(() => api.hostFacets(), [])
  const { data, error, loading, reload } = useApi(() => api.hostPage({
    search: serverSearch,
    risk: risk === 'all' ? undefined : risk,
    page: tableState.page,
    pageSize: 10,
    sort: tableState.sort?.id,
    direction: tableState.sort?.direction,
  }), [serverSearch, risk, tableState.page, tableState.sort?.id, tableState.sort?.direction])

  useEffect(() => {
    const timer = window.setTimeout(() => setServerSearch(tableState.query.trim()), 250)
    return () => window.clearTimeout(timer)
  }, [tableState.query])

  useEffect(() => {
    const nextRisk = requestedRisk === 'critical' || requestedRisk === 'healthy' || requestedRisk === 'stale' ? requestedRisk : 'all'
    setRisk(nextRisk)
  }, [requestedRisk])

  useEffect(() => {
    const hostId = searchParams.get('host')
    if (!hostId) return
    const requestedHost = data?.rows.find((host) => host.id === hostId)
    if (requestedHost) {
      if (selected?.id !== requestedHost.id) setSelected(requestedHost)
      return
    }
    if (selected?.id === hostId) return
    let active = true
    void api.host(hostId).then((host) => { if (active) setSelected(host) }).catch(() => undefined)
    return () => { active = false }
  }, [data?.rows, searchParams, selected?.id])

  function updateRisk(nextRisk: 'all' | 'critical' | 'healthy' | 'stale') {
    setRisk(nextRisk)
    setSelected(null)
    const next = new URLSearchParams(searchParams)
    if (nextRisk === 'all') next.delete('risk')
    else next.set('risk', nextRisk)
    next.delete('host')
    next.delete('page')
    setSearchParams(next, { replace: true })
  }

  function openHost(host: Host) {
    setSelected(host)
    const next = new URLSearchParams(searchParams)
    next.set('host', host.id)
    setSearchParams(next, { replace: true })
  }

  function closeHost() {
    setSelected(null)
    const next = new URLSearchParams(searchParams)
    next.delete('host')
    setSearchParams(next, { replace: true })
  }
  const hosts = data?.rows ?? []

  const columns: SecurityColumn<Host>[] = [
    { id: 'asset', header: 'Asset', priority: 'primary', hideable: false, sortValue: (host) => host.hostname, exportValue: (host) => host.hostname, cell: (host) => <button className="asset-identity" aria-label={host.hostname} onClick={() => openHost(host)}><span className="asset-icon"><Server size={16} /></span><span><strong>{host.hostname}</strong><small>{host.fqdn ?? host.ip_addresses[0] ?? 'No address reported'}</small></span></button> },
    { id: 'status', header: 'Posture Freshness', priority: 'secondary', sortValue: (host) => hostStatus(host).label, exportValue: (host) => hostStatus(host).label, cell: (host) => { const status = hostStatus(host); return <StatusBadge label={status.label} tone={status.tone} /> } },
    { id: 'os', header: 'Operating system', priority: 'detail', sortValue: (host) => `${host.operating_system} ${host.os_version}`, exportValue: (host) => `${host.operating_system} ${host.os_version}`, cell: (host) => <span className="table-primary">{host.operating_system} {host.os_version}<small>Kernel {host.kernel}</small></span> },
    { id: 'environment', header: 'Environment', priority: 'detail', sortValue: (host) => host.tags.environment ?? '', exportValue: (host) => host.tags.environment ?? '', cell: (host) => <span className="table-primary capitalize">{host.tags.environment ?? 'Unassigned'}<small>{host.tags.owner ?? 'No owner'}</small></span> },
    { id: 'risk', header: 'Security score', priority: 'secondary', sortValue: (host) => host.security_score ?? -1, exportValue: (host) => host.security_score, cell: (host) => <div className="flex items-center gap-3"><RiskScore value={host.security_score ?? 0} label="posture" size="sm" /><span className="table-primary"><strong className="font-mono">{host.security_score?.toFixed(1) ?? '—'}</strong><small>Security posture</small></span></div> },
    { id: 'findings', header: 'Open exposure', priority: 'detail', sortValue: (host) => host.finding_counts.critical * 1000 + host.finding_counts.high, exportValue: (host) => `${host.finding_counts.critical} critical; ${host.finding_counts.high} high`, cell: (host) => <span className="table-primary"><span className={host.finding_counts.critical ? 'text-rose-700' : 'text-stone-700'}>{host.finding_counts.critical} critical</span><small>{host.finding_counts.high} high · {host.finding_counts.medium} medium</small></span> },
    { id: 'last_seen', header: 'Last seen', priority: 'detail', sortValue: (host) => host.last_scan_at ?? '', exportValue: (host) => host.last_scan_at, cell: (host) => <span className="font-mono text-[10px] text-stone-600">{formatDateTime(host.last_scan_at)}</span> },
  ]

  return <div className="page-reveal">
    <PageHeader eyebrow="Asset management" title="Linux assets" detail="Inventory, sensor health, exposure, and the latest accepted posture for every reporting endpoint." action={facets.data?.total ? <Button variant="primary" onClick={() => setEnrolling(true)}><Plus size={15} />Enroll asset</Button> : undefined} />
    {(loading && !data) || (facets.loading && !facets.data) ? <LoadingState variant="table" /> : error || facets.error ? <ErrorState message={error ?? facets.error ?? 'Unable To Load Assets'} retry={() => { void reload(); void facets.reload() }} /> : facets.data?.total === 0 ? <EmptyState title="No assets registered" detail="An asset appears automatically when its first authenticated report or agent check-in is accepted." action={<Button variant="primary" onClick={() => setEnrolling(true)}><Plus size={15} />Enroll First Asset</Button>} /> : <section className="soc-panel overflow-hidden">
      <div className="asset-filter-row"><div className="filter-tabs" role="group" aria-label="Asset risk filter">{(['all', 'critical', 'healthy', 'stale'] as const).map((value) => <button key={value} className={risk === value ? 'active' : ''} onClick={() => updateRisk(value)}>{value === 'all' ? 'All Assets' : value === 'critical' ? 'Critical Exposure' : value === 'healthy' ? 'Healthy' : 'Stale Posture'}<span>{value === 'all' ? facets.data?.total ?? 0 : value === 'critical' ? facets.data?.critical ?? 0 : value === 'healthy' ? facets.data?.healthy ?? 0 : facets.data?.stale ?? 0}</span></button>)}</div></div>
      <SecurityTable rows={hosts} columns={columns} query={tableState.query} onQueryChange={(value) => { setSelected(null); tableState.setQuery(value) }} sort={tableState.sort} onSortChange={tableState.setSort} searchText={(host) => `${host.hostname} ${host.fqdn ?? ''} ${host.ip_addresses.join(' ')} ${host.operating_system} ${host.tags.environment ?? ''}`} searchPlaceholder="Search hostname, IP, OS, or environment" filename="lsa-assets.csv" emptyTitle="No assets match this view" embedded serverPagination={{ page: data?.page ?? tableState.page, pageSize: data?.pageSize ?? 10, totalRows: data?.total ?? 0, onPageChange: tableState.setPage }} />
      {loading && <p className="px-5 py-2 text-xs text-stone-500" role="status">Updating Assets…</p>}
    </section>}
    {enrolling && <EnrollHostPanel close={() => setEnrolling(false)} created={() => { void reload(); void facets.reload() }} />}
    {selected && <HostQuickView key={selected.id} host={selected} close={closeHost} deleted={() => { closeHost(); void reload(); void facets.reload() }} />}
  </div>
}
