import { Cpu, Network, Plus, Server, ShieldAlert } from 'lucide-react'
import { useState } from 'react'
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
import type { Host } from '../types'

function hostStatus(host: Host) {
  if (!host.last_scan_at) return { label: 'Never seen', tone: 'offline' as const }
  const age = Date.now() - new Date(host.last_scan_at).getTime()
  if (age > 86_400_000) return { label: 'Stale', tone: 'warning' as const }
  return { label: 'Online', tone: 'online' as const }
}

export function HostsPage() {
  const [risk, setRisk] = useState<'all' | 'critical' | 'healthy' | 'stale'>('all')
  const [enrolling, setEnrolling] = useState(false)
  const [selected, setSelected] = useState<Host | null>(null)
  const { data, error, loading, reload } = useApi(() => api.hosts(), [])
  const hosts = data?.filter((host) => {
    if (risk === 'critical') return host.finding_counts.critical > 0
    if (risk === 'healthy') return host.finding_counts.critical === 0 && (host.security_score ?? 0) >= 80
    if (risk === 'stale') return hostStatus(host).tone !== 'online'
    return true
  }) ?? []

  const columns: SecurityColumn<Host>[] = [
    { id: 'asset', header: 'Asset', hideable: false, sortValue: (host) => host.hostname, exportValue: (host) => host.hostname, cell: (host) => <button className="asset-identity" aria-label={host.hostname} onClick={() => setSelected(host)}><span className="asset-icon"><Server size={16} /></span><span><strong>{host.hostname}</strong><small>{host.fqdn ?? host.ip_addresses[0] ?? 'No address reported'}</small></span></button> },
    { id: 'status', header: 'Sensor status', sortValue: (host) => hostStatus(host).label, exportValue: (host) => hostStatus(host).label, cell: (host) => { const status = hostStatus(host); return <StatusBadge label={status.label} tone={status.tone} pulse={status.tone === 'online'} /> } },
    { id: 'os', header: 'Operating system', sortValue: (host) => `${host.operating_system} ${host.os_version}`, exportValue: (host) => `${host.operating_system} ${host.os_version}`, cell: (host) => <span className="table-primary">{host.operating_system} {host.os_version}<small>Kernel {host.kernel}</small></span> },
    { id: 'environment', header: 'Environment', sortValue: (host) => host.tags.environment ?? '', exportValue: (host) => host.tags.environment ?? '', cell: (host) => <span className="table-primary capitalize">{host.tags.environment ?? 'Unassigned'}<small>{host.tags.owner ?? 'No owner'}</small></span> },
    { id: 'risk', header: 'Security score', sortValue: (host) => host.security_score ?? -1, exportValue: (host) => host.security_score, cell: (host) => <div className="flex items-center gap-3"><RiskScore value={host.security_score ?? 0} label="posture" size="sm" /><span className="table-primary"><strong className="font-mono">{host.security_score?.toFixed(1) ?? '—'}</strong><small>Security posture</small></span></div> },
    { id: 'findings', header: 'Open exposure', sortValue: (host) => host.finding_counts.critical * 1000 + host.finding_counts.high, exportValue: (host) => `${host.finding_counts.critical} critical; ${host.finding_counts.high} high`, cell: (host) => <span className="table-primary"><span className={host.finding_counts.critical ? 'text-rose-400' : 'text-slate-300'}>{host.finding_counts.critical} critical</span><small>{host.finding_counts.high} high · {host.finding_counts.medium} medium</small></span> },
    { id: 'last_seen', header: 'Last seen', sortValue: (host) => host.last_scan_at ?? '', exportValue: (host) => host.last_scan_at, cell: (host) => <span className="font-mono text-[10px] text-slate-400">{host.last_scan_at ? new Date(host.last_scan_at).toLocaleString() : 'Never'}</span> },
  ]

  return <div className="page-reveal">
    <PageHeader eyebrow="Asset management" title="Linux assets" detail="Inventory, sensor health, exposure, and the latest accepted posture for every reporting endpoint." action={<Button variant="primary" onClick={() => setEnrolling(true)}><Plus size={15} />Enroll asset</Button>} />
    {loading ? <LoadingState /> : error ? <ErrorState message={error} retry={reload} /> : !data?.length ? <EmptyState title="No assets registered" detail="An asset appears automatically when its first authenticated report or agent check-in is accepted." /> : <section className="soc-panel overflow-hidden">
      <div className="asset-filter-row"><div className="filter-tabs" role="group" aria-label="Asset risk filter">{(['all', 'critical', 'healthy', 'stale'] as const).map((value) => <button key={value} className={risk === value ? 'active' : ''} onClick={() => setRisk(value)}>{value === 'all' ? 'All assets' : value === 'critical' ? 'Critical exposure' : value === 'healthy' ? 'Healthy' : 'Stale sensors'}<span>{value === 'all' ? data.length : value === 'critical' ? data.filter((host) => host.finding_counts.critical > 0).length : value === 'healthy' ? data.filter((host) => host.finding_counts.critical === 0 && (host.security_score ?? 0) >= 80).length : data.filter((host) => hostStatus(host).tone !== 'online').length}</span></button>)}</div></div>
      <SecurityTable rows={hosts} columns={columns} searchText={(host) => `${host.hostname} ${host.fqdn ?? ''} ${host.ip_addresses.join(' ')} ${host.operating_system} ${host.tags.environment ?? ''}`} searchPlaceholder="Search hostname, IP, OS, or environment" filename="lsa-assets.csv" emptyTitle="No assets match this view" renderExpanded={(host) => <div className="asset-expanded"><div><Network size={15} /><span><small>Network identity</small><strong>{host.ip_addresses.join(', ') || 'No address reported'}</strong></span></div><div><Cpu size={15} /><span><small>Platform</small><strong>{String(host.system_info?.cpu_model ?? host.architecture)}</strong></span></div><div><ShieldAlert size={15} /><span><small>Compliance</small><strong>{host.compliance_score?.toFixed(1) ?? '—'}%</strong></span></div><Button size="sm" onClick={() => setSelected(host)}>Open asset details</Button></div>} />
    </section>}
    {enrolling && <EnrollHostPanel close={() => setEnrolling(false)} created={() => void reload()} />}
    {selected && <HostQuickView key={selected.id} host={selected} close={() => setSelected(null)} deleted={() => { setSelected(null); void reload() }} />}
  </div>
}
