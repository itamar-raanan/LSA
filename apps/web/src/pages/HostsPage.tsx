import { DesktopTower, MagnifyingGlass, Plus } from '@phosphor-icons/react'
import { useState } from 'react'
import { api } from '../api/client'
import { PageHeader } from '../components/PageHeader'
import { EnrollHostPanel } from '../components/EnrollHostPanel'
import { EmptyState, ErrorState, LoadingState } from '../components/StatePanel'
import { useApi } from '../hooks/useApi'
import { HostQuickView } from '../components/HostQuickView'
import type { Host } from '../types'

export function HostsPage() {
  const [search, setSearch] = useState('')
  const [risk, setRisk] = useState<'all' | 'critical' | 'healthy'>('all')
  const [enrolling, setEnrolling] = useState(false)
  const [selected, setSelected] = useState<Host | null>(null)
  const { data, error, loading, reload } = useApi(() => api.hosts(), [])
  const hosts = data?.filter((host) => {
    const matchesSearch = host.hostname.toLowerCase().includes(search.toLowerCase())
    const matchesRisk = risk === 'all' || (risk === 'critical' ? host.finding_counts.critical > 0 : host.finding_counts.critical === 0 && (host.security_score ?? 0) >= 80)
    return matchesSearch && matchesRisk
  }) ?? []
  function score(value: number | null) {
    return <div className="score-cell"><span className="score-value">{value?.toFixed(1) ?? '—'}</span><span className="score-track"><span style={{ transform: `scaleX(${(value ?? 0) / 100})` }} /></span></div>
  }
  return (
    <div className="page-reveal">
      <PageHeader eyebrow="Asset inventory" title="Linux hosts" detail="Persistent identities and the most recent accepted posture for every reporting server." action={<button className="button-primary" onClick={() => setEnrolling(true)}><Plus size={16} /> Enroll host</button>} />
      {loading ? <LoadingState /> : error ? <ErrorState message={error} retry={reload} /> : !data?.length ? <EmptyState title="No hosts registered" detail="A host is registered automatically when its first authenticated report is accepted." /> : (
        <section className="panel overflow-hidden">
          <div className="flex flex-col gap-4 px-5 py-5 xl:flex-row xl:items-center xl:justify-between md:px-7">
            <label className="relative block w-full sm:max-w-sm"><span className="sr-only">Search hosts by hostname</span><MagnifyingGlass className="absolute left-3 top-1/2 -translate-y-1/2 text-stone-600" size={16} /><input className="search-input" type="search" placeholder="Search hostname" value={search} onChange={(event) => setSearch(event.target.value)} /></label>
            <div className="flex flex-wrap items-center gap-2">{(['all', 'critical', 'healthy'] as const).map((value) => <button key={value} className={`filter-chip ${risk === value ? 'filter-chip-active' : ''}`} onClick={() => setRisk(value)}>{value === 'all' ? 'All hosts' : value === 'critical' ? 'Critical exposure' : 'Healthy'}</button>)}<span className="ml-2 font-mono text-[10px] uppercase tracking-[0.15em] text-stone-600">{hosts.length} shown</span></div>
          </div>
          <div className="overflow-x-auto border-t border-stone-800">
            <table className="data-table min-w-[850px]">
              <thead><tr><th>Host</th><th>Operating system</th><th>Environment</th><th>Security</th><th>Compliance</th><th>Open risk</th></tr></thead>
              <tbody>{hosts.map((host) => (
                <tr key={host.id} className="cursor-pointer" onClick={() => setSelected(host)}>
                  <td><div className="flex items-center gap-3"><span className="grid size-9 shrink-0 place-items-center rounded-[10px] border border-stone-800 bg-[#101411] text-emerald-500"><DesktopTower size={17} weight="duotone" /></span><span><button className="font-medium text-stone-200 hover:text-emerald-300" onClick={() => setSelected(host)}>{host.hostname}</button><span className="table-subtitle">{host.ip_addresses[0] ?? 'No address reported'}</span></span></div></td>
                  <td>{host.operating_system} {host.os_version}<span className="table-subtitle">Kernel {host.kernel}</span></td>
                  <td className="capitalize">{host.tags.environment ?? 'Unassigned'}<span className="table-subtitle">{host.tags.owner ?? 'No owner'}</span></td>
                  <td>{score(host.security_score)}</td>
                  <td>{score(host.compliance_score)}</td>
                  <td><span className={host.finding_counts.critical ? 'text-rose-400' : 'text-stone-300'}>{host.finding_counts.critical} critical</span><span className="table-subtitle">{host.finding_counts.high} high</span></td>
                </tr>
              ))}</tbody>
            </table>
            {!hosts.length && <div className="p-10 text-center text-sm text-stone-500">No hosts match “{search}”.</div>}
          </div>
        </section>
      )}
      {enrolling && <EnrollHostPanel close={() => setEnrolling(false)} created={() => void reload()} />}
      {selected && <HostQuickView key={selected.id} host={selected} close={() => setSelected(null)} deleted={() => { setSelected(null); void reload() }} />}
    </div>
  )
}
