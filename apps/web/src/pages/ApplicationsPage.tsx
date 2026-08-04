import { Gear, MagnifyingGlass, Package } from '@phosphor-icons/react'
import { Boxes, GitCompareArrows, Server, Shapes } from 'lucide-react'
import { useMemo, useState } from 'react'
import type { FormEvent } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import { PageHeader } from '../components/PageHeader'
import { EmptyState, ErrorState, LoadingState } from '../components/StatePanel'
import { SecurityMetricCard } from '../components/security/SecurityMetricCard'
import { useApi } from '../hooks/useApi'
import { cn } from '../lib/utils'
import type { ApplicationEstateItem } from '../types'

type ApplicationKind = '' | ApplicationEstateItem['kind']

function applicationKey(item: ApplicationEstateItem) {
  return `${item.kind}:${item.source}:${item.name}`
}

function stateLabel(item: ApplicationEstateItem) {
  if (item.kind === 'package') return `${item.version_count || 1} observed version${item.version_count === 1 ? '' : 's'}`
  if (item.running_host_count) return `${item.running_host_count} running`
  if (item.enabled_host_count) return `${item.enabled_host_count} enabled`
  return 'Not active'
}

export function ApplicationsPage() {
  const [draftSearch, setDraftSearch] = useState('')
  const [search, setSearch] = useState('')
  const [kind, setKind] = useState<ApplicationKind>('')
  const [selected, setSelected] = useState<ApplicationEstateItem | null>(null)
  const estate = useApi(() => api.applicationEstate(search, kind), [search, kind])
  const correlation = useApi(
    () => selected ? api.applicationCorrelation(selected.name, selected.kind, selected.source) : Promise.resolve([]),
    [selected?.name, selected?.kind, selected?.source],
  )
  const versionDistribution = useMemo(() => {
    const versions = new Map<string, number>()
    for (const host of correlation.data ?? []) {
      const version = host.version ?? 'Version not reported'
      versions.set(version, (versions.get(version) ?? 0) + 1)
    }
    return [...versions.entries()].sort((a, b) => b[1] - a[1])
  }, [correlation.data])
  const metrics = estate.data?.metrics

  function submitSearch(event: FormEvent) {
    event.preventDefault()
    setSearch(draftSearch.trim())
    setSelected(null)
  }

  return <div className="page-reveal">
    <PageHeader eyebrow="Software estate" title="Applications" detail="Correlate installed packages and system services across every reporting Linux host. Compare versions, runtime state, operating systems, and host posture from one inventory." />

    {estate.loading && !estate.data ? <LoadingState /> : estate.error ? <ErrorState message={estate.error} retry={estate.reload} /> : !estate.data ? null : <>
      <section className="metric-grid application-metric-grid mb-4">
        <SecurityMetricCard title="Unique applications" value={metrics?.unique_applications ?? 0} detail={`${metrics?.package_count ?? 0} packages · ${metrics?.service_count ?? 0} services`} icon={Shapes} />
        <SecurityMetricCard title="Installations" value={metrics?.installation_count ?? 0} detail="Active application-to-host records" icon={Boxes} />
        <SecurityMetricCard title="Reporting hosts" value={metrics?.reporting_hosts ?? 0} detail="Hosts contributing inventory" tone="success" icon={Server} />
        <SecurityMetricCard title="Version drift" value={metrics?.version_drift_count ?? 0} detail="Applications with multiple versions" tone={metrics?.version_drift_count ? 'medium' : 'success'} icon={GitCompareArrows} />
      </section>

      <div className="application-estate-layout">
        <section className="panel min-w-0 overflow-hidden">
          <div className="security-table-toolbar">
            <form className="soc-search" onSubmit={submitSearch}>
              <MagnifyingGlass size={15} />
              <label className="sr-only" htmlFor="application-search">Search applications</label>
              <input id="application-search" value={draftSearch} onChange={(event) => setDraftSearch(event.target.value)} placeholder="Search application, version, or publisher" />
            </form>
            <div className="flex flex-wrap gap-2">
              {([['', 'All'], ['package', 'Packages'], ['service', 'Services']] as const).map(([value, label]) => <button key={label} className={kind === value ? 'filter-chip filter-chip-active' : 'filter-chip'} aria-pressed={kind === value} onClick={() => { setKind(value); setSelected(null) }}>{label}</button>)}
            </div>
          </div>

          {!estate.data.applications.length ? <div className="p-4"><EmptyState title="No applications found" detail={search || kind ? 'Change the search or type filter to see more inventory.' : 'Application inventory appears after an agent or offline report submits package and service data.'} /></div> : <div className="overflow-x-auto">
            <table className="data-table min-w-[820px]">
              <thead><tr><th>Application</th><th>Coverage</th><th>Versions & state</th><th>Type</th><th>Source</th><th>Last observed</th></tr></thead>
              <tbody>{estate.data.applications.map((item) => {
                const active = selected ? applicationKey(selected) === applicationKey(item) : false
                return <tr key={applicationKey(item)} className={cn('application-estate-row', active && 'application-estate-row-active')}>
                  <td><button className="application-name-button" onClick={() => setSelected(item)} aria-pressed={active}><span className="application-kind-icon">{item.kind === 'package' ? <Package size={15} /> : <Gear size={15} />}</span><span><strong>{item.name}</strong><small>{item.publisher ?? item.description ?? 'Publisher not reported'}</small></span></button></td>
                  <td><span className="table-primary">{item.host_count} host{item.host_count === 1 ? '' : 's'}</span><span className="table-subtitle">{Math.round((item.host_count / Math.max(metrics?.reporting_hosts ?? 1, 1)) * 100)}% of reporting fleet</span></td>
                  <td><span className="table-primary">{stateLabel(item)}</span><span className="table-subtitle">First seen {new Date(item.first_seen_at).toLocaleDateString()}</span></td>
                  <td className="capitalize">{item.kind}</td>
                  <td className="font-mono text-xs capitalize">{item.source}</td>
                  <td className="font-mono text-xs">{new Date(item.last_seen_at).toLocaleDateString()}</td>
                </tr>
              })}</tbody>
            </table>
          </div>}
        </section>

        <aside className="application-correlation-panel panel" aria-label="Application correlation">
          {!selected ? <div className="application-correlation-empty"><GitCompareArrows size={22} /><h2>Select an application</h2><p>Choose a package or service to compare versions, host posture, operating systems, and runtime state.</p></div> : <>
            <header className="application-correlation-header">
              <div className="application-kind-icon">{selected.kind === 'package' ? <Package size={17} /> : <Gear size={17} />}</div>
              <div className="min-w-0"><p className="section-label">Host correlation</p><h2>{selected.name}</h2><p>{selected.kind} · {selected.source} · {selected.host_count} host{selected.host_count === 1 ? '' : 's'}</p></div>
            </header>
            {correlation.loading ? <div className="skeleton m-5 h-52 rounded-lg" /> : correlation.error ? <div className="p-5"><ErrorState message={correlation.error} retry={correlation.reload} /></div> : <>
              {versionDistribution.length > 0 && <section className="application-version-block"><p className="detail-label">Version distribution</p><div className="mt-4 grid gap-3">{versionDistribution.map(([version, count]) => <div key={version}><div className="flex items-center justify-between gap-3 text-xs"><span className="min-w-0 truncate font-mono">{version}</span><span className="font-mono text-stone-600">{count}</span></div><div className="application-version-track"><span style={{ width: `${(count / Math.max(correlation.data?.length ?? 1, 1)) * 100}%` }} /></div></div>)}</div></section>}
              <section className="application-host-list"><div className="flex items-center justify-between"><p className="detail-label">Affected hosts</p><span className="font-mono text-[10px] text-stone-600">{correlation.data?.length ?? 0}</span></div>{correlation.data?.map((host) => <Link key={host.application_id} to={`/hosts/${host.host_id}`} className="application-host-link"><span className="min-w-0"><strong>{host.hostname}</strong><small>{host.os_family} {host.os_version} · {host.environment ?? 'Environment not set'}</small><small className="font-mono">{host.version ?? host.status}{host.architecture ? ` · ${host.architecture}` : ''}</small></span><span className="application-host-score"><strong>{host.security_score?.toFixed(0) ?? '—'}</strong><small>Security</small></span></Link>)}</section>
            </>}
          </>}
        </aside>
      </div>
    </>}
  </div>
}
