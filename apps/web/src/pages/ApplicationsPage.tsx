import { Gear, MagnifyingGlass, Package } from '@phosphor-icons/react'
import { Boxes, ExternalLink, GitCompareArrows, RefreshCw, Server, ShieldAlert, Shapes, Upload } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import type { ChangeEvent, FormEvent } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import { useAuth } from '../auth/useAuth'
import { PageHeader } from '../components/PageHeader'
import { EmptyState, ErrorState, LoadingState } from '../components/StatePanel'
import { SecurityMetricCard } from '../components/security/SecurityMetricCard'
import { Button } from '../components/ui/Button'
import { useApi } from '../hooks/useApi'
import { cn } from '../lib/utils'
import type { ApplicationEstateItem, ApplicationVulnerability } from '../types'

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

function vulnerabilityLabel(item: ApplicationVulnerability) {
  return item.cve_id ?? item.id
}

export function ApplicationsPage() {
  const { user } = useAuth()
  const [draftSearch, setDraftSearch] = useState('')
  const [search, setSearch] = useState('')
  const [kind, setKind] = useState<ApplicationKind>('')
  const [selected, setSelected] = useState<ApplicationEstateItem | null>(null)
  const [selectedVulnerability, setSelectedVulnerability] = useState<ApplicationVulnerability | null>(null)
  const [operation, setOperation] = useState<{ busy: boolean; message: string | null; error: string | null }>({ busy: false, message: null, error: null })
  const snapshotInput = useRef<HTMLInputElement>(null)
  const estate = useApi(() => api.applicationEstate(search, kind), [search, kind])
  const intelligence = useApi(() => api.vulnerabilitySummary(), [])
  const correlation = useApi(
    () => selected ? api.applicationCorrelation(selected.name, selected.kind, selected.source) : Promise.resolve([]),
    [selected?.name, selected?.kind, selected?.source],
  )
  const vulnerabilities = useApi(
    () => selected?.kind === 'package' ? api.applicationVulnerabilities(selected.name, selected.kind, selected.source) : Promise.resolve([]),
    [selected?.name, selected?.kind, selected?.source],
  )
  const refreshIntelligence = intelligence.refresh

  useEffect(() => {
    setSelectedVulnerability(null)
  }, [selected?.name, selected?.kind, selected?.source])

  useEffect(() => {
    const status = intelligence.data?.last_sync?.status
    if (status !== 'queued' && status !== 'running') return
    const timer = window.setInterval(() => void refreshIntelligence(), 4000)
    return () => window.clearInterval(timer)
  }, [intelligence.data?.last_sync?.status, refreshIntelligence])

  const visibleHosts = useMemo(() => {
    if (!selectedVulnerability) return correlation.data ?? []
    const allowed = new Set(selectedVulnerability.affected_host_ids)
    return (correlation.data ?? []).filter((host) => allowed.has(host.host_id))
  }, [correlation.data, selectedVulnerability])
  const versionDistribution = useMemo(() => {
    const versions = new Map<string, number>()
    for (const host of visibleHosts) {
      const version = host.version ?? 'Version not reported'
      versions.set(version, (versions.get(version) ?? 0) + 1)
    }
    return [...versions.entries()].sort((a, b) => b[1] - a[1])
  }, [visibleHosts])
  const metrics = estate.data?.metrics
  const risk = intelligence.data

  function submitSearch(event: FormEvent) {
    event.preventDefault()
    setSearch(draftSearch.trim())
    setSelected(null)
  }

  async function queueRefresh() {
    setOperation({ busy: true, message: null, error: null })
    try {
      const run = await api.queueVulnerabilitySync()
      setOperation({ busy: false, message: `Intelligence refresh ${run.status}.`, error: null })
      await intelligence.refresh()
    } catch (reason) {
      setOperation({ busy: false, message: null, error: reason instanceof Error ? reason.message : 'Unable to queue refresh' })
    }
  }

  async function importSnapshot(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (!file) return
    setOperation({ busy: true, message: null, error: null })
    try {
      const result = await api.importVulnerabilitySnapshot(file)
      setOperation({ busy: false, message: `Imported ${result.vulnerabilities_found} vulnerabilities and ${result.matches_found} exposures.`, error: null })
      await Promise.all([intelligence.reload(), estate.refresh(), vulnerabilities.refresh()])
    } catch (reason) {
      setOperation({ busy: false, message: null, error: reason instanceof Error ? reason.message : 'Snapshot import failed' })
    }
  }

  const syncStatus = intelligence.data?.last_sync
  const intelligenceState = intelligence.data?.intelligence_state
  return <div className="page-reveal">
    <PageHeader
      eyebrow="Software Estate"
      title="Applications"
      detail="Correlate installed software, vulnerable versions, and affected Linux hosts using locally cached OSV advisories enriched with CISA exploitation intelligence."
      action={user?.role === 'admin' ? <div className="flex flex-wrap justify-end gap-2">
        <input ref={snapshotInput} className="sr-only" type="file" accept="application/json,.json" onChange={importSnapshot} aria-label="Import Vulnerability Snapshot" />
        <Button onClick={() => snapshotInput.current?.click()} disabled={operation.busy}><Upload size={14} />Import Snapshot</Button>
        <Button variant="primary" onClick={queueRefresh} disabled={operation.busy || syncStatus?.status === 'queued' || syncStatus?.status === 'running'}><RefreshCw className={syncStatus?.status === 'running' ? 'animate-spin' : ''} size={14} />Refresh Intelligence</Button>
      </div> : undefined}
    />

    {(operation.message || operation.error || intelligenceState === 'never' || intelligenceState === 'stale' || intelligenceState === 'refreshing' || intelligenceState === 'failed') && <section className={cn('intelligence-status', (operation.error || intelligenceState === 'failed') && 'intelligence-status-error')} aria-live="polite">
      <ShieldAlert size={16} />
      <div><strong>{operation.error ? 'Intelligence Update Failed' : intelligenceState === 'failed' ? 'Last Refresh Failed' : intelligenceState === 'refreshing' ? 'Intelligence Refresh In Progress' : intelligenceState === 'stale' ? 'Vulnerability Intelligence Is Stale' : intelligenceState === 'never' ? 'Vulnerability Intelligence Not Synchronized' : 'Vulnerability Intelligence Updated'}</strong><p>{operation.error ?? operation.message ?? syncStatus?.error ?? (intelligenceState === 'stale' ? 'Queue a refresh or import a current offline snapshot before making remediation decisions.' : intelligenceState === 'never' ? 'Queue the first online refresh or import an offline snapshot to begin package correlation.' : 'The synchronization worker will process the queued request.')}</p></div>
    </section>}

    {estate.loading && !estate.data ? <LoadingState /> : estate.error ? <ErrorState message={estate.error} retry={estate.reload} /> : !estate.data ? null : <>
      <section className="metric-grid application-metric-grid mb-4">
        <SecurityMetricCard title="Unique Applications" value={metrics?.unique_applications ?? 0} detail={`${metrics?.package_count ?? 0} packages · ${metrics?.service_count ?? 0} services`} icon={Shapes} />
        <SecurityMetricCard title="Vulnerable Hosts" value={risk?.affected_hosts ?? 0} detail={`${risk?.affected_applications ?? 0} affected installations`} tone={risk?.affected_hosts ? 'medium' : 'success'} icon={Server} />
        <SecurityMetricCard title="Active Exposures" value={risk?.exposure_count ?? 0} detail={`${risk?.vulnerability_count ?? 0} unique advisories`} tone={risk?.severity_counts.critical ? 'critical' : risk?.exposure_count ? 'medium' : 'success'} icon={Boxes} />
        <SecurityMetricCard title="Known Exploited" value={risk?.known_exploited ?? 0} detail="CISA KEV prioritized exposures" tone={risk?.known_exploited ? 'critical' : 'success'} icon={ShieldAlert} />
      </section>

      <div className="application-estate-layout">
        <section className="panel min-w-0 overflow-hidden">
          <div className="security-table-toolbar">
            <form className="soc-search" onSubmit={submitSearch}>
              <MagnifyingGlass size={15} />
              <label className="sr-only" htmlFor="application-search">Search Applications</label>
              <input id="application-search" value={draftSearch} onChange={(event) => setDraftSearch(event.target.value)} placeholder="Search Application, Version, Or Publisher" />
            </form>
            <div className="flex flex-wrap gap-2">
              {([['', 'All'], ['package', 'Packages'], ['service', 'Services']] as const).map(([value, label]) => <button key={label} className={kind === value ? 'filter-chip filter-chip-active' : 'filter-chip'} aria-pressed={kind === value} onClick={() => { setKind(value); setSelected(null) }}>{label}</button>)}
            </div>
          </div>

          {!estate.data.applications.length ? <div className="p-4"><EmptyState title="No Applications Found" detail={search || kind ? 'Change the search or type filter to see more inventory.' : 'Application inventory appears after an agent or offline report submits package and service data.'} /></div> : <div className="overflow-x-auto">
            <table className="data-table min-w-[820px]">
              <thead><tr><th>Application</th><th>Coverage</th><th>Risk</th><th>Versions And State</th><th>Type</th><th>Source</th><th>Last Observed</th></tr></thead>
              <tbody>{estate.data.applications.map((item) => {
                const active = selected ? applicationKey(selected) === applicationKey(item) : false
                return <tr key={applicationKey(item)} className={cn('application-estate-row', active && 'application-estate-row-active')}>
                  <td><button className="application-name-button" onClick={() => setSelected(item)} aria-pressed={active}><span className="application-kind-icon">{item.kind === 'package' ? <Package size={15} /> : <Gear size={15} />}</span><span><strong>{item.name}</strong><small>{item.publisher ?? item.description ?? 'Publisher Not Reported'}</small></span></button></td>
                  <td><span className="table-primary">{item.host_count} Host{item.host_count === 1 ? '' : 's'}</span><span className="table-subtitle">{Math.round((item.host_count / Math.max(metrics?.reporting_hosts ?? 1, 1)) * 100)}% Of Reporting Fleet</span></td>
                  <td>{item.known_exploited_count ? <><span className="kev-badge">Known Exploited</span><span className="table-subtitle">{item.vulnerability_count} Advisories</span></> : item.vulnerability_count ? <><span className="severity-badge severity-high">Review</span><span className="table-subtitle">{item.vulnerability_count} Advisories</span></> : <span className="table-subtitle">No Matches</span>}</td>
                  <td><span className="table-primary">{stateLabel(item)}</span><span className="table-subtitle">First Seen {new Date(item.first_seen_at).toLocaleDateString()}</span></td>
                  <td className="capitalize">{item.kind}</td>
                  <td className="font-mono text-xs capitalize">{item.source}</td>
                  <td className="font-mono text-xs">{new Date(item.last_seen_at).toLocaleDateString()}</td>
                </tr>
              })}</tbody>
            </table>
          </div>}
        </section>

        <aside className="application-correlation-panel panel" aria-label="Application Correlation">
          {!selected ? <div className="application-correlation-empty"><GitCompareArrows size={22} /><h2>Select An Application</h2><p>Choose a package or service to review vulnerable versions, affected hosts, operating systems, and runtime state.</p></div> : <>
            <header className="application-correlation-header">
              <div className="application-kind-icon">{selected.kind === 'package' ? <Package size={17} /> : <Gear size={17} />}</div>
              <div className="min-w-0"><p className="section-label">Application Investigation</p><h2>{selected.name}</h2><p>{selected.kind} · {selected.source} · {selected.host_count} Host{selected.host_count === 1 ? '' : 's'}</p></div>
            </header>
            {selected.kind === 'package' && <section className="application-vulnerability-block">
              <div className="flex items-center justify-between"><p className="detail-label">Vulnerability Intelligence</p><span className="font-mono text-[10px] text-stone-600">{vulnerabilities.data?.length ?? 0}</span></div>
              {vulnerabilities.loading ? <div className="skeleton mt-4 h-24 rounded-lg" /> : vulnerabilities.error ? <div className="mt-4"><ErrorState message={vulnerabilities.error} retry={vulnerabilities.reload} /></div> : !vulnerabilities.data?.length ? <p className="application-vulnerability-empty">No cached advisories match the observed package versions.</p> : <div className="application-vulnerability-list">{vulnerabilities.data.map((item) => <button key={item.id} className={cn('application-vulnerability-item', selectedVulnerability?.id === item.id && 'application-vulnerability-item-active')} onClick={() => setSelectedVulnerability(selectedVulnerability?.id === item.id ? null : item)}>
                <span className="flex min-w-0 items-center gap-2"><span className={`severity-badge severity-${item.severity}`}>{item.severity}</span><strong>{vulnerabilityLabel(item)}</strong>{item.known_exploited && <span className="kev-badge">Known Exploited</span>}</span>
                <small>{item.summary || 'Security Advisory'}</small>
                <span className="application-vulnerability-meta">{item.affected_hosts} Host{item.affected_hosts === 1 ? '' : 's'} · {item.affected_versions.length} Version{item.affected_versions.length === 1 ? '' : 's'}{item.fixed_versions.length ? ` · Fixed In ${item.fixed_versions[0]}` : ''}</span>
              </button>)}</div>}
              {selectedVulnerability && <div className="application-vulnerability-detail"><p>{selectedVulnerability.kev_required_action ?? selectedVulnerability.summary}</p>{selectedVulnerability.references.find((reference) => reference.url)?.url && <a href={selectedVulnerability.references.find((reference) => reference.url)?.url} target="_blank" rel="noreferrer">Open Advisory <ExternalLink size={11} /></a>}</div>}
            </section>}
            {correlation.loading ? <div className="skeleton m-5 h-52 rounded-lg" /> : correlation.error ? <div className="p-5"><ErrorState message={correlation.error} retry={correlation.reload} /></div> : <>
              {versionDistribution.length > 0 && <section className="application-version-block"><div className="flex items-center justify-between"><p className="detail-label">Version Distribution</p>{selectedVulnerability && <button className="text-button" onClick={() => setSelectedVulnerability(null)}>Show All Hosts</button>}</div><div className="mt-4 grid gap-3">{versionDistribution.map(([version, count]) => <div key={version}><div className="flex items-center justify-between gap-3 text-xs"><span className="min-w-0 truncate font-mono">{version}</span><span className="font-mono text-stone-600">{count}</span></div><div className="application-version-track"><span style={{ width: `${(count / Math.max(visibleHosts.length, 1)) * 100}%` }} /></div></div>)}</div></section>}
              <section className="application-host-list"><div className="flex items-center justify-between"><p className="detail-label">{selectedVulnerability ? 'Affected Hosts' : 'Observed Hosts'}</p><span className="font-mono text-[10px] text-stone-600">{visibleHosts.length}</span></div>{visibleHosts.map((host) => <Link key={host.application_id} to={`/hosts/${host.host_id}`} className="application-host-link"><span className="min-w-0"><strong>{host.hostname}</strong><small>{host.os_family} {host.os_version} · {host.environment ?? 'Environment Not Set'}</small><small className="font-mono">{host.version ?? host.status}{host.architecture ? ` · ${host.architecture}` : ''}</small></span><span className="application-host-score"><strong>{host.security_score?.toFixed(0) ?? '—'}</strong><small>Security</small></span></Link>)}</section>
            </>}
          </>}
        </aside>
      </div>
    </>}
  </div>
}
