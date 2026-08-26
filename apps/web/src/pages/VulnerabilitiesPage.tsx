import { Bug, Boxes, RefreshCw, Server, ShieldAlert, Upload } from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef, useState, type ChangeEvent } from 'react'
import { useLocation, useSearchParams } from 'react-router-dom'
import { api } from '../api/client'
import { useAuth } from '../auth/useAuth'
import { PageHeader } from '../components/PageHeader'
import { ErrorState, LoadingState } from '../components/StatePanel'
import { SecurityMetricCard } from '../components/security/SecurityMetricCard'
import { SecurityTable, type SecurityColumn } from '../components/security/SecurityTable'
import { Button } from '../components/ui/Button'
import { VulnerabilityInvestigationPanel } from '../components/VulnerabilityInvestigationPanel'
import { useApi } from '../hooks/useApi'
import { useSecurityTableUrlState } from '../hooks/useSecurityTableUrlState'
import { cn } from '../lib/utils'
import { formatDate } from '../lib/dateTime'
import { withInvestigationReturn } from '../lib/investigationContext'
import type { VulnerabilityEstateItem } from '../types'

type ExploitationFilter = 'all' | 'kev'

function vulnerabilityLabel(item: VulnerabilityEstateItem) {
  return item.cve_id ?? item.id
}

export function VulnerabilitiesPage() {
  const { user } = useAuth()
  const [searchParams, setSearchParams] = useSearchParams()
  const location = useLocation()
  const requestedSeverity = searchParams.get('severity') ?? ''
  const requestedExploitation = searchParams.get('exploitation')
  const tableState = useSecurityTableUrlState({ clearOnSearch: ['vulnerability'] })
  const [query, setQuery] = useState(searchParams.get('search') ?? '')
  const [search, setSearch] = useState(searchParams.get('search') ?? '')
  const [severity, setSeverity] = useState(requestedSeverity)
  const [exploitation, setExploitation] = useState<ExploitationFilter>(requestedExploitation === 'kev' ? 'kev' : 'all')
  const [selected, setSelected] = useState<VulnerabilityEstateItem | null>(null)
  const [operation, setOperation] = useState<{ busy: boolean; message: string | null; error: string | null }>({ busy: false, message: null, error: null })
  const snapshotInput = useRef<HTMLInputElement>(null)

  const summary = useApi(() => api.vulnerabilitySummary(), [])
  const refreshSummary = summary.refresh
  const syncRunStatus = summary.data?.last_sync?.status
  const queue = useApi(() => api.vulnerabilityPage({
    search,
    severity: severity || undefined,
    knownExploited: exploitation === 'kev' ? true : undefined,
    page: tableState.page,
    pageSize: 15,
    sort: tableState.sort?.id,
    direction: tableState.sort?.direction,
  }), [search, severity, exploitation, tableState.page, tableState.sort?.id, tableState.sort?.direction])
  const exposures = useApi(() => selected ? api.vulnerabilityExposures(selected.id) : Promise.resolve([]), [selected?.id])

  const closeInvestigation = useCallback(() => {
    setSelected(null)
    const next = new URLSearchParams(searchParams)
    next.delete('vulnerability')
    setSearchParams(next, { replace: true })
  }, [searchParams, setSearchParams])

  const openInvestigation = useCallback((item: VulnerabilityEstateItem) => {
    setSelected(item)
    const next = new URLSearchParams(searchParams)
    next.set('vulnerability', item.id)
    setSearchParams(next, { replace: true })
  }, [searchParams, setSearchParams])

  useEffect(() => {
    const timer = window.setTimeout(() => setSearch(query.trim()), 250)
    return () => window.clearTimeout(timer)
  }, [query])

  useEffect(() => {
    const requested = searchParams.get('vulnerability')
    if (!requested) return
    const match = queue.data?.rows.find(item => item.id === requested)
    if (match && selected?.id !== match.id) setSelected(match)
  }, [queue.data?.rows, searchParams, selected?.id])

  useEffect(() => {
    if (syncRunStatus !== 'queued' && syncRunStatus !== 'running') return
    const timer = window.setInterval(() => void refreshSummary(), 4000)
    return () => window.clearInterval(timer)
  }, [refreshSummary, syncRunStatus])

  function updateQuery(value: string) {
    setQuery(value)
    setSelected(null)
    const next = new URLSearchParams(searchParams)
    if (value.trim()) next.set('search', value)
    else next.delete('search')
    next.delete('vulnerability')
    next.delete('page')
    setSearchParams(next, { replace: true })
  }

  function updateFilter(key: 'severity' | 'exploitation', value: string) {
    if (key === 'severity') setSeverity(value)
    else setExploitation(value === 'kev' ? 'kev' : 'all')
    setSelected(null)
    const next = new URLSearchParams(searchParams)
    if (!value || value === 'all') next.delete(key)
    else next.set(key, value)
    next.delete('vulnerability')
    next.delete('page')
    setSearchParams(next, { replace: true })
  }

  async function queueRefresh() {
    setOperation({ busy: true, message: null, error: null })
    try {
      const run = await api.queueVulnerabilitySync()
      setOperation({ busy: false, message: `Intelligence Refresh ${run.status}.`, error: null })
      await summary.refresh()
    } catch (reason) {
      setOperation({ busy: false, message: null, error: reason instanceof Error ? reason.message : 'Unable To Queue Refresh' })
    }
  }

  async function importSnapshot(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (!file) return
    setOperation({ busy: true, message: null, error: null })
    try {
      const result = await api.importVulnerabilitySnapshot(file)
      setOperation({ busy: false, message: `Imported ${result.vulnerabilities_found} Vulnerabilities And ${result.matches_found} Exposures.`, error: null })
      await Promise.all([summary.reload(), queue.reload()])
    } catch (reason) {
      setOperation({ busy: false, message: null, error: reason instanceof Error ? reason.message : 'Snapshot Import Failed' })
    }
  }

  const columns = useMemo<SecurityColumn<VulnerabilityEstateItem>[]>(() => [
    { id: 'identifier', header: 'Vulnerability', hideable: false, priority: 'primary', sortValue: vulnerabilityLabel, exportValue: vulnerabilityLabel, cell: item => <button className="finding-table-link vulnerability-table-link" aria-label={`Investigate ${vulnerabilityLabel(item)}`} onClick={() => openInvestigation(item)}><span className="min-w-0"><strong>{vulnerabilityLabel(item)}</strong><small>{item.summary || 'Security Advisory'}</small></span><span className="vulnerability-mobile-priority" aria-hidden="true"><span className={`severity-badge severity-${item.severity}`}>{item.severity}{item.cvss_score === null ? '' : ` · ${item.cvss_score.toFixed(1)}`}</span>{item.known_exploited && <span className="kev-badge">Known Exploited</span>}</span></button> },
    { id: 'severity', header: 'Severity', priority: 'secondary', sortValue: item => item.cvss_score ?? -1, exportValue: item => `${item.severity}${item.cvss_score === null ? '' : ` ${item.cvss_score}`}`, cell: item => <><span className={`severity-badge severity-${item.severity}`}>{item.severity}</span><span className="table-subtitle">{item.cvss_score === null ? 'CVSS Not Reported' : `CVSS ${item.cvss_score.toFixed(1)}`}</span></> },
    { id: 'priority', header: 'Exploit Priority', priority: 'secondary', sortValue: item => item.known_exploited ? 1 : 0, exportValue: item => item.known_exploited ? 'CISA KEV' : 'No Known Exploitation', cell: item => item.known_exploited ? <><span className="kev-badge">Known Exploited</span><span className="table-subtitle">Due {formatDate(item.kev_due_date, 'Date Not Reported')}</span></> : <span className="table-subtitle">No CISA KEV Match</span> },
    { id: 'hosts', header: 'Impact', priority: 'secondary', sortValue: item => item.affected_hosts, exportValue: item => `${item.affected_hosts} hosts; ${item.exposure_count} exposures`, cell: item => <><span className="table-primary">{item.affected_hosts} Host{item.affected_hosts === 1 ? '' : 's'}</span><span className="table-subtitle">{item.exposure_count} Exposure{item.exposure_count === 1 ? '' : 's'} · {item.affected_applications} Application{item.affected_applications === 1 ? '' : 's'}</span></> },
    { id: 'software', header: 'Affected Software', priority: 'detail', sortValue: item => item.application_names.join(' '), exportValue: item => item.application_names.join(', '), cell: item => <span className="table-primary">{item.application_names.slice(0, 2).join(', ') || 'Not Reported'}<small>{item.affected_versions.length} Affected Version{item.affected_versions.length === 1 ? '' : 's'}</small></span> },
    { id: 'fix', header: 'Fix Availability', priority: 'detail', sortValue: item => item.fixed_versions.length, exportValue: item => item.fixed_versions.join(', '), cell: item => item.fixed_versions.length ? <><span className="status-pill status-pill-online">Fix Reported</span><span className="table-subtitle">{item.fixed_versions[0]}</span></> : <><span className="status-pill status-pill-stale">Vendor Review</span><span className="table-subtitle">No Fixed Version Reported</span></> },
    { id: 'published', header: 'Published', priority: 'detail', sortValue: item => item.published_at ?? '', exportValue: item => item.published_at, cell: item => <span className="font-mono text-[10px] text-stone-600">{formatDate(item.published_at, 'Not Reported')}</span> },
  ], [openInvestigation])

  const risk = summary.data
  const syncStatus = risk?.last_sync
  const intelligenceState = risk?.intelligence_state
  const operationNotice = operation.message || operation.error || intelligenceState === 'never' || intelligenceState === 'stale' || intelligenceState === 'refreshing' || intelligenceState === 'failed'

  return <div className="page-reveal">
    <PageHeader
      eyebrow="Exposure Management"
      title="Vulnerabilities"
      detail="Prioritize active CVEs by severity, known exploitation, affected Linux hosts, exposed software, and available vendor fixes."
      action={user?.role === 'admin' ? <div className="flex flex-wrap justify-end gap-2">
        <input ref={snapshotInput} className="sr-only" type="file" accept="application/json,.json" onChange={importSnapshot} aria-label="Import Vulnerability Snapshot" />
        <Button onClick={() => snapshotInput.current?.click()} disabled={operation.busy}><Upload size={14} />Import Snapshot</Button>
        <Button variant="primary" onClick={() => void queueRefresh()} disabled={operation.busy || syncStatus?.status === 'queued' || syncStatus?.status === 'running'}><RefreshCw className={syncStatus?.status === 'running' ? 'animate-spin' : ''} size={14} />Refresh Intelligence</Button>
      </div> : undefined}
    />

    {operationNotice && <section className={cn('intelligence-status', (operation.error || intelligenceState === 'failed') && 'intelligence-status-error')} aria-live="polite">
      <ShieldAlert size={16} />
      <div><strong>{operation.error ? 'Intelligence Update Failed' : intelligenceState === 'failed' ? 'Last Refresh Failed' : intelligenceState === 'refreshing' ? 'Intelligence Refresh In Progress' : intelligenceState === 'stale' ? 'Vulnerability Intelligence Is Stale' : intelligenceState === 'never' ? 'Vulnerability Intelligence Not Synchronized' : 'Vulnerability Intelligence Updated'}</strong><p>{operation.error ?? operation.message ?? syncStatus?.error ?? (intelligenceState === 'stale' ? 'Refresh online intelligence or import a current offline snapshot before making remediation decisions.' : intelligenceState === 'never' ? 'Run the first refresh or import an offline snapshot to begin package correlation.' : 'The synchronization worker will process the queued request.')}</p></div>
    </section>}

    {summary.loading && !risk ? <LoadingState variant="table" /> : summary.error ? <ErrorState message={summary.error} retry={summary.reload} /> : <>
      <section className="metric-grid application-metric-grid mb-4">
        <SecurityMetricCard title="Active CVEs" value={risk?.vulnerability_count ?? 0} detail={`${risk?.exposure_count ?? 0} Active Exposures`} tone={risk?.vulnerability_count ? 'medium' : 'success'} icon={Bug} />
        <SecurityMetricCard title="Critical And High" value={(risk?.severity_counts.critical ?? 0) + (risk?.severity_counts.high ?? 0)} detail={`${risk?.severity_counts.critical ?? 0} Critical · ${risk?.severity_counts.high ?? 0} High`} tone={risk?.severity_counts.critical ? 'critical' : risk?.severity_counts.high ? 'medium' : 'success'} icon={ShieldAlert} />
        <SecurityMetricCard title="Known Exploited CVEs" value={risk?.known_exploited ?? 0} detail={`${risk?.known_exploited ?? 0} CVE${risk?.known_exploited === 1 ? '' : 's'} · ${risk?.exposure_count ?? 0} Total Exposure${risk?.exposure_count === 1 ? '' : 's'}`} tone={risk?.known_exploited ? 'critical' : 'success'} icon={Boxes} />
        <SecurityMetricCard title="Affected Hosts" value={risk?.affected_hosts ?? 0} detail={`${risk?.affected_applications ?? 0} Affected Applications`} tone={risk?.affected_hosts ? 'medium' : 'success'} icon={Server} />
      </section>

      {queue.loading && !queue.data ? <LoadingState variant="table" /> : queue.error ? <ErrorState message={queue.error} retry={queue.reload} /> : <section className="panel min-w-0 overflow-hidden">
        <SecurityTable
          rows={queue.data?.rows ?? []}
          columns={columns}
          ariaLabel="Vulnerability Queue"
          query={query}
          onQueryChange={updateQuery}
          sort={tableState.sort}
          onSortChange={tableState.setSort}
          serverPagination={{ page: queue.data?.page ?? 0, pageSize: queue.data?.pageSize ?? 15, totalRows: queue.data?.total ?? 0, onPageChange: tableState.setPage }}
          searchText={item => `${vulnerabilityLabel(item)} ${item.aliases.join(' ')} ${item.summary} ${item.application_names.join(' ')}`}
          rowLabel={vulnerabilityLabel}
          searchPlaceholder="Search CVE, Advisory, Or Description"
          filename="lsa-vulnerabilities.csv"
          pageSize={15}
          embedded
          emptyTitle="No Active Vulnerabilities"
          emptyDetail={query || severity || exploitation !== 'all' ? 'Change the search or filters to review other active exposures.' : intelligenceState === 'never' ? 'Refresh vulnerability intelligence or import an offline snapshot to correlate installed packages.' : 'No cached advisory currently matches an active installed package.'}
          toolbarActions={<>
            <label className="table-filter-field"><span className="sr-only">Filter Vulnerability Severity</span><select aria-label="Filter Vulnerability Severity" value={severity} onChange={event => updateFilter('severity', event.target.value)}><option value="">All Severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="unknown">Unknown</option></select></label>
            <label className="table-filter-field"><span className="sr-only">Filter Exploitation Status</span><select aria-label="Filter Exploitation Status" value={exploitation} onChange={event => updateFilter('exploitation', event.target.value)}><option value="all">All Exploitation States</option><option value="kev">Known Exploited</option></select></label>
          </>}
        />
      </section>}
    </>}

    {selected && <VulnerabilityInvestigationPanel item={selected} exposures={exposures.data ?? []} loading={exposures.loading} error={exposures.error} retry={exposures.reload} hostHref={hostId => withInvestigationReturn(`/hosts/${hostId}`, location)} close={closeInvestigation} />}
  </div>
}
