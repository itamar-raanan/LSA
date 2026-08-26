import { Gear, Package } from '@phosphor-icons/react'
import { Boxes, Server, ShieldAlert, Shapes } from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useLocation, useSearchParams } from 'react-router-dom'
import { api } from '../api/client'
import { ApplicationInvestigationPanel } from '../components/ApplicationInvestigationPanel'
import { PageHeader } from '../components/PageHeader'
import { ErrorState, LoadingState } from '../components/StatePanel'
import { SecurityMetricCard } from '../components/security/SecurityMetricCard'
import { SecurityTable, type SecurityColumn } from '../components/security/SecurityTable'
import { useApi } from '../hooks/useApi'
import { useSecurityTableUrlState } from '../hooks/useSecurityTableUrlState'
import { withInvestigationReturn } from '../lib/investigationContext'
import { formatDate } from '../lib/dateTime'
import type { ApplicationEstateItem } from '../types'

type ApplicationKind = '' | ApplicationEstateItem['kind']
type RiskFilter = 'all' | 'vulnerable' | 'kev'
type ApplicationRow = ApplicationEstateItem & { id: string }

function applicationKey(item: ApplicationEstateItem) {
  return `${item.kind}:${item.source}:${item.name}`
}

function stateLabel(item: ApplicationEstateItem) {
  if (item.kind === 'package') return `${item.version_count || 1} Observed Version${item.version_count === 1 ? '' : 's'}`
  if (item.running_host_count) return `${item.running_host_count} Running`
  if (item.enabled_host_count) return `${item.enabled_host_count} Enabled`
  return 'Not Active'
}

export function ApplicationsPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const location = useLocation()
  const requestedSearch = searchParams.get('search') ?? ''
  const requestedApplication = searchParams.get('application')
  const requestedKind = searchParams.get('kind')
  const requestedRisk = searchParams.get('risk')
  const tableState = useSecurityTableUrlState({ clearOnSearch: ['application'] })
  const [query, setQuery] = useState(requestedSearch)
  const [search, setSearch] = useState(requestedSearch)
  const [kind, setKind] = useState<ApplicationKind>(requestedKind === 'package' || requestedKind === 'service' ? requestedKind : '')
  const [riskFilter, setRiskFilter] = useState<RiskFilter>(requestedRisk === 'vulnerable' || requestedRisk === 'kev' ? requestedRisk : 'all')
  const [selected, setSelected] = useState<ApplicationEstateItem | null>(null)
  const ignoredApplication = useRef<string | null>(null)
  const estate = useApi(() => api.applicationEstatePage({
    search,
    kind,
    risk: riskFilter === 'all' ? undefined : riskFilter,
    page: tableState.page,
    pageSize: 10,
    sort: tableState.sort?.id,
    direction: tableState.sort?.direction,
  }), [search, kind, riskFilter, tableState.page, tableState.sort?.id, tableState.sort?.direction])
  const intelligence = useApi(() => api.vulnerabilitySummary(), [])
  const correlation = useApi(
    () => selected ? api.applicationCorrelation(selected.name, selected.kind, selected.source) : Promise.resolve([]),
    [selected?.name, selected?.kind, selected?.source],
  )
  const vulnerabilities = useApi(
    () => selected?.kind === 'package' ? api.applicationVulnerabilities(selected.name, selected.kind, selected.source) : Promise.resolve([]),
    [selected?.name, selected?.kind, selected?.source],
  )
  const closeInvestigation = useCallback(() => {
    ignoredApplication.current = requestedApplication
    setSelected(null)
    const next = new URLSearchParams(searchParams)
    next.delete('application')
    setSearchParams(next, { replace: true })
  }, [requestedApplication, searchParams, setSearchParams])

  const openInvestigation = useCallback((application: ApplicationEstateItem) => {
    ignoredApplication.current = null
    setSelected(application)
    const next = new URLSearchParams(searchParams)
    next.set('application', applicationKey(application))
    setSearchParams(next, { replace: true })
  }, [searchParams, setSearchParams])

  function updateQuery(value: string) {
    setQuery(value)
    setSelected(null)
    const next = new URLSearchParams(searchParams)
    if (value.trim()) next.set('search', value)
    else next.delete('search')
    next.delete('application')
    next.delete('page')
    setSearchParams(next, { replace: true })
  }

  function updateFilter(key: 'kind' | 'risk', value: string) {
    if (key === 'kind') setKind(value as ApplicationKind)
    else setRiskFilter(value as RiskFilter)
    setSelected(null)
    const next = new URLSearchParams(searchParams)
    if (!value || value === 'all') next.delete(key)
    else next.set(key, value)
    next.delete('application')
    next.delete('page')
    setSearchParams(next, { replace: true })
  }

  useEffect(() => {
    const timer = window.setTimeout(() => setSearch(query.trim()), 250)
    return () => window.clearTimeout(timer)
  }, [query])

  useEffect(() => {
    if (requestedSearch !== query) setQuery(requestedSearch)
  }, [query, requestedSearch])

  useEffect(() => {
    setKind(requestedKind === 'package' || requestedKind === 'service' ? requestedKind : '')
    setRiskFilter(requestedRisk === 'vulnerable' || requestedRisk === 'kev' ? requestedRisk : 'all')
  }, [requestedKind, requestedRisk])

  useEffect(() => {
    if (!requestedApplication) {
      ignoredApplication.current = null
      return
    }
    if (ignoredApplication.current === requestedApplication) return
    const application = estate.data?.data.applications.find((item) => applicationKey(item) === requestedApplication)
    if (application) {
      setSelected(application)
      return
    }
    if (selected && applicationKey(selected) === requestedApplication) return
    const [requestedType, requestedSource, ...nameParts] = requestedApplication.split(':')
    if ((requestedType !== 'package' && requestedType !== 'service') || !requestedSource || !nameParts.length) return
    let active = true
    void api.applicationEstatePage({ search: nameParts.join(':'), kind: requestedType, page: 0, pageSize: 100 })
      .then((result) => {
        const match = result.data.applications.find((item) => applicationKey(item) === requestedApplication)
        if (active && match) setSelected(match)
      })
      .catch(() => undefined)
    return () => { active = false }
  }, [estate.data?.data.applications, requestedApplication, selected])

  const metrics = estate.data?.data.metrics
  const risk = intelligence.data
  const rows = useMemo<ApplicationRow[]>(() => (estate.data?.data.applications ?? [])
    .map((item) => ({ ...item, id: applicationKey(item) })), [estate.data?.data.applications])
  const columns = useMemo<SecurityColumn<ApplicationRow>[]>(() => [
    {
      id: 'application',
      header: 'Application',
      cell: (item) => {
        const active = selected ? applicationKey(selected) === applicationKey(item) : false
        return <button className="application-name-button" onClick={() => openInvestigation(item)} aria-pressed={active}><span className="application-kind-icon">{item.kind === 'package' ? <Package size={15} /> : <Gear size={15} />}</span><span><strong>{item.name}</strong><small>{item.publisher ?? item.description ?? 'Publisher Not Reported'}</small></span></button>
      },
      sortValue: (item) => item.name,
      exportValue: (item) => item.name,
      hideable: false,
      priority: 'primary',
    },
    {
      id: 'coverage',
      header: 'Coverage',
      cell: (item) => <><span className="table-primary">{item.host_count} Host{item.host_count === 1 ? '' : 's'}</span><span className="table-subtitle">{Math.round((item.host_count / Math.max(metrics?.reporting_hosts ?? 1, 1)) * 100)}% Of Reporting Fleet</span></>,
      sortValue: (item) => item.host_count,
      exportValue: (item) => item.host_count,
      priority: 'secondary',
    },
    {
      id: 'risk',
      header: 'Risk',
      cell: (item) => item.known_exploited_count ? <><span className="kev-badge">Known Exploited</span><span className="table-subtitle">{item.vulnerability_count} Advisories</span></> : item.vulnerability_count ? <><span className="severity-badge severity-high">Review</span><span className="table-subtitle">{item.vulnerability_count} Advisories</span></> : <span className="table-subtitle">No Matches</span>,
      sortValue: (item) => item.known_exploited_count * 1000 + item.vulnerability_count,
      exportValue: (item) => item.known_exploited_count ? 'Known Exploited' : item.vulnerability_count ? `${item.vulnerability_count} Advisories` : 'No Matches',
      priority: 'secondary',
    },
    {
      id: 'state',
      header: 'Versions And State',
      cell: (item) => <><span className="table-primary">{stateLabel(item)}</span><span className="table-subtitle">First Seen {formatDate(item.first_seen_at)}</span></>,
      sortValue: (item) => item.version_count || item.running_host_count || item.enabled_host_count,
      exportValue: stateLabel,
      priority: 'detail',
    },
    { id: 'type', header: 'Type', priority: 'detail', cell: (item) => <span className="capitalize">{item.kind}</span>, sortValue: (item) => item.kind, exportValue: (item) => item.kind },
    { id: 'source', header: 'Source', priority: 'detail', cell: (item) => <span className="font-mono text-xs capitalize">{item.source}</span>, sortValue: (item) => item.source, exportValue: (item) => item.source },
    { id: 'observed', header: 'Last Observed', priority: 'detail', cell: (item) => <span className="font-mono text-xs">{formatDate(item.last_seen_at)}</span>, sortValue: (item) => item.last_seen_at, exportValue: (item) => item.last_seen_at },
  ], [metrics?.reporting_hosts, openInvestigation, selected])

  return <div className="page-reveal">
    <PageHeader
      eyebrow="Software Estate"
      title="Applications"
      detail="Correlate installed packages, services, versions, and reporting Linux hosts. Open an application to review its related advisory and host context."
    />

    {estate.loading && !estate.data ? <LoadingState variant="table" /> : estate.error ? <ErrorState message={estate.error} retry={estate.reload} /> : !estate.data ? null : <>
      <section className="metric-grid application-metric-grid mb-4">
        <SecurityMetricCard title="Unique Applications" value={metrics?.unique_applications ?? 0} detail={`${metrics?.package_count ?? 0} Packages · ${metrics?.service_count ?? 0} Services`} icon={Shapes} />
        <SecurityMetricCard title="Vulnerable Hosts" value={risk?.affected_hosts ?? 0} detail={`${risk?.affected_applications ?? 0} Affected Installations`} tone={risk?.affected_hosts ? 'medium' : 'success'} icon={Server} />
        <SecurityMetricCard title="Active Exposures" value={risk?.exposure_count ?? 0} detail={`${risk?.vulnerability_count ?? 0} Unique Advisories`} tone={risk?.severity_counts.critical ? 'critical' : risk?.exposure_count ? 'medium' : 'success'} icon={Boxes} />
        <SecurityMetricCard title="Known Exploited" value={risk?.known_exploited ?? 0} detail="CISA KEV Prioritized Exposures" tone={risk?.known_exploited ? 'critical' : 'success'} icon={ShieldAlert} />
      </section>

      <section className="panel min-w-0 overflow-hidden">
        <SecurityTable
          rows={rows}
          columns={columns}
          ariaLabel="Application Inventory"
          query={query}
          onQueryChange={updateQuery}
          sort={tableState.sort}
          onSortChange={tableState.setSort}
          serverPagination={{ page: estate.data.page, pageSize: estate.data.pageSize, totalRows: estate.data.total, onPageChange: tableState.setPage }}
          searchText={(item) => `${item.name} ${item.publisher ?? ''} ${item.description ?? ''} ${item.kind} ${item.source}`}
          rowLabel={(item) => item.name}
          searchPlaceholder="Search Application, Version, Or Publisher"
          filename="lsa-application-inventory.csv"
          pageSize={10}
          embedded
          emptyTitle="No Applications Found"
          emptyDetail={query || kind || riskFilter !== 'all' ? 'Change the search or filters to see more inventory.' : 'Application inventory appears after an agent or offline report submits package and service data.'}
          toolbarActions={<>
            <label className="table-filter-field"><span className="sr-only">Filter Application Type</span><select aria-label="Filter Application Type" value={kind} onChange={(event) => updateFilter('kind', event.target.value)}><option value="">All Types</option><option value="package">Packages</option><option value="service">Services</option></select></label>
            <label className="table-filter-field"><span className="sr-only">Filter Application Risk</span><select aria-label="Filter Application Risk" value={riskFilter} onChange={(event) => updateFilter('risk', event.target.value)}><option value="all">All Risk</option><option value="vulnerable">Vulnerable</option><option value="kev">Known Exploited</option></select></label>
          </>}
        />
      </section>
    </>}

    {selected && <ApplicationInvestigationPanel
      key={applicationKey(selected)}
      application={selected}
      hosts={correlation.data ?? []}
      hostsLoading={correlation.loading}
      hostsError={correlation.error}
      retryHosts={correlation.reload}
      vulnerabilities={vulnerabilities.data ?? []}
      vulnerabilitiesLoading={vulnerabilities.loading}
      vulnerabilitiesError={vulnerabilities.error}
      retryVulnerabilities={vulnerabilities.reload}
      hostHref={(hostId) => withInvestigationReturn(`/hosts/${hostId}`, location)}
      close={closeInvestigation}
    />}
  </div>
}
