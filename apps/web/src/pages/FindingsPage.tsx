import { ArrowRight, FolderOpen, ShieldWarning } from '@phosphor-icons/react'
import { useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api } from '../api/client'
import { FindingDetailPanel } from '../components/FindingDetailPanel'
import { PageHeader } from '../components/PageHeader'
import { type SecurityColumn, SecurityTable } from '../components/security/SecurityTable'
import { SeverityBadge } from '../components/SeverityBadge'
import { ErrorState, LoadingState } from '../components/StatePanel'
import { useApi } from '../hooks/useApi'
import { useSecurityTableUrlState } from '../hooks/useSecurityTableUrlState'
import type { Finding, Severity } from '../types'

const categoryCatalog = [
  { id: 'accounts', name: 'Accounts', detail: 'Local identities and privileged UIDs' },
  { id: 'audit', name: 'Audit', detail: 'Linux audit subsystem and event capture' },
  { id: 'filesystem', name: 'Filesystem', detail: 'Ownership and permissions on sensitive files' },
  { id: 'kernel', name: 'Kernel', detail: 'Runtime hardening and process isolation' },
  { id: 'logging', name: 'Logging', detail: 'Persistent system journal and log posture' },
  { id: 'mandatory_access', name: 'Mandatory Access', detail: 'AppArmor policy enforcement' },
  { id: 'network', name: 'Network', detail: 'Firewall, listeners, and packet forwarding' },
  { id: 'packages', name: 'Packages', detail: 'Required security software' },
  { id: 'services', name: 'Services', detail: 'Enabled and active system services' },
  { id: 'ssh', name: 'SSH', detail: 'Remote access authentication and exposure' },
  { id: 'time', name: 'Time Synchronization', detail: 'Trusted and synchronized system time' },
  { id: 'updates', name: 'Updates', detail: 'Repositories, patching, and reboot posture' },
]

const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

export function FindingsPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const requestedSeverity = searchParams.get('severity')
  const initialSeverity = severityOrder.includes(requestedSeverity as Severity) ? requestedSeverity as Severity : 'all'
  const [severity, setSeverity] = useState<Severity | 'all'>(initialSeverity)
  const [lifecycle, setLifecycle] = useState(searchParams.get('lifecycle') ?? 'all')
  const [category, setCategory] = useState<string | null>(searchParams.get('category'))
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null)
  const tableState = useSecurityTableUrlState({ clearOnSearch: ['finding'] })
  const [serverSearch, setServerSearch] = useState(tableState.query)
  const facets = useApi(() => api.findingFacets(), [])
  const { data, error, loading, reload } = useApi(
    () => category ? api.findingPage({
      search: serverSearch,
      severity: severity === 'all' ? undefined : severity,
      lifecycle: lifecycle === 'all' ? undefined : lifecycle,
      category,
      page: tableState.page,
      pageSize: 10,
      sort: tableState.sort?.id,
      direction: tableState.sort?.direction,
    }) : Promise.resolve({ rows: [], total: 0, page: 0, pageSize: 10 }),
    [category, severity, lifecycle, serverSearch, tableState.page, tableState.sort?.id, tableState.sort?.direction],
  )
  const findings = useMemo(() => data?.rows ?? [], [data?.rows])
  const categories = useMemo(() => {
    const known = new Set(categoryCatalog.map((item) => item.id))
    const discovered = (facets.data?.categories ?? []).filter((item) => !known.has(item.category))
      .map((item) => ({ id: item.category, name: item.category.replaceAll('_', ' '), detail: 'Scanner-reported control category' }))
    return [...categoryCatalog, ...discovered]
  }, [facets.data?.categories])
  const selectedCategory = categories.find((item) => item.id === category) ?? null
  const selectedFacet = facets.data?.categories.find((item) => item.category === category)
  const lifecycleOptions = selectedFacet?.lifecycles ?? []

  useEffect(() => {
    const timer = window.setTimeout(() => setServerSearch(tableState.query.trim()), 250)
    return () => window.clearTimeout(timer)
  }, [tableState.query])

  useEffect(() => {
    const nextSeverity = severityOrder.includes(requestedSeverity as Severity) ? requestedSeverity as Severity : 'all'
    setSeverity(nextSeverity)
    setLifecycle(searchParams.get('lifecycle') ?? 'all')
    setCategory(searchParams.get('category'))
  }, [requestedSeverity, searchParams])

  useEffect(() => {
    const findingId = searchParams.get('finding')
    if (!findingId) {
      setSelectedFinding(null)
      return
    }
    const requestedFinding = findings.find((finding) => finding.id === findingId)
    if (requestedFinding) {
      if (selectedFinding?.id !== requestedFinding.id) setSelectedFinding(requestedFinding)
      return
    }
    if (selectedFinding?.id === findingId) return
    let active = true
    void api.finding(findingId).then((finding) => { if (active) setSelectedFinding(finding) }).catch(() => undefined)
    return () => { active = false }
  }, [findings, searchParams, selectedFinding?.id])

  function updateParams(updates: Record<string, string | null>) {
    const next = new URLSearchParams(searchParams)
    for (const [key, value] of Object.entries(updates)) {
      if (!value || value === 'all') next.delete(key)
      else next.set(key, value)
    }
    if (['category', 'severity', 'lifecycle'].some((key) => key in updates)) next.delete('page')
    setSearchParams(next, { replace: true })
  }

  function openFinding(finding: Finding) {
    setSelectedFinding(finding)
    setCategory(finding.category)
    updateParams({ category: finding.category, finding: finding.id })
  }

  function closeFinding() {
    setSelectedFinding(null)
    updateParams({ finding: null })
  }

  const columns: SecurityColumn<Finding>[] = [
    { id: 'severity', header: 'Severity', priority: 'secondary', sortValue: (finding) => severityOrder.indexOf(finding.severity), exportValue: (finding) => finding.severity, cell: (finding) => <SeverityBadge severity={finding.severity} /> },
    { id: 'finding', header: 'Finding', priority: 'primary', hideable: false, sortValue: (finding) => finding.title, exportValue: (finding) => finding.title, cell: (finding) => <button className="finding-table-link" onClick={() => openFinding(finding)}><strong>{finding.title}</strong><small>{finding.control_id} · {finding.module}</small></button> },
    { id: 'host', header: 'Affected Host', priority: 'secondary', sortValue: (finding) => finding.hostname, exportValue: (finding) => finding.hostname, cell: (finding) => <span className="table-primary">{finding.hostname}<small>Host Record</small></span> },
    { id: 'lifecycle', header: 'Lifecycle', priority: 'detail', sortValue: (finding) => finding.lifecycle, exportValue: (finding) => finding.lifecycle, cell: (finding) => <span className={`status-pill ${finding.lifecycle === 'new' ? 'status-pill-warning' : 'status-pill-stale'}`}>{finding.lifecycle}</span> },
    { id: 'observed', header: 'Observed State', priority: 'detail', sortValue: (finding) => finding.actual ?? '', exportValue: (finding) => finding.actual, cell: (finding) => <span className="finding-observed-state">{finding.actual || 'No Concrete Value Reported'}</span> },
    { id: 'impact', header: 'Change Impact', priority: 'detail', sortValue: (finding) => Number(finding.reboot_required) * 2 + Number(finding.service_restart), exportValue: (finding) => finding.reboot_required ? 'Reboot required' : finding.service_restart ? 'Service restart' : 'No restart reported', cell: (finding) => <span className="table-primary">{finding.reboot_required ? 'Reboot Required' : finding.service_restart ? 'Service Restart' : 'No Restart'}<small>{finding.remediation_commands.length} Apply Steps</small></span> },
    { id: 'action', header: '', priority: 'detail', hideable: false, cell: (finding) => <button className="button-secondary min-h-8 whitespace-nowrap px-3" onClick={() => openFinding(finding)}>Investigate <ArrowRight size={14} /></button> },
  ]

  function selectCategory(nextCategory: string) {
    setCategory(nextCategory)
    setLifecycle('all')
    setSelectedFinding(null)
    updateParams({ category: nextCategory, lifecycle: null, finding: null })
  }

  return <div className="page-reveal">
    <PageHeader eyebrow="Risk Queue" title="Security Findings" detail="Select a control category, prioritize its unresolved findings, and open an operator-ready remediation guide without losing your place in the queue." />
    {facets.loading && !facets.data ? <LoadingState /> : facets.error || error ? <ErrorState message={facets.error ?? error ?? 'Unable To Load Findings'} retry={() => { void facets.reload(); void reload() }} /> : <section className="panel overflow-hidden" aria-label="Findings workspace">
      <div className="findings-summary-strip">
        <div><span className="detail-label">Open Findings</span><strong>{facets.data?.total ?? 0}</strong></div>
        <div><span className="detail-label">Critical</span><strong className={facets.data?.critical ? 'text-rose-500' : ''}>{facets.data?.critical ?? 0}</strong></div>
        <div><span className="detail-label">Affected Hosts</span><strong>{facets.data?.affected_hosts ?? 0}</strong></div>
        <div><span className="detail-label">Control Categories</span><strong>{categories.length}</strong></div>
      </div>

      <div className="findings-workspace-grid">
        <aside className="findings-category-rail" aria-label="Control categories">
          <div className="findings-category-heading"><div><p className="section-label">Control Categories</p><p>Choose one category to inspect its queue.</p></div><FolderOpen size={18} /></div>
          <nav className="findings-category-list">
            {categories.map((item) => {
              const categoryFacet = facets.data?.categories.find((facet) => facet.category === item.id)
              const count = categoryFacet?.count ?? 0
              const critical = categoryFacet?.critical ?? 0
              const selected = category === item.id
              return <button key={item.id} className={`finding-category-item ${selected ? 'finding-category-item-active' : ''}`} aria-pressed={selected} onClick={() => selectCategory(item.id)}>
                <span className="min-w-0 flex-1"><strong>{item.name}</strong><small>{item.detail}</small></span>
                <span className="finding-category-count"><b>{count}</b>{critical > 0 && <em>{critical} Critical</em>}</span>
              </button>
            })}
          </nav>
        </aside>

        <div className="min-w-0">
          {!selectedCategory ? <div className="findings-category-empty">
            <ShieldWarning size={26} />
            <h2>Select A Control Category</h2>
            <p>All scanner categories remain visible on the left. Choose one to search, sort, filter, export, and investigate its current findings.</p>
          </div> : <>
            <header className="findings-queue-header">
              <div><p className="section-label">{selectedCategory.name}</p><h2>{selectedCategory.name} Findings</h2><p>{selectedCategory.detail}. Showing findings from every host's latest accepted report.</p></div>
              <span className="settings-state">{data?.total ?? 0} Matching</span>
            </header>
            <SecurityTable
              key={selectedCategory.id}
              rows={findings}
              columns={columns}
              ariaLabel={`${selectedCategory.name} Findings`}
              searchText={(finding) => `${finding.title} ${finding.control_id} ${finding.hostname} ${finding.module} ${finding.actual ?? ''}`}
              rowLabel={(finding) => finding.title}
              searchPlaceholder="Search Finding, Control, Host, Or Observed State"
              filename={`lsa-${selectedCategory.id}-findings.csv`}
              pageSize={10}
              query={tableState.query}
              onQueryChange={(value) => { setSelectedFinding(null); tableState.setQuery(value) }}
              sort={tableState.sort}
              onSortChange={tableState.setSort}
              serverPagination={{ page: data?.page ?? tableState.page, pageSize: data?.pageSize ?? 10, totalRows: data?.total ?? 0, onPageChange: tableState.setPage }}
              emptyTitle="No Findings Match This View"
              emptyDetail="Adjust the severity, lifecycle, or search terms. The category remains part of the scanner catalog."
              embedded
              toolbarActions={<><select className="select-input min-h-9" aria-label="Filter by severity" value={severity} onChange={(event) => { const value = event.target.value as Severity | 'all'; setSeverity(value); updateParams({ severity: value, finding: null }) }}><option value="all">All Severities</option>{severityOrder.map((item) => <option key={item} value={item}>{item[0].toUpperCase() + item.slice(1)}</option>)}</select><select className="select-input min-h-9" aria-label="Filter by lifecycle" value={lifecycle} onChange={(event) => { const value = event.target.value; setLifecycle(value); updateParams({ lifecycle: value, finding: null }) }}><option value="all">All Lifecycles</option>{lifecycleOptions.map((item) => <option key={item} value={item}>{item[0].toUpperCase() + item.slice(1)}</option>)}</select></>}
            />
            {loading && <p className="px-5 py-2 text-xs text-stone-500" role="status">Updating Findings…</p>}
          </>}
        </div>
      </div>
    </section>}
    {selectedFinding && <FindingDetailPanel finding={selectedFinding} close={closeFinding} />}
  </div>
}
