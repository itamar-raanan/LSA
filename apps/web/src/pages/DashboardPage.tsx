import { Activity, ArrowRight, Database, Gauge, ShieldAlert, ShieldCheck, ShieldX, WifiOff } from 'lucide-react'
import { lazy, Suspense } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { api } from '../api/client'
import { PageHeader } from '../components/PageHeader'
import { RiskScore } from '../components/security/RiskScore'
import { SecurityMetricCard } from '../components/security/SecurityMetricCard'
import { SecurityTimeline } from '../components/security/SecurityTimeline'
import { StatusBadge } from '../components/security/StatusBadge'
import { SeverityBadge } from '../components/SeverityBadge'
import { EmptyState, ErrorState, LoadingState } from '../components/StatePanel'
import { useApi } from '../hooks/useApi'
import { withInvestigationReturn } from '../lib/investigationContext'
import type { Finding, Host, Severity } from '../types'

const severityRank: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
const DashboardChart = lazy(() => import('../components/security/DashboardChart'))

function findingUrl(finding: Finding) {
  const params = new URLSearchParams({ category: finding.category, finding: finding.id })
  return `/findings?${params}`
}

function hostRisk(host: Host) {
  return host.finding_counts.critical * 10_000 + host.finding_counts.high * 100 + (100 - (host.security_score ?? 0))
}

export function DashboardPage() {
  const location = useLocation()
  const { data, error, loading, reload } = useApi(async () => {
    const [dashboard, recentHosts, criticalFindings, highFindings] = await Promise.all([
      api.dashboard(),
      api.hostPage({ page: 0, pageSize: 6, sort: 'last_seen', direction: 'desc' }),
      api.findingPage({ severity: 'critical', page: 0, pageSize: 7, sort: 'lifecycle', direction: 'asc' }),
      api.findingPage({ severity: 'high', page: 0, pageSize: 7, sort: 'lifecycle', direction: 'asc' }),
    ])
    return { dashboard, recentHosts: recentHosts.rows, findings: [...criticalFindings.rows, ...highFindings.rows] }
  }, [])

  if (loading) return <><PageHeader eyebrow="Security Operations" title="Security Overview" detail="Loading the current fleet posture and exposure queue." /><LoadingState /></>
  if (error) return <><PageHeader eyebrow="Security Operations" title="Security Overview" detail="Current fleet posture and exposure queue." /><ErrorState message={error} retry={reload} /></>
  if (!data || data.dashboard.total_hosts === 0) return <><PageHeader eyebrow="Security Operations" title="Security Overview" detail="Current fleet posture and exposure queue." /><EmptyState title="No Telemetry Available" detail="Enroll a Linux endpoint or import an offline report to establish the first fleet baseline." /></>

  const { dashboard, recentHosts: hosts, findings } = data
  const priorityFindings = findings
    .filter((finding) => finding.severity === 'critical' || finding.severity === 'high')
    .sort((a, b) => severityRank[a.severity] - severityRank[b.severity] || Number(b.lifecycle === 'new') - Number(a.lifecycle === 'new'))
  const riskHosts = [...(dashboard.highest_risk_hosts.length ? dashboard.highest_risk_hosts : hosts)]
    .sort((a, b) => hostRisk(b) - hostRisk(a))
    .slice(0, 5)
  const healthData = [
    { name: 'Healthy', value: dashboard.healthy_hosts, color: '#4f8063' },
    { name: 'At Risk', value: Math.max(0, dashboard.at_risk_hosts - dashboard.critical_hosts), color: '#b78a32' },
    { name: 'Critical', value: dashboard.critical_hosts, color: '#b74f52' },
    { name: 'Unclassified', value: Math.max(0, dashboard.total_hosts - dashboard.healthy_hosts - dashboard.at_risk_hosts), color: '#958d80' },
  ].filter((item) => item.value > 0)
  const recentEvents = [...hosts]
    .sort((a, b) => String(b.last_scan_at ?? '').localeCompare(String(a.last_scan_at ?? '')))
    .slice(0, 6)
    .map((host) => ({
      id: host.id,
      title: `${host.hostname} Reported Posture`,
      detail: `${host.operating_system} ${host.os_version} · ${host.finding_counts.critical} Critical Findings`,
      timestamp: host.last_scan_at,
      tone: host.finding_counts.critical ? 'critical' as const : host.security_score != null && host.security_score < 75 ? 'high' as const : 'success' as const,
      icon: Activity,
      to: withInvestigationReturn(`/hosts/${host.id}`, location),
    }))
  const latestReportAt = hosts.find((host) => host.last_scan_at)?.last_scan_at ?? null
  const hostInvestigationUrl = (hostId: string) => withInvestigationReturn(`/hosts/${hostId}`, location)

  return <div className="page-reveal">
    <PageHeader eyebrow="Security Operations" title="Security Overview" detail="See what requires attention, investigate the affected systems, and confirm whether fleet posture is improving." />

    <section className="dashboard-data-context" aria-label="Dashboard Data Context">
      <div><Activity size={15} /><span><strong>Latest Accepted Posture</strong>{latestReportAt ? `Updated ${new Date(latestReportAt).toLocaleString()}` : 'No Endpoint Report Time Available'}</span></div>
      <div><Database size={15} /><span><strong>Evidence Source</strong>Server Summaries From Locally Retained Reports</span></div>
    </section>

    <section className="metric-grid dashboard-metric-grid" aria-label="Security Metrics">
      <SecurityMetricCard title="Critical Findings" value={dashboard.finding_counts.critical ?? 0} detail={`${dashboard.finding_counts.high ?? 0} High Severity Findings`} tone={(dashboard.finding_counts.critical ?? 0) ? 'critical' : 'success'} icon={ShieldAlert} to="/findings?severity=critical" />
      <SecurityMetricCard title="Affected Assets" value={dashboard.at_risk_hosts} detail={`${dashboard.critical_hosts} With Critical Exposure`} tone={dashboard.critical_hosts ? 'high' : 'success'} icon={ShieldX} to="/hosts?risk=critical" />
      <SecurityMetricCard title="Stale Reports" value={dashboard.stale_hosts} detail={`${dashboard.total_hosts - dashboard.stale_hosts} Of ${dashboard.total_hosts} Current`} tone={dashboard.stale_hosts ? 'medium' : 'success'} icon={WifiOff} to="/hosts?risk=stale" />
      <SecurityMetricCard title="Compliance Score" value={`${dashboard.compliance_score.toFixed(1)}%`} detail={`${dashboard.overall_security_score.toFixed(1)} Security Score`} tone={dashboard.compliance_score < 70 ? 'critical' : dashboard.compliance_score < 85 ? 'medium' : 'success'} icon={Gauge} to="/hosts" />
    </section>

    <section className="mt-4 grid gap-4 xl:grid-cols-[1.2fr_0.8fr]">
      <article className="soc-panel overflow-hidden">
        <div className="panel-heading"><div><p className="panel-kicker">Priority Queue</p><h2>Findings Requiring Attention</h2></div><Link to="/findings?severity=critical" className="panel-link">Open Queue <ArrowRight size={13} /></Link></div>
        <div className="overflow-x-auto"><table className="compact-security-table dashboard-priority-table"><thead><tr><th>Finding</th><th>Asset</th><th>Severity</th><th>Lifecycle</th></tr></thead><tbody>{priorityFindings.slice(0, 7).map((finding) => <tr key={finding.id}><td><Link to={findingUrl(finding)} className="finding-link">{finding.title}</Link><span>{finding.control_id}</span></td><td><Link to={hostInvestigationUrl(finding.host_id)} className="dashboard-host-link">{finding.hostname}</Link></td><td><SeverityBadge severity={finding.severity} /></td><td><StatusBadge label={finding.lifecycle} tone={finding.lifecycle === 'new' ? 'warning' : 'neutral'} /></td></tr>)}</tbody></table>{!priorityFindings.length && <div className="grid min-h-44 place-items-center"><div className="text-center"><ShieldCheck className="mx-auto text-[#4f6f5c]" size={22} /><p className="mt-3 text-xs text-slate-300">No Critical Or High Findings</p><Link to="/findings" className="panel-link mt-2">Review All Findings <ArrowRight size={13} /></Link></div></div>}</div>
      </article>

      <article className="soc-panel overflow-hidden">
        <div className="panel-heading"><div><p className="panel-kicker">Affected Assets</p><h2>Highest Risk Hosts</h2></div><Link to="/hosts?risk=critical" className="panel-link">View Assets <ArrowRight size={13} /></Link></div>
        <div className="dashboard-risk-list">{riskHosts.map((host, index) => <Link key={host.id} to={hostInvestigationUrl(host.id)} className="dashboard-risk-host">
          <span className="dashboard-risk-rank">{String(index + 1).padStart(2, '0')}</span>
          <span className="min-w-0 flex-1"><strong>{host.hostname}</strong><small>{host.operating_system} {host.os_version} · {host.finding_counts.critical} Critical</small></span>
          <span className="dashboard-risk-score"><strong>{host.security_score?.toFixed(0) ?? '—'}</strong><small>Security</small></span>
        </Link>)}</div>
      </article>
    </section>

    <section className="mt-4 grid gap-4 xl:grid-cols-[0.92fr_1.08fr]">
      <article className="soc-panel posture-panel">
        <div className="panel-heading"><div><p className="panel-kicker">Estate Posture</p><h2>Asset Health Distribution</h2></div><StatusBadge label={`${dashboard.stale_hosts} Stale`} tone={dashboard.stale_hosts ? 'warning' : 'online'} /></div>
        <div className="posture-content">
          <RiskScore value={dashboard.overall_security_score} />
          <div className="posture-chart" aria-label="Asset Health Distribution Chart"><Suspense fallback={<div className="chart-skeleton" />}><DashboardChart type="health" data={healthData} /></Suspense></div>
          <div className="posture-legend">{healthData.map((item) => <div key={item.name}><span style={{ backgroundColor: item.color }} /><p><strong>{item.value}</strong><small>{item.name}</small></p></div>)}</div>
        </div>
      </article>

      <article className="soc-panel overflow-hidden"><div className="panel-heading"><div><p className="panel-kicker">Telemetry</p><h2>Recent Endpoint Activity</h2></div><Link to="/hosts" className="panel-link">All Assets <ArrowRight size={13} /></Link></div><SecurityTimeline events={recentEvents} /></article>
    </section>
  </div>
}
