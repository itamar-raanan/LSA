import { Activity, AlertTriangle, ArrowRight, CalendarClock, FileWarning, Server, ShieldCheck, ShieldX } from 'lucide-react'
import { lazy, Suspense } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import { useAuth } from '../auth/useAuth'
import { PageHeader } from '../components/PageHeader'
import { RiskScore } from '../components/security/RiskScore'
import { SecurityMetricCard } from '../components/security/SecurityMetricCard'
import { SecurityTimeline } from '../components/security/SecurityTimeline'
import { StatusBadge } from '../components/security/StatusBadge'
import { SeverityBadge } from '../components/SeverityBadge'
import { EmptyState, ErrorState, LoadingState } from '../components/StatePanel'
import { Button } from '../components/ui/Button'
import { useApi } from '../hooks/useApi'
import type { Severity } from '../types'

const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
const severityColors: Record<Severity, string> = { critical: '#ef476f', high: '#f59e55', medium: '#e3bd56', low: '#4aa3df', info: '#64748b' }
const DashboardChart = lazy(() => import('../components/security/DashboardChart'))

export function DashboardPage() {
  const { user } = useAuth()
  const { data, error, loading, reload } = useApi(async () => {
    const [dashboard, hosts, findings, certificate] = await Promise.all([
      api.dashboard(), api.hosts(), api.findings(), user?.role === 'admin' ? api.tlsCertificate().catch(() => null) : Promise.resolve(null),
    ])
    return { dashboard, hosts, findings, certificate }
  }, [user?.role])

  if (loading) return <><PageHeader eyebrow="Security operations" title="SOC overview" detail="Loading the current fleet posture and exposure queue." /><LoadingState /></>
  if (error) return <><PageHeader eyebrow="Security operations" title="SOC overview" detail="Current fleet posture and exposure queue." /><ErrorState message={error} retry={reload} /></>
  if (!data || data.dashboard.total_hosts === 0) return <><PageHeader eyebrow="Security operations" title="SOC overview" detail="Current fleet posture and exposure queue." /><EmptyState title="No telemetry available" detail="Enroll a Linux endpoint or import an offline report to establish the first fleet baseline." /></>

  const { dashboard, hosts, findings, certificate } = data
  const criticalFindings = findings.filter((finding) => finding.severity === 'critical' || finding.severity === 'high')
  const certificateDays = certificate ? Math.ceil((new Date(certificate.not_valid_after).getTime() - Date.now()) / 86_400_000) : null
  const certificateTone = certificateDays == null ? 'neutral' : certificateDays <= 14 ? 'critical' : certificateDays <= 45 ? 'medium' : 'success'
  const healthData = [
    { name: 'Healthy', value: dashboard.healthy_hosts, color: '#36b37e' },
    { name: 'At risk', value: Math.max(0, dashboard.at_risk_hosts - dashboard.critical_hosts), color: '#e3bd56' },
    { name: 'Critical', value: dashboard.critical_hosts, color: '#ef476f' },
    { name: 'Unclassified', value: Math.max(0, dashboard.total_hosts - dashboard.healthy_hosts - dashboard.at_risk_hosts), color: '#45536a' },
  ].filter((item) => item.value > 0)
  const severityData = severityOrder.map((severity) => ({ severity, name: severity[0].toUpperCase() + severity.slice(1), count: dashboard.finding_counts[severity] ?? 0, fill: severityColors[severity] }))
  const recentEvents = [...hosts].sort((a, b) => String(b.last_scan_at ?? '').localeCompare(String(a.last_scan_at ?? ''))).slice(0, 6).map((host) => ({
    id: host.id, title: `${host.hostname} reported posture`, detail: `${host.operating_system} ${host.os_version} · ${host.finding_counts.critical} critical findings`, timestamp: host.last_scan_at,
    tone: host.finding_counts.critical ? 'critical' as const : host.security_score != null && host.security_score < 75 ? 'high' as const : 'success' as const, icon: Activity,
  }))

  return <div className="page-reveal">
    <PageHeader eyebrow="Security operations" title="SOC overview" detail="Live fleet posture, exposure, and evidence activity from the latest accepted endpoint reports." action={<Button asChild><Link to="/reports">Import evidence <ArrowRight size={14} /></Link></Button>} />

    <section className="metric-grid" aria-label="Security metrics">
      <SecurityMetricCard title="Total assets" value={dashboard.total_hosts} detail={`${dashboard.healthy_hosts} healthy`} tone="neutral" icon={Server} />
      <SecurityMetricCard title="Active threats" value={dashboard.finding_counts.critical ?? 0} detail={`${dashboard.finding_counts.high ?? 0} high severity`} tone={(dashboard.finding_counts.critical ?? 0) ? 'critical' : 'success'} icon={ShieldX} />
      <SecurityMetricCard title="Vulnerable systems" value={dashboard.at_risk_hosts} detail={`${dashboard.critical_hosts} critical hosts`} tone={dashboard.critical_hosts ? 'high' : 'success'} icon={FileWarning} />
      <SecurityMetricCard title="Certificate expiry" value={certificateDays == null ? '—' : `${certificateDays}d`} detail={certificate ? certificate.subject : 'Not available'} tone={certificateTone} icon={CalendarClock} />
      <SecurityMetricCard title="Compliance score" value={`${dashboard.compliance_score.toFixed(1)}%`} detail="Latest accepted evidence" tone={dashboard.compliance_score >= 90 ? 'success' : dashboard.compliance_score >= 75 ? 'medium' : 'high'} icon={ShieldCheck} />
    </section>

    <section className="mt-4 grid gap-4 xl:grid-cols-[1.08fr_0.92fr]">
      <article className="soc-panel posture-panel">
        <div className="panel-heading"><div><p className="panel-kicker">Estate posture</p><h2>Asset health distribution</h2></div><StatusBadge label={`${dashboard.stale_hosts} stale`} tone={dashboard.stale_hosts ? 'warning' : 'online'} /></div>
        <div className="posture-content">
          <RiskScore value={dashboard.overall_security_score} />
          <div className="posture-chart" aria-label="Asset health distribution chart"><Suspense fallback={<div className="chart-skeleton" />}><DashboardChart type="health" data={healthData} /></Suspense></div>
          <div className="posture-legend">{healthData.map((item) => <div key={item.name}><span style={{ backgroundColor: item.color }} /><p><strong>{item.value}</strong><small>{item.name}</small></p></div>)}</div>
        </div>
      </article>

      <article className="soc-panel">
        <div className="panel-heading"><div><p className="panel-kicker">Exposure</p><h2>Vulnerability severity</h2></div><Link to="/findings" className="panel-link">Open queue <ArrowRight size={13} /></Link></div>
        <div className="severity-chart" aria-label="Vulnerability severity chart"><Suspense fallback={<div className="chart-skeleton" />}><DashboardChart type="severity" data={severityData} /></Suspense></div>
      </article>
    </section>

    <section className="mt-4 grid gap-4 xl:grid-cols-[1.25fr_0.75fr]">
      <article className="soc-panel overflow-hidden">
        <div className="panel-heading"><div><p className="panel-kicker">Priority queue</p><h2>Critical findings</h2></div><span className="panel-count">{criticalFindings.length} open</span></div>
        <div className="overflow-x-auto"><table className="compact-security-table"><thead><tr><th>Finding</th><th>Asset</th><th>Severity</th><th>Lifecycle</th></tr></thead><tbody>{criticalFindings.slice(0, 7).map((finding) => <tr key={finding.id}><td><Link to="/findings" className="finding-link">{finding.title}</Link><span>{finding.control_id}</span></td><td>{finding.hostname}</td><td><SeverityBadge severity={finding.severity} /></td><td><StatusBadge label={finding.lifecycle} tone={finding.lifecycle === 'new' ? 'warning' : 'neutral'} /></td></tr>)}</tbody></table>{!criticalFindings.length && <div className="grid min-h-44 place-items-center"><div className="text-center"><ShieldCheck className="mx-auto text-emerald-400" size={22} /><p className="mt-3 text-xs text-slate-300">No critical or high findings</p></div></div>}</div>
      </article>
      <article className="soc-panel overflow-hidden"><div className="panel-heading"><div><p className="panel-kicker">Telemetry</p><h2>Recent endpoint activity</h2></div></div><SecurityTimeline events={recentEvents} /></article>
    </section>

    {dashboard.critical_hosts > 0 && <div className="soc-callout soc-callout-critical"><AlertTriangle size={17} /><div><strong>{dashboard.critical_hosts} systems require immediate review</strong><p>Prioritize hosts with critical controls before their next policy cycle.</p></div><Button asChild size="sm" variant="danger"><Link to="/hosts">Review assets</Link></Button></div>}
  </div>
}
