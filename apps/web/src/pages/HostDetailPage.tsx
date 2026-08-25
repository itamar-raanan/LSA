import { ArrowLeft, CaretDown, HardDrive, Network, ShieldCheck } from '@phosphor-icons/react'
import { ShieldAlert } from 'lucide-react'
import { useState } from 'react'
import { Link, useLocation, useParams } from 'react-router-dom'
import { api } from '../api/client'
import { PageHeader } from '../components/PageHeader'
import { ApplicationInventory } from '../components/ApplicationInventory'
import { RemediationGuide } from '../components/RemediationGuide'
import { SeverityBadge } from '../components/SeverityBadge'
import { ReportHistory } from '../components/ReportHistory'
import { ErrorState, LoadingState } from '../components/StatePanel'
import { useApi } from '../hooks/useApi'
import { investigationReturn } from '../lib/investigationContext'
import { formatDate } from '../lib/dateTime'

export function HostDetailPage() {
  const { hostId = '' } = useParams()
  const location = useLocation()
  const returnContext = investigationReturn(new URLSearchParams(location.search).get('return_to'))
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null)
  const hostState = useApi(() => api.host(hostId), [hostId])
  const findingState = useApi(() => api.findings({ host_id: hostId }), [hostId])
  const vulnerabilityState = useApi(() => api.hostVulnerabilities(hostId), [hostId])
  if (hostState.loading) return <LoadingState variant="detail" />
  if (hostState.error || !hostState.data) return <ErrorState message={hostState.error ?? 'Host not found'} retry={hostState.reload} />
  const host = hostState.data
  return (
    <div className="page-reveal">
      <Link to={returnContext?.to ?? '/hosts'} className="mb-7 inline-flex items-center gap-2 text-xs text-stone-500 hover:text-stone-700"><ArrowLeft size={15} /> {returnContext ? `Return To ${returnContext.label}` : 'Back To Assets'}</Link>
      <PageHeader eyebrow={`${host.os_family} ${host.os_version}`} title={host.hostname} detail={host.fqdn ?? 'No fully qualified domain name reported'} action={<span className="rounded-full border border-[#b8c5ba] bg-[#edf1eb] px-3 py-1.5 font-mono text-[10px] capitalize tracking-wider text-[#4f6f5c]">Reporting</span>} />
      <section className="grid gap-4 lg:grid-cols-[1.3fr_0.7fr]">
        <div className="panel p-6 md:p-8">
          <p className="section-label">Identity and ownership</p>
          <dl className="mt-7 grid gap-x-10 gap-y-6 sm:grid-cols-2">
            {[
              ['Operating system', `${host.operating_system} ${host.os_version}`],
              ['Kernel', host.kernel],
              ['Architecture', host.architecture],
              ['IP address', host.ip_addresses[0] ?? 'Not reported'],
              ['Environment', host.tags.environment ?? 'Unassigned'],
              ['Owner', host.tags.owner ?? 'Unassigned'],
              ['Application', host.tags.application ?? 'Unassigned'],
              ['Criticality', host.tags.criticality ?? 'Unassigned'],
            ].map(([label, value]) => <div key={label}><dt className="text-[10px] capitalize tracking-wider text-stone-600">{label}</dt><dd className="mt-2 text-sm capitalize text-stone-700">{value}</dd></div>)}
          </dl>
        </div>
        <div className="panel p-6 md:p-8">
          <p className="section-label">Current posture</p>
          <div className="mt-8 grid grid-cols-2 gap-7">
            <div><span className="font-mono text-4xl tracking-[-0.08em] text-stone-900">{host.security_score?.toFixed(1) ?? '—'}</span><p className="mt-2 text-xs text-stone-600">Security score</p></div>
            <div><span className="font-mono text-4xl tracking-[-0.08em] text-stone-900">{host.compliance_score?.toFixed(1) ?? '—'}</span><p className="mt-2 text-xs text-stone-600">Compliance</p></div>
          </div>
          <div className="mt-8 space-y-3 border-t border-stone-200 pt-6">
            <div className="flex items-center justify-between text-xs"><span className="flex items-center gap-2 text-stone-500"><ShieldCheck size={16} /> Critical findings</span><span className="font-mono text-rose-700">{host.finding_counts.critical}</span></div>
            <div className="flex items-center justify-between text-xs"><span className="flex items-center gap-2 text-stone-500"><Network size={16} /> High findings</span><span className="font-mono text-orange-700">{host.finding_counts.high}</span></div>
            <div className="flex items-center justify-between text-xs"><span className="flex items-center gap-2 text-stone-500"><HardDrive size={16} /> Last report</span><span className="font-mono text-stone-700">{formatDate(host.last_scan_at, 'Never')}</span></div>
          </div>
        </div>
      </section>
      <section className="panel mt-4 overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-3 px-6 py-5 md:px-8"><div><p className="section-label">Application Vulnerabilities</p><p className="mt-2 text-xs text-stone-500">Active package exposures correlated from the latest cached advisory intelligence.</p></div><span className="flex items-center gap-2 font-mono text-xs text-stone-600"><ShieldAlert size={15} />{vulnerabilityState.data?.length ?? 0} Exposures</span></div>
        {vulnerabilityState.loading ? <div className="skeleton m-6 h-32 rounded-lg" /> : vulnerabilityState.error ? <div className="p-6"><ErrorState message={vulnerabilityState.error} retry={vulnerabilityState.reload} /></div> : !vulnerabilityState.data?.length ? <div className="border-t border-stone-200 p-8 text-center text-xs text-stone-500">No cached vulnerabilities match this host's installed package versions.</div> : <div className="overflow-x-auto border-t border-stone-200"><table className="data-table min-w-[800px]"><thead><tr><th>Vulnerability</th><th>Application</th><th>Severity</th><th>Fix</th><th>Priority</th><th>Last Confirmed</th></tr></thead><tbody>{vulnerabilityState.data.map((item) => <tr key={`${item.application_id}:${item.id}`}><td><span className="table-primary">{item.cve_id ?? item.id}</span><span className="table-subtitle max-w-[28rem] truncate">{item.summary || 'Security Advisory'}</span></td><td><span className="table-primary">{item.application_name}</span><span className="table-subtitle font-mono">{item.installed_version ?? 'Version Not Reported'}</span></td><td><span className={`severity-badge severity-${item.severity}`}>{item.severity}</span></td><td><span className="table-primary font-mono text-xs">{item.fixed_versions[0] ?? 'Vendor Guidance'}</span></td><td>{item.known_exploited ? <span className="kev-badge">Known Exploited</span> : <span className="table-subtitle">Standard</span>}</td><td className="font-mono text-xs">{formatDate(item.last_seen_at)}</td></tr>)}</tbody></table></div>}
      </section>
      <ApplicationInventory hostId={host.id} />
      <ReportHistory hostId={host.id} />
      <section className="panel mt-4 overflow-hidden">
        <div className="px-6 py-5 md:px-8"><p className="section-label">Open findings</p></div>
        {findingState.loading ? <div className="skeleton m-6 h-40 rounded-2xl" /> : findingState.error ? <div className="p-6 text-sm text-rose-700">{findingState.error}</div> : !findingState.data?.length ? <div className="border-t border-stone-200 p-10 text-center text-sm text-stone-500">No open findings in the latest report.</div> : (
          <div className="divide-y divide-stone-200 border-t border-stone-200">{findingState.data.map((finding) => (
            <article key={finding.id}>
              <button className="grid w-full gap-5 px-6 py-5 text-left md:grid-cols-[auto_1fr_auto] md:px-8" onClick={() => setExpandedFinding(expandedFinding === finding.id ? null : finding.id)} aria-expanded={expandedFinding === finding.id}>
                <SeverityBadge severity={finding.severity} />
                <div><div className="flex flex-wrap items-center gap-2"><p className="text-sm font-medium text-stone-800">{finding.title}</p><span className="font-mono text-[9px] text-stone-600">{finding.control_id}</span></div><p className="mt-2 text-xs leading-5 text-stone-500">{finding.remediation_summary ?? 'Open the guide to compare the current and required states.'}</p></div>
                <CaretDown size={16} className={`mt-1 text-stone-600 transition-transform ${expandedFinding === finding.id ? 'rotate-180' : ''}`} />
              </button>
              {expandedFinding === finding.id && <div className="border-t border-stone-200 bg-[#f7f3eb] px-5 py-6 md:px-8"><RemediationGuide finding={finding} /></div>}
            </article>
          ))}</div>
        )}
      </section>
    </div>
  )
}
