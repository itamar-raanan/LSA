import { ArrowLeft, Copy, HardDrive, Network, ShieldCheck } from '@phosphor-icons/react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api/client'
import { PageHeader } from '../components/PageHeader'
import { SeverityBadge } from '../components/SeverityBadge'
import { ErrorState, LoadingState } from '../components/StatePanel'
import { useApi } from '../hooks/useApi'

export function HostDetailPage() {
  const { hostId = '' } = useParams()
  const hostState = useApi(() => api.host(hostId), [hostId])
  const findingState = useApi(() => api.findings({ host_id: hostId }), [hostId])
  if (hostState.loading) return <LoadingState />
  if (hostState.error || !hostState.data) return <ErrorState message={hostState.error ?? 'Host not found'} retry={hostState.reload} />
  const host = hostState.data
  return (
    <div className="page-reveal">
      <Link to="/hosts" className="mb-7 inline-flex items-center gap-2 text-xs text-stone-500 hover:text-stone-200"><ArrowLeft size={15} /> Back to hosts</Link>
      <PageHeader eyebrow={`${host.os_family} ${host.os_version}`} title={host.hostname} detail={host.fqdn ?? 'No fully qualified domain name reported'} action={<span className="rounded-full border border-emerald-800/50 bg-emerald-950/30 px-3 py-1.5 font-mono text-[10px] uppercase tracking-wider text-emerald-300">Reporting</span>} />
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
            ].map(([label, value]) => <div key={label}><dt className="text-[10px] uppercase tracking-wider text-stone-600">{label}</dt><dd className="mt-2 text-sm capitalize text-stone-300">{value}</dd></div>)}
          </dl>
        </div>
        <div className="panel p-6 md:p-8">
          <p className="section-label">Current posture</p>
          <div className="mt-8 grid grid-cols-2 gap-7">
            <div><span className="font-mono text-4xl tracking-[-0.08em] text-stone-50">{host.security_score?.toFixed(1) ?? '—'}</span><p className="mt-2 text-xs text-stone-600">Security score</p></div>
            <div><span className="font-mono text-4xl tracking-[-0.08em] text-stone-50">{host.compliance_score?.toFixed(1) ?? '—'}</span><p className="mt-2 text-xs text-stone-600">Compliance</p></div>
          </div>
          <div className="mt-8 space-y-3 border-t border-stone-800 pt-6">
            <div className="flex items-center justify-between text-xs"><span className="flex items-center gap-2 text-stone-500"><ShieldCheck size={16} /> Critical findings</span><span className="font-mono text-rose-400">{host.finding_counts.critical}</span></div>
            <div className="flex items-center justify-between text-xs"><span className="flex items-center gap-2 text-stone-500"><Network size={16} /> High findings</span><span className="font-mono text-orange-300">{host.finding_counts.high}</span></div>
            <div className="flex items-center justify-between text-xs"><span className="flex items-center gap-2 text-stone-500"><HardDrive size={16} /> Last report</span><span className="font-mono text-stone-300">{host.last_scan_at ? new Date(host.last_scan_at).toLocaleDateString() : 'Never'}</span></div>
          </div>
        </div>
      </section>
      <section className="panel mt-4 overflow-hidden">
        <div className="px-6 py-5 md:px-8"><p className="section-label">Open findings</p></div>
        {findingState.loading ? <div className="skeleton m-6 h-40 rounded-2xl" /> : findingState.error ? <div className="p-6 text-sm text-rose-300">{findingState.error}</div> : !findingState.data?.length ? <div className="border-t border-stone-800 p-10 text-center text-sm text-stone-500">No open findings in the latest report.</div> : (
          <div className="divide-y divide-stone-800 border-t border-stone-800">{findingState.data.map((finding) => (
            <article key={finding.id} className="grid gap-5 px-6 py-5 md:grid-cols-[auto_1fr_auto] md:px-8">
              <SeverityBadge severity={finding.severity} />
              <div><div className="flex flex-wrap items-center gap-2"><p className="text-sm font-medium text-stone-200">{finding.title}</p><span className="font-mono text-[9px] text-stone-600">{finding.control_id}</span></div><p className="mt-2 text-xs leading-5 text-stone-500">{finding.remediation_summary ?? 'No remediation guidance supplied.'}</p></div>
              {finding.remediation_commands[0] && <button className="icon-button" aria-label="Copy remediation command" onClick={() => void navigator.clipboard.writeText(finding.remediation_commands[0])}><Copy size={16} /></button>}
            </article>
          ))}</div>
        )}
      </section>
    </div>
  )
}

