import { ArrowRight, ClockCounterClockwise, HardDrives, Pulse, ShieldWarning } from '@phosphor-icons/react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import { ErrorState, LoadingState, EmptyState } from '../components/StatePanel'
import { PageHeader } from '../components/PageHeader'
import { ScoreRing } from '../components/ScoreRing'
import { useApi } from '../hooks/useApi'

const severityRows = [
  { key: 'critical', label: 'Critical', color: 'bg-rose-500' },
  { key: 'high', label: 'High', color: 'bg-orange-400' },
  { key: 'medium', label: 'Medium', color: 'bg-amber-300' },
  { key: 'low', label: 'Low', color: 'bg-sky-400' },
] as const

const postureStats = [
  ['Reporting', HardDrives],
  ['Healthy', Pulse],
  ['Critical', ShieldWarning],
  ['Stale', ClockCounterClockwise],
] as const

export function DashboardPage() {
  const { data, error, loading, reload } = useApi(() => api.dashboard(), [])
  if (loading) return <><PageHeader eyebrow="Fleet posture" title="Security overview" detail="Loading the latest accepted reports." /><LoadingState /></>
  if (error) return <><PageHeader eyebrow="Fleet posture" title="Security overview" detail="Current security and compliance state." /><ErrorState message={error} retry={reload} /></>
  if (!data || data.total_hosts === 0) return <><PageHeader eyebrow="Fleet posture" title="Security overview" detail="Current security and compliance state." /><EmptyState title="No hosts have reported yet" detail="Run the scanner in upload mode or import an offline report bundle to establish the fleet baseline." /></>

  const maxFindings = Math.max(...severityRows.map(({ key }) => data.finding_counts[key] ?? 0), 1)
  const postureLabel = data.overall_security_score >= 90 ? 'Strong posture' : data.overall_security_score >= 75 ? 'Attention required' : 'Elevated exposure'
  const postureTone = data.overall_security_score >= 90 ? 'text-emerald-300' : data.overall_security_score >= 75 ? 'text-amber-300' : 'text-rose-300'
  return (
    <div className="page-reveal">
      <PageHeader
        eyebrow="Fleet posture"
        title="Security overview"
        detail="A live view of accepted evidence across every reporting Linux host."
        action={<Link to="/reports" className="button-secondary">Import report <ArrowRight size={16} /></Link>}
      />

      <section className="grid gap-4 xl:grid-cols-[1.35fr_0.65fr]">
        <div className="panel relative overflow-hidden p-6 md:p-8">
          <div className="absolute -right-20 -top-24 size-80 rounded-full border border-emerald-800/10 opacity-50 [background:radial-gradient(circle,rgba(76,145,103,.16),transparent_68%)]" />
          <div className="relative flex flex-col gap-8 md:flex-row md:items-center md:justify-between">
            <div>
              <div className="flex items-center gap-3"><p className="section-label">Overall security score</p><span className={`font-mono text-[9px] uppercase tracking-[.1em] ${postureTone}`}>{postureLabel}</span></div>
              <div className="mt-5 flex items-end gap-3">
                <strong className="font-mono text-6xl font-medium tracking-[-0.09em] text-stone-50 md:text-7xl">{data.overall_security_score.toFixed(1)}</strong>
                <span className="mb-2 text-sm text-stone-600">/ 100</span>
              </div>
              <p className="mt-5 max-w-[48ch] text-sm leading-6 text-stone-400">The estate is measured from the most recent accepted report for each host. Older evidence remains available in report history.</p>
            </div>
            <ScoreRing value={data.compliance_score} label="Compliance" />
          </div>
          <div className="relative mt-8 grid grid-cols-2 divide-x divide-stone-800 border-t border-stone-800 pt-6 sm:grid-cols-4">
            {postureStats.map(([label, Icon], index) => {
              const value = [data.total_hosts, data.healthy_hosts, data.critical_hosts, data.stale_hosts][index]
              return (
              <div key={String(label)} className={`px-4 first:pl-0 ${index > 1 ? 'mt-5 border-t border-stone-800 pt-5 sm:mt-0 sm:border-t-0 sm:pt-0' : ''}`}>
                <Icon size={17} weight="duotone" className="mb-3 text-stone-500" />
                <p className="font-mono text-2xl tracking-[-0.06em] text-stone-100">{value}</p>
                <p className="mt-1 text-[11px] text-stone-600">{label as string}</p>
              </div>
              )
            })}
          </div>
        </div>

        <div className="panel p-6 md:p-8">
          <div className="flex items-center justify-between"><p className="section-label">Open findings</p><span className="font-mono text-[10px] text-stone-600">LATEST SCANS</span></div>
          <div className="mt-8 space-y-6">
            {severityRows.map(({ key, label, color }) => {
              const value = data.finding_counts[key] ?? 0
              return (
                <div key={key}>
                  <div className="mb-2 flex items-center justify-between text-xs"><span className="text-stone-400">{label}</span><span className="font-mono text-stone-200">{value}</span></div>
                  <div className="h-1.5 overflow-hidden rounded-full bg-stone-800"><div className={`h-full rounded-full ${color} transition-[transform] duration-700 origin-left`} style={{ transform: `scaleX(${value / maxFindings})` }} /></div>
                </div>
              )
            })}
          </div>
          <Link to="/findings" className="mt-8 flex items-center justify-between border-t border-stone-800 pt-5 text-xs text-stone-400 transition hover:text-stone-100">Review finding queue <ArrowRight size={15} /></Link>
        </div>
      </section>

      <section className="mt-4 grid gap-4 xl:grid-cols-[1fr_0.72fr]">
        <div className="panel overflow-hidden">
          <div className="flex items-center justify-between px-6 py-5 md:px-8"><div><p className="section-label">Highest-risk hosts</p><p className="mt-2 text-xs text-stone-600">Prioritized by current security score</p></div><Link to="/hosts" className="text-xs text-emerald-400 hover:text-emerald-300">View all</Link></div>
          <div className="divide-y divide-stone-800 border-t border-stone-800">
            {data.highest_risk_hosts.map((host) => (
              <Link to={`/hosts/${host.id}`} key={host.id} className="group grid grid-cols-[1fr_auto] items-center gap-5 px-6 py-4 transition hover:bg-stone-800/30 md:grid-cols-[1.2fr_0.7fr_0.45fr] md:px-8">
                <div className="min-w-0"><p className="truncate text-sm font-medium text-stone-200 group-hover:text-white">{host.hostname}</p><p className="mt-1 truncate font-mono text-[10px] text-stone-600">{host.ip_addresses[0] ?? 'No address'} · {host.os_family.toUpperCase()} {host.os_version}</p></div>
                <span className="hidden text-xs text-stone-500 md:block">{host.tags.environment ?? 'Unassigned'}</span>
                <div className="flex items-center justify-end gap-3"><div className="score-track"><span style={{ transform: `scaleX(${(host.security_score ?? 0) / 100})` }} /></div><div className="text-right"><strong className="font-mono text-lg font-medium text-stone-100">{host.security_score?.toFixed(1) ?? '—'}</strong><p className="text-[9px] uppercase tracking-widest text-stone-700">score</p></div></div>
              </Link>
            ))}
          </div>
        </div>

        <div className="panel p-6 md:p-8">
          <p className="section-label">Operating systems</p>
          <div className="mt-8 flex h-3 overflow-hidden rounded-full bg-stone-800">
            {Object.entries(data.os_distribution).map(([name, value], index) => (
              <div key={name} className={['bg-emerald-500', 'bg-emerald-300', 'bg-teal-700'][index % 3]} style={{ width: `${(value / data.total_hosts) * 100}%` }} />
            ))}
          </div>
          <div className="mt-7 space-y-4">
            {Object.entries(data.os_distribution).map(([name, value], index) => (
              <div key={name} className="flex items-center justify-between text-xs"><span className="flex items-center gap-2 capitalize text-stone-400"><span className={`size-1.5 rounded-full ${['bg-emerald-500', 'bg-emerald-300', 'bg-teal-700'][index % 3]}`} />{name}</span><span className="font-mono text-stone-300">{value}</span></div>
            ))}
          </div>
          <div className="mt-8 border-t border-stone-800 pt-5"><p className="text-xs leading-5 text-stone-600">Only Debian, Ubuntu, and the RHEL family are accepted by report contract v1.</p></div>
        </div>
      </section>
    </div>
  )
}
