import { CaretDown, Check, Copy, Funnel } from '@phosphor-icons/react'
import { useMemo, useState } from 'react'
import { api } from '../api/client'
import { PageHeader } from '../components/PageHeader'
import { SeverityBadge } from '../components/SeverityBadge'
import { EmptyState, ErrorState, LoadingState } from '../components/StatePanel'
import { useApi } from '../hooks/useApi'

const categoryCatalog = [
  { id: 'accounts', name: 'Accounts', detail: 'Local identities and privileged UIDs' },
  { id: 'audit', name: 'Audit', detail: 'Linux audit subsystem and event capture' },
  { id: 'filesystem', name: 'Filesystem', detail: 'Ownership and permissions on sensitive files' },
  { id: 'kernel', name: 'Kernel', detail: 'Runtime hardening and process isolation' },
  { id: 'logging', name: 'Logging', detail: 'Persistent system journal and log posture' },
  { id: 'mandatory_access', name: 'Mandatory access', detail: 'AppArmor policy enforcement' },
  { id: 'network', name: 'Network', detail: 'Firewall, listeners, and packet forwarding' },
  { id: 'packages', name: 'Packages', detail: 'Required security software' },
  { id: 'services', name: 'Services', detail: 'Enabled and active system services' },
  { id: 'ssh', name: 'SSH', detail: 'Remote access authentication and exposure' },
  { id: 'time', name: 'Time synchronization', detail: 'Trusted and synchronized system time' },
  { id: 'updates', name: 'Updates', detail: 'Repositories, patching, and reboot posture' },
]

export function FindingsPage() {
  const [severity, setSeverity] = useState('')
  const [category, setCategory] = useState<string | null>(null)
  const [expanded, setExpanded] = useState<string | null>(null)
  const [copied, setCopied] = useState<string | null>(null)
  const { data, error, loading, reload } = useApi(() => api.findings(), [])
  const categories = useMemo(() => {
    const known = new Set(categoryCatalog.map((item) => item.id))
    const discovered = [...new Set((data ?? []).map((item) => item.category))]
      .filter((item) => !known.has(item))
      .map((item) => ({ id: item, name: item.replaceAll('_', ' '), detail: 'Scanner-reported control category' }))
    return [...categoryCatalog, ...discovered]
  }, [data])
  const visible = (data ?? []).filter((item) => item.category === category && (!severity || item.severity === severity))

  async function copyCommand(id: string, command: string) {
    await navigator.clipboard.writeText(command)
    setCopied(id)
    window.setTimeout(() => setCopied(null), 1600)
  }

  return <div className="page-reveal">
    <PageHeader eyebrow="Risk queue" title="Findings by control category" detail="Start with the complete control surface, then open a category to inspect relevant unresolved findings." />
    {loading ? <LoadingState /> : error ? <ErrorState message={error} retry={reload} /> : <>
      <section aria-label="Control categories">
        <div className="mb-4 flex items-end justify-between gap-4"><div><p className="section-label">Control categories</p><p className="mt-2 text-xs text-stone-600">Select a category to reveal its current findings.</p></div><p className="font-mono text-[10px] capitalize tracking-[.12em] text-stone-600">{data?.length ?? 0} open total</p></div>
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          {categories.map((item) => {
            const findings = (data ?? []).filter((finding) => finding.category === item.id)
            const critical = findings.filter((finding) => finding.severity === 'critical').length
            const selected = category === item.id
            return <button key={item.id} className={`category-tile ${selected ? 'category-tile-active' : ''}`} aria-pressed={selected} onClick={() => { setCategory(selected ? null : item.id); setExpanded(null) }}>
              <div className="flex items-start justify-between gap-4"><div><p className="text-sm font-medium capitalize text-stone-200">{item.name}</p><p className="mt-1.5 line-clamp-2 text-left text-[11px] leading-[1.55] text-stone-600">{item.detail}</p></div><span className="font-mono text-2xl tracking-[-.06em] text-stone-300">{findings.length}</span></div>
              <div className="mt-4 flex items-center justify-between border-t border-white/[.06] pt-3 font-mono text-[8px] capitalize tracking-[.1em] text-stone-700"><span>{selected ? 'Selected' : 'Open findings'}</span><span className={critical ? 'text-rose-400' : ''}>{critical} critical</span></div>
            </button>
          })}
        </div>
      </section>
      {category && <section className="mt-8">
        <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between"><div><p className="section-label">{categories.find((item) => item.id === category)?.name}</p><p className="mt-2 text-sm text-stone-400">Relevant findings from every host's latest report</p></div><div className="flex items-center gap-3"><Funnel size={16} className="text-stone-600" /><select className="select-input" aria-label="Filter by severity" value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></div></div>
        {!visible.length ? <EmptyState title="No findings in this category" detail="This category has no open findings for the selected severity. Its controls remain part of the scanner catalog." /> : <div className="panel overflow-hidden divide-y divide-stone-800">
          {visible.map((finding) => {
            const isExpanded = expanded === finding.id
            return <article key={finding.id}>
              <button className="grid w-full grid-cols-[auto_1fr_auto] items-start gap-4 px-5 py-5 text-left transition hover:bg-stone-800/25 md:grid-cols-[100px_1fr_160px_auto] md:items-center md:px-7" onClick={() => setExpanded(isExpanded ? null : finding.id)}>
                <SeverityBadge severity={finding.severity} />
                <div className="min-w-0"><p className="truncate text-sm font-medium text-stone-200">{finding.title}</p><p className="mt-1 font-mono text-[10px] text-stone-600">{finding.control_id} · {finding.module}</p></div>
                <div className="hidden md:block"><p className="text-xs text-stone-400">{finding.hostname}</p><p className="mt-1 text-[10px] capitalize text-stone-700">{finding.lifecycle}</p></div>
                <CaretDown size={16} className={`mt-1 text-stone-600 transition-transform ${isExpanded ? 'rotate-180' : ''}`} />
              </button>
              {isExpanded && <div className="border-t border-stone-800 bg-[#f7f3eb] px-5 py-6 md:px-7">
                <div className="grid gap-7 lg:grid-cols-2"><div><p className="detail-label">Observed</p><pre className="evidence-block">{finding.actual ?? 'No observed value supplied'}</pre></div><div><p className="detail-label">Expected</p><pre className="evidence-block">{finding.expected ?? 'No expected value supplied'}</pre></div></div>
                <div className="mt-7 border-t border-stone-800 pt-6"><p className="detail-label">Remediation</p><p className="mt-3 text-sm leading-6 text-stone-400">{finding.remediation_summary ?? 'No remediation guidance supplied.'}</p>{finding.remediation_commands.map((command) => <div key={command} className="mt-4 flex items-center gap-3 rounded-xl border border-stone-800 bg-[#eee8dd] px-4 py-3"><code className="min-w-0 flex-1 overflow-x-auto font-mono text-xs text-[#4f6f5c]">{command}</code><button className="icon-button shrink-0" aria-label="Copy command" onClick={() => void copyCommand(finding.id, command)}>{copied === finding.id ? <Check size={16} /> : <Copy size={16} />}</button></div>)}</div>
              </div>}
            </article>
          })}
        </div>}
      </section>}
    </>}
  </div>
}
