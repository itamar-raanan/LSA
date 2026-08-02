import { CaretDown, Check, Copy, Funnel } from '@phosphor-icons/react'
import { useState } from 'react'
import { api } from '../api/client'
import { PageHeader } from '../components/PageHeader'
import { SeverityBadge } from '../components/SeverityBadge'
import { EmptyState, ErrorState, LoadingState } from '../components/StatePanel'
import { useApi } from '../hooks/useApi'

export function FindingsPage() {
  const [severity, setSeverity] = useState('')
  const [expanded, setExpanded] = useState<string | null>(null)
  const [copied, setCopied] = useState<string | null>(null)
  const { data, error, loading, reload } = useApi(() => api.findings({ severity }), [severity])

  async function copyCommand(id: string, command: string) {
    await navigator.clipboard.writeText(command)
    setCopied(id)
    window.setTimeout(() => setCopied(null), 1600)
  }

  return (
    <div className="page-reveal">
      <PageHeader eyebrow="Risk queue" title="Open findings" detail="The current unresolved, manual, and errored controls from each host's latest report." />
      <div className="mb-4 flex items-center gap-3">
        <Funnel size={16} className="text-stone-600" />
        <select className="select-input" aria-label="Filter by severity" value={severity} onChange={(event) => setSeverity(event.target.value)}>
          <option value="">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option>
        </select>
      </div>
      {loading ? <LoadingState /> : error ? <ErrorState message={error} retry={reload} /> : !data?.length ? <EmptyState title="No findings in this view" detail="Change the severity filter or submit a report containing failed, manual, or errored controls." /> : (
        <section className="panel overflow-hidden divide-y divide-stone-800">
          {data.map((finding) => {
            const isExpanded = expanded === finding.id
            return (
              <article key={finding.id}>
                <button className="grid w-full grid-cols-[auto_1fr_auto] items-start gap-4 px-5 py-5 text-left transition hover:bg-stone-800/25 md:grid-cols-[100px_1fr_160px_auto] md:items-center md:px-7" onClick={() => setExpanded(isExpanded ? null : finding.id)}>
                  <SeverityBadge severity={finding.severity} />
                  <div className="min-w-0"><p className="truncate text-sm font-medium text-stone-200">{finding.title}</p><p className="mt-1 font-mono text-[10px] text-stone-600">{finding.control_id} · {finding.module}</p></div>
                  <div className="hidden md:block"><p className="text-xs text-stone-400">{finding.hostname}</p><p className="mt-1 text-[10px] capitalize text-stone-700">{finding.lifecycle}</p></div>
                  <CaretDown size={16} className={`mt-1 text-stone-600 transition-transform ${isExpanded ? 'rotate-180' : ''}`} />
                </button>
                {isExpanded && (
                  <div className="border-t border-stone-800 bg-[#0e120f] px-5 py-6 md:px-7">
                    <div className="grid gap-7 lg:grid-cols-2">
                      <div><p className="detail-label">Observed</p><pre className="evidence-block">{finding.actual ?? 'No observed value supplied'}</pre></div>
                      <div><p className="detail-label">Expected</p><pre className="evidence-block">{finding.expected ?? 'No expected value supplied'}</pre></div>
                    </div>
                    <div className="mt-7 border-t border-stone-800 pt-6"><p className="detail-label">Remediation</p><p className="mt-3 text-sm leading-6 text-stone-400">{finding.remediation_summary ?? 'No remediation guidance supplied.'}</p>{finding.remediation_commands.map((command) => <div key={command} className="mt-4 flex items-center gap-3 rounded-xl border border-stone-800 bg-stone-950 px-4 py-3"><code className="min-w-0 flex-1 overflow-x-auto font-mono text-xs text-emerald-200">{command}</code><button className="icon-button shrink-0" aria-label="Copy command" onClick={() => void copyCommand(finding.id, command)}>{copied === finding.id ? <Check size={16} /> : <Copy size={16} />}</button></div>)}</div>
                  </div>
                )}
              </article>
            )
          })}
        </section>
      )}
    </div>
  )
}

