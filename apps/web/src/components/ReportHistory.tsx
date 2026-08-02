import { ArrowDown, ArrowUp, ArrowsCounterClockwise } from '@phosphor-icons/react'
import { useState } from 'react'
import type { ReactNode } from 'react'
import { api } from '../api/client'
import { useApi } from '../hooks/useApi'
import type { ReportComparison } from '../types'
import { ErrorState } from './StatePanel'

export function ReportHistory({ hostId }: { hostId: string }) {
  const { data, error, loading, reload } = useApi(() => api.reports(hostId), [hostId])
  const [comparison, setComparison] = useState<ReportComparison | null>(null)
  const [comparing, setComparing] = useState<string | null>(null)
  const [comparisonError, setComparisonError] = useState('')

  async function compare(reportId: string) {
    setComparing(reportId)
    setComparisonError('')
    try {
      setComparison(await api.compareReport(reportId))
    } catch (reason) {
      setComparisonError(reason instanceof Error ? reason.message : 'Comparison failed')
    } finally {
      setComparing(null)
    }
  }

  if (loading) return <div className="skeleton h-52 rounded-[22px]" />
  if (error) return <ErrorState message={error} retry={reload} />
  if (!data?.length) return null

  return (
    <section className="panel mt-4 overflow-hidden">
      <div className="flex items-center justify-between px-6 py-5 md:px-8">
        <div><p className="section-label">Report history</p><p className="mt-2 text-xs text-stone-600">Immutable accepted evidence, newest first</p></div>
        <span className="font-mono text-[10px] text-stone-600">{data.length} REPORTS</span>
      </div>
      <div className="divide-y divide-stone-800 border-t border-stone-800">
        {data.slice(0, 8).map((report, index) => (
          <div key={report.id} className="grid items-center gap-4 px-6 py-4 sm:grid-cols-[1fr_auto_auto] md:px-8">
            <div><p className="text-sm text-stone-300">{new Date(report.generated_at).toLocaleString()}</p><p className="mt-1 font-mono text-[9px] uppercase tracking-wider text-stone-600">{report.profile} · scanner {report.scanner_version}</p></div>
            <div className="flex gap-6"><div><span className="font-mono text-sm text-stone-200">{report.security_score.toFixed(1)}</span><p className="text-[9px] uppercase tracking-wider text-stone-700">Security</p></div><div><span className="font-mono text-sm text-stone-200">{report.compliance_score.toFixed(1)}</span><p className="text-[9px] uppercase tracking-wider text-stone-700">Compliance</p></div></div>
            <button className="button-secondary min-h-9 px-3" disabled={comparing === report.id} onClick={() => void compare(report.id)}><ArrowsCounterClockwise size={14} />{index === data.length - 1 ? 'Baseline' : 'Compare'}</button>
          </div>
        ))}
      </div>
      {comparisonError && <p className="border-t border-rose-900/40 bg-rose-950/20 px-6 py-4 text-xs text-rose-300">{comparisonError}</p>}
      {comparison && (
        <div className="grid gap-6 border-t border-stone-800 bg-[#0e120f] px-6 py-6 md:grid-cols-3 md:px-8">
          <DeltaColumn label="New" items={comparison.new} icon={<ArrowUp size={15} />} color="text-rose-300" />
          <DeltaColumn label="Persistent" items={comparison.persistent} icon={<ArrowsCounterClockwise size={15} />} color="text-amber-200" />
          <DeltaColumn label="Resolved" items={comparison.resolved} icon={<ArrowDown size={15} />} color="text-emerald-300" />
        </div>
      )}
    </section>
  )
}

function DeltaColumn({ label, items, icon, color }: { label: string; items: ReportComparison['new']; icon: ReactNode; color: string }) {
  return <div><p className={`flex items-center gap-2 text-xs font-medium ${color}`}>{icon}{label} <span className="font-mono">{items.length}</span></p><div className="mt-3 space-y-2">{items.slice(0, 4).map((item) => <p key={item.control_id} className="truncate font-mono text-[9px] text-stone-600" title={item.title}>{item.control_id}</p>)}{!items.length && <p className="text-[10px] text-stone-700">None</p>}</div></div>
}
