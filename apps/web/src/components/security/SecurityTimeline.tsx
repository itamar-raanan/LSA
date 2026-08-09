import type { LucideIcon } from 'lucide-react'
import { Clock3 } from 'lucide-react'
import { Link } from 'react-router-dom'
import { formatCompactDateTime } from '../../lib/dateTime'
import { cn } from '../../lib/utils'

export interface TimelineEvent {
  id: string
  title: string
  detail: string
  timestamp: string | null
  tone?: 'critical' | 'high' | 'medium' | 'low' | 'success' | 'neutral'
  icon?: LucideIcon
  to?: string
}

export function SecurityTimeline({ events, empty = 'No recent activity.' }: { events: TimelineEvent[]; empty?: string }) {
  if (!events.length) return <p className="px-5 py-10 text-center text-xs text-slate-500">{empty}</p>
  return <ol className="security-timeline">{events.map((event) => {
    const Icon = event.icon ?? Clock3
    const content = <>
      <span className={cn('timeline-icon', `timeline-${event.tone ?? 'neutral'}`)}><Icon size={14} /></span>
      <div className="min-w-0 flex-1"><p className="truncate text-xs font-medium text-slate-200">{event.title}</p><p className="mt-1 truncate text-[11px] text-slate-500">{event.detail}</p></div>
      <time className="shrink-0 font-mono text-[9px] text-slate-600" dateTime={event.timestamp ?? undefined}>{formatCompactDateTime(event.timestamp)}</time>
    </>
    return <li key={event.id}>{event.to ? <Link to={event.to} className="timeline-event">{content}</Link> : <div className="timeline-event">{content}</div>}</li>
  })}</ol>
}
