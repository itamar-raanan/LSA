import { ArrowDownRight, ArrowUpRight, Minus } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { cn } from '../../lib/utils'

type MetricTone = 'neutral' | 'critical' | 'high' | 'medium' | 'low' | 'success'

export function SecurityMetricCard({ title, value, detail, trend, tone = 'neutral', icon: Icon }: { title: string; value: string | number; detail?: string; trend?: number | null; tone?: MetricTone; icon: LucideIcon }) {
  const TrendIcon = trend == null || trend === 0 ? Minus : trend > 0 ? ArrowUpRight : ArrowDownRight
  return (
    <article className={cn('security-metric-card', `metric-tone-${tone}`)}>
      <div className="flex items-start justify-between gap-4">
        <div className="metric-icon"><Icon size={17} /></div>
        {trend != null && <span className="metric-trend"><TrendIcon size={13} />{trend === 0 ? 'No change' : `${Math.abs(trend)}%`}</span>}
      </div>
      <p className="metric-value">{value}</p>
      <p className="metric-title">{title}</p>
      {detail && <p className="metric-detail">{detail}</p>}
    </article>
  )
}
