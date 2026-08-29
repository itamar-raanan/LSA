import { ArrowDownRight, ArrowUpRight, Minus } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { Link } from 'react-router-dom'
import { cn } from '../../lib/utils'

type MetricTone = 'neutral' | 'critical' | 'high' | 'medium' | 'low' | 'success'

export function SecurityMetricCard({ title, value, detail, trend, tone = 'neutral', icon: Icon, to }: { title: string; value: string | number; detail?: string; trend?: number | null; tone?: MetricTone; icon: LucideIcon; to?: string }) {
  const TrendIcon = trend == null || trend === 0 ? Minus : trend > 0 ? ArrowUpRight : ArrowDownRight
  const card = (
    <article className={cn('security-metric-card', `metric-tone-${tone}`)}>
      <div className="metric-copy">
        <p className="metric-value">{value}</p>
        <p className="metric-title">{title}</p>
        {detail && <p className="metric-detail">{detail}</p>}
      </div>
      <div className="metric-aside">
        <div className="metric-icon"><Icon size={15} /></div>
        {trend != null && <span className="metric-trend"><TrendIcon size={11} />{trend === 0 ? 'No change' : `${Math.abs(trend)}%`}</span>}
      </div>
    </article>
  )
  return to ? <Link className="security-metric-link" to={to} aria-label={`${title}: ${value}`}>{card}</Link> : card
}
