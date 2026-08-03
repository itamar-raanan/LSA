import { Circle } from 'lucide-react'
import { cn } from '../../lib/utils'

export type StatusTone = 'online' | 'offline' | 'warning' | 'critical' | 'neutral'

export function StatusBadge({ label, tone = 'neutral', pulse = false }: { label: string; tone?: StatusTone; pulse?: boolean }) {
  return <span className={cn('soc-status-badge', `soc-status-${tone}`)}><Circle size={7} fill="currentColor" className={pulse ? 'status-dot-pulse' : ''} />{label}</span>
}
