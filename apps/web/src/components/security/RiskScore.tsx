import { cn } from '../../lib/utils'

function toneFor(value: number) {
  if (value >= 90) return 'healthy'
  if (value >= 75) return 'medium'
  if (value >= 55) return 'high'
  return 'critical'
}

export function RiskScore({ value, label = 'Security score', size = 'lg' }: { value: number; label?: string; size?: 'sm' | 'lg' }) {
  const clamped = Math.max(0, Math.min(value, 100))
  return (
    <div className={cn('risk-score', `risk-score-${size}`, `risk-score-${toneFor(clamped)}`)} style={{ '--score': `${clamped * 3.6}deg` } as React.CSSProperties}>
      <div className="risk-score-inner">
        <strong>{value.toFixed(size === 'sm' ? 0 : 1)}</strong>
        <span>{label}</span>
      </div>
    </div>
  )
}
