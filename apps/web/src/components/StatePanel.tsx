import { ArrowClockwise, Database, WarningCircle } from '@phosphor-icons/react'
import type { ReactNode } from 'react'

type LoadingVariant = 'dashboard' | 'table' | 'detail' | 'settings'

export function LoadingState({ variant = 'dashboard' }: { variant?: LoadingVariant }) {
  return (
    <div className={`loading-state loading-state-${variant}`} aria-label="Loading data" aria-busy="true" role="status">
      <span className="sr-only">Loading Current Console Data</span>
      {variant === 'dashboard' && <><div className="loading-metric-row">{[0, 1, 2, 3].map((item) => <div key={item} className="skeleton loading-metric" />)}</div><div className="loading-dashboard-panels"><div className="skeleton" /><div className="skeleton" /></div></>}
      {variant === 'table' && <div className="loading-table"><div className="skeleton loading-table-toolbar" />{[0, 1, 2, 3, 4, 5].map((item) => <div key={item} className="loading-table-row"><span className="skeleton" /><span className="skeleton" /><span className="skeleton" /></div>)}</div>}
      {variant === 'detail' && <><div className="skeleton loading-detail-heading" /><div className="loading-detail-grid"><div className="skeleton" /><div className="skeleton" /></div><div className="skeleton loading-detail-body" /></>}
      {variant === 'settings' && <div className="loading-settings"><div className="skeleton" /><div className="loading-settings-content"><div className="skeleton" />{[0, 1, 2].map((item) => <div key={item} className="skeleton" />)}</div></div>}
    </div>
  )
}

export function ErrorState({ message, retry }: { message: string; retry: () => void }) {
  return (
    <div className="state-panel state-panel-error" role="alert">
      <WarningCircle size={25} weight="duotone" />
      <div className="min-w-0 flex-1">
        <h2>Data Could Not Be Loaded</h2>
        <p>{message}</p>
      </div>
      <button className="button-secondary" onClick={retry}>
        <ArrowClockwise size={16} /> Retry
      </button>
    </div>
  )
}

export function EmptyState({ title, detail, action }: { title: string; detail: string; action?: ReactNode }) {
  return (
    <div className="panel empty-state">
      <div className="empty-state-icon">
        <Database size={22} weight="duotone" />
      </div>
      <h2>{title}</h2>
      <p>{detail}</p>
      {action && <div className="empty-state-action">{action}</div>}
    </div>
  )
}
