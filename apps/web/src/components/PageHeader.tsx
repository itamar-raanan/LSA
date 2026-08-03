import type { ReactNode } from 'react'

export function PageHeader({ eyebrow, title, detail, action }: { eyebrow: string; title: string; detail: string; action?: ReactNode }) {
  return (
    <header className="page-header">
      <div>
        <p className="page-eyebrow">{eyebrow}</p>
        <h1 className="page-title">{title}</h1>
        <p className="page-detail">{detail}</p>
      </div>
      {action && <div className="page-header-action">{action}</div>}
    </header>
  )
}
