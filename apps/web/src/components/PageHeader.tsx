import type { ReactNode } from 'react'

export function PageHeader({ eyebrow, title, detail, action }: { eyebrow: string; title: string; detail: string; action?: ReactNode }) {
  return (
    <header className="mb-8 flex flex-col gap-5 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-emerald-400">{eyebrow}</p>
        <h1 className="mt-3 text-[32px] font-medium leading-none tracking-[-0.055em] text-stone-50 md:text-[38px]">{title}</h1>
        <p className="mt-3 max-w-[65ch] text-sm leading-6 text-stone-500">{detail}</p>
      </div>
      {action}
    </header>
  )
}

