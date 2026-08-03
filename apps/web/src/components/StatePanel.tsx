import { ArrowClockwise, Database, WarningCircle } from '@phosphor-icons/react'

export function LoadingState() {
  return (
    <div className="grid gap-4" aria-label="Loading data" aria-busy="true">
      <div className="grid grid-cols-3 gap-3"><div className="skeleton h-20 rounded-2xl" /><div className="skeleton h-20 rounded-2xl" /><div className="skeleton h-20 rounded-2xl" /></div>
      <div className="grid gap-4 md:grid-cols-[1.45fr_0.75fr]">
        <div className="skeleton h-72 rounded-[20px]" />
        <div className="skeleton h-72 rounded-[20px]" />
      </div>
    </div>
  )
}

export function ErrorState({ message, retry }: { message: string; retry: () => void }) {
  return (
    <div className="state-panel border-rose-900/40 bg-rose-950/10" role="alert">
      <WarningCircle size={25} weight="duotone" className="text-rose-400" />
      <div className="min-w-0 flex-1">
        <h2 className="text-sm font-semibold text-stone-100">Data could not be loaded</h2>
        <p className="mt-1 text-sm leading-6 text-stone-400">{message}</p>
      </div>
      <button className="button-secondary" onClick={retry}>
        <ArrowClockwise size={16} /> Retry
      </button>
    </div>
  )
}

export function EmptyState({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="panel flex min-h-72 flex-col items-center justify-center overflow-hidden px-6 py-16 text-center">
      <div className="mb-5 grid size-12 place-items-center rounded-[14px] border border-[#b8c5ba] bg-[#edf1eb] text-[#4f6f5c]">
        <Database size={22} weight="duotone" />
      </div>
      <h2 className="text-base font-semibold text-stone-100">{title}</h2>
      <p className="mt-2 max-w-md text-sm leading-6 text-stone-500">{detail}</p>
    </div>
  )
}
