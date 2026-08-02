export function BrandMark({ compact = false }: { compact?: boolean }) {
  return (
    <div className="flex items-center gap-3">
      <div className="brand-mark" aria-hidden="true">
        <span />
        <span />
        <span />
      </div>
      {!compact && (
        <div>
          <p className="text-[13px] font-semibold tracking-[-0.02em] text-stone-100">Linux Security Auditor</p>
          <p className="mt-0.5 font-mono text-[9px] uppercase tracking-[0.18em] text-stone-500">Fleet intelligence</p>
        </div>
      )}
    </div>
  )
}

