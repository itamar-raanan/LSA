export function BrandMark({ compact = false, tone = 'dark' }: { compact?: boolean; tone?: 'dark' | 'light' }) {
  return (
    <div className="flex items-center gap-3">
      <div className="brand-mark" aria-hidden="true">
        <span />
        <span />
        <span />
      </div>
      {!compact && (
        <div>
          <p className={`text-[12px] font-semibold tracking-[-0.015em] ${tone === 'light' ? 'text-stone-900' : 'text-stone-100'}`}>Linux Security Auditor</p>
          <p className={`mt-0.5 text-[9px] font-medium tracking-[0.08em] ${tone === 'light' ? 'text-stone-600' : 'text-stone-500'}`}>Fleet Intelligence</p>
        </div>
      )}
    </div>
  )
}
