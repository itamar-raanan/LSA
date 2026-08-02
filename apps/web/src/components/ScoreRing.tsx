export function ScoreRing({ value, label }: { value: number; label: string }) {
  const clamped = Math.max(0, Math.min(value, 100))
  return (
    <div className="relative grid size-36 place-items-center rounded-full" style={{ background: `conic-gradient(#61a882 ${clamped * 3.6}deg, #2b302c 0deg)` }}>
      <div className="absolute inset-[7px] rounded-full bg-[#151916]" />
      <div className="relative text-center">
        <strong className="block font-mono text-[32px] font-medium tracking-[-0.08em] text-stone-50">{value.toFixed(1)}</strong>
        <span className="mt-1 block text-[10px] uppercase tracking-[0.16em] text-stone-500">{label}</span>
      </div>
    </div>
  )
}

