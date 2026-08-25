import { Gear, MagnifyingGlass, Package } from '@phosphor-icons/react'
import { useMemo, useState } from 'react'
import { api } from '../api/client'
import { useApi } from '../hooks/useApi'
import { formatDate } from '../lib/dateTime'
import type { ApplicationInventoryItem } from '../types'

type InventoryKind = 'all' | ApplicationInventoryItem['kind']

function state(item: ApplicationInventoryItem) {
  if (item.kind === 'package') return item.status
  if (item.running) return 'Running'
  if (item.enabled) return 'Enabled'
  return item.status
}

export function ApplicationInventory({ hostId }: { hostId: string }) {
  const inventoryState = useApi(() => api.applications(hostId), [hostId])
  const [search, setSearch] = useState('')
  const [kind, setKind] = useState<InventoryKind>('all')
  const [visibleCount, setVisibleCount] = useState(100)
  const applications = useMemo(() => {
    const query = search.trim().toLowerCase()
    return (inventoryState.data ?? []).filter((item) => (
      (kind === 'all' || item.kind === kind)
      && (!query || [item.name, item.version, item.publisher, item.description].some((value) => value?.toLowerCase().includes(query)))
    ))
  }, [inventoryState.data, kind, search])
  const packageCount = inventoryState.data?.filter((item) => item.kind === 'package').length ?? 0
  const serviceCount = inventoryState.data?.filter((item) => item.kind === 'service').length ?? 0
  const visibleApplications = applications.slice(0, visibleCount)

  return <section className="panel mt-4 overflow-hidden">
    <div className="flex flex-col gap-5 px-6 py-5 md:flex-row md:items-end md:justify-between md:px-8">
      <div><p className="section-label">Application inventory</p><p className="mt-2 text-xs text-stone-500">Installed packages and systemd services from the latest accepted report.</p></div>
      <div className="flex flex-wrap gap-2">
        {([['all', `All ${packageCount + serviceCount}`], ['package', `Packages ${packageCount}`], ['service', `Services ${serviceCount}`]] as const).map(([value, label]) => <button key={value} className={kind === value ? 'filter-chip filter-chip-active' : 'filter-chip'} aria-pressed={kind === value} onClick={() => { setKind(value); setVisibleCount(100) }}>{label}</button>)}
      </div>
    </div>
    <div className="border-t border-stone-200 px-6 py-4 md:px-8">
      <label className="relative block max-w-md"><span className="sr-only">Search application inventory</span><MagnifyingGlass className="absolute left-3 top-1/2 -translate-y-1/2 text-stone-600" size={16} /><input className="search-input" placeholder="Search name, version, publisher, or description" value={search} onChange={(event) => { setSearch(event.target.value); setVisibleCount(100) }} /></label>
    </div>
    {inventoryState.loading ? <div className="skeleton m-6 h-40 rounded-2xl" /> : inventoryState.error ? <div className="p-6 text-sm text-rose-700">{inventoryState.error}</div> : !inventoryState.data?.length ? <div className="border-t border-stone-200 p-10 text-center text-sm text-stone-500">No application inventory has been reported yet.</div> : !applications.length ? <div className="border-t border-stone-200 p-10 text-center text-sm text-stone-500">No inventory items match this filter.</div> : <div className="max-h-[34rem] overflow-auto border-t border-stone-200">
      <table className="data-table min-w-[760px]">
        <thead><tr><th>Application</th><th>Type</th><th>Version</th><th>State</th><th>Source</th><th>Last observed</th></tr></thead>
        <tbody>{visibleApplications.map((item) => <tr key={item.id}>
          <td><span className="flex items-center gap-2 font-medium text-stone-800">{item.kind === 'package' ? <Package size={15} className="text-[#4f6f5c]" /> : <Gear size={15} className="text-[#4f6f5c]" />}{item.name}</span>{item.description && <span className="table-subtitle max-w-md truncate">{item.description}</span>}</td>
          <td className="capitalize">{item.kind}</td>
          <td className="font-mono text-xs">{item.version ?? '—'}{item.architecture && <span className="table-subtitle">{item.architecture}</span>}</td>
          <td><span className={item.running ? 'text-[#4f6f5c]' : 'text-stone-400'}>{state(item)}</span>{item.kind === 'service' && <span className="table-subtitle">{item.enabled ? 'enabled at boot' : 'not enabled at boot'}</span>}</td>
          <td className="font-mono text-xs capitalize text-stone-500">{item.source}</td>
          <td className="font-mono text-xs text-stone-500">{formatDate(item.last_seen_at)}</td>
        </tr>)}</tbody>
      </table>
      {visibleApplications.length < applications.length && <div className="flex items-center justify-between border-t border-stone-200 px-6 py-4"><p className="font-mono text-[10px] text-stone-600">Showing {visibleApplications.length} of {applications.length}</p><button className="button-secondary min-h-9 px-3" onClick={() => setVisibleCount((value) => value + 100)}>Show 100 more</button></div>}
    </div>}
  </section>
}
