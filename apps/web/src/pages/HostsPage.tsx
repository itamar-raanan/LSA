import { MagnifyingGlass, Plus } from '@phosphor-icons/react'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import { PageHeader } from '../components/PageHeader'
import { EnrollHostPanel } from '../components/EnrollHostPanel'
import { EmptyState, ErrorState, LoadingState } from '../components/StatePanel'
import { useApi } from '../hooks/useApi'

export function HostsPage() {
  const [search, setSearch] = useState('')
  const [enrolling, setEnrolling] = useState(false)
  const { data, error, loading, reload } = useApi(() => api.hosts(), [])
  const hosts = data?.filter((host) => host.hostname.toLowerCase().includes(search.toLowerCase())) ?? []
  return (
    <div className="page-reveal">
      <PageHeader eyebrow="Asset inventory" title="Linux hosts" detail="Persistent identities and the most recent accepted posture for every reporting server." action={<button className="button-primary" onClick={() => setEnrolling(true)}><Plus size={16} /> Enroll host</button>} />
      {loading ? <LoadingState /> : error ? <ErrorState message={error} retry={reload} /> : !data?.length ? <EmptyState title="No hosts registered" detail="A host is registered automatically when its first authenticated report is accepted." /> : (
        <section className="panel overflow-hidden">
          <div className="flex flex-col gap-4 px-5 py-5 sm:flex-row sm:items-center sm:justify-between md:px-7">
            <label className="relative block w-full sm:max-w-sm"><MagnifyingGlass className="absolute left-3 top-1/2 -translate-y-1/2 text-stone-600" size={16} /><input className="search-input" placeholder="Search hostname" value={search} onChange={(event) => setSearch(event.target.value)} /></label>
            <p className="font-mono text-[10px] uppercase tracking-[0.15em] text-stone-600">{hosts.length} reporting hosts</p>
          </div>
          <div className="overflow-x-auto border-t border-stone-800">
            <table className="data-table min-w-[850px]">
              <thead><tr><th>Host</th><th>Operating system</th><th>Environment</th><th>Security</th><th>Compliance</th><th>Open risk</th></tr></thead>
              <tbody>{hosts.map((host) => (
                <tr key={host.id}>
                  <td><Link className="font-medium text-stone-200 hover:text-emerald-300" to={`/hosts/${host.id}`}>{host.hostname}</Link><span className="table-subtitle">{host.ip_addresses[0] ?? 'No address reported'}</span></td>
                  <td>{host.operating_system} {host.os_version}<span className="table-subtitle">Kernel {host.kernel}</span></td>
                  <td className="capitalize">{host.tags.environment ?? 'Unassigned'}<span className="table-subtitle">{host.tags.owner ?? 'No owner'}</span></td>
                  <td><span className="score-value">{host.security_score?.toFixed(1) ?? '—'}</span></td>
                  <td><span className="score-value">{host.compliance_score?.toFixed(1) ?? '—'}</span></td>
                  <td><span className={host.finding_counts.critical ? 'text-rose-400' : 'text-stone-300'}>{host.finding_counts.critical} critical</span><span className="table-subtitle">{host.finding_counts.high} high</span></td>
                </tr>
              ))}</tbody>
            </table>
            {!hosts.length && <div className="p-10 text-center text-sm text-stone-500">No hosts match “{search}”.</div>}
          </div>
        </section>
      )}
      {enrolling && <EnrollHostPanel close={() => setEnrolling(false)} created={() => void reload()} />}
    </div>
  )
}
