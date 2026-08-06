import { Fingerprint, Plus, ShieldCheck, Trash } from '@phosphor-icons/react'
import { useState } from 'react'
import { api } from '../api/client'
import { useAuth } from '../auth/useAuth'
import { CreateSigningKeyPanel } from '../components/CreateSigningKeyPanel'
import { PageHeader } from '../components/PageHeader'
import { type SecurityColumn, SecurityTable } from '../components/security/SecurityTable'
import { StatusBadge } from '../components/security/StatusBadge'
import { EmptyState, ErrorState, LoadingState } from '../components/StatePanel'
import { useApi } from '../hooks/useApi'
import { useSecurityTableUrlState } from '../hooks/useSecurityTableUrlState'
import type { SigningKey } from '../types'

function keyState(key: SigningKey): 'active' | 'expired' | 'revoked' {
  if (key.revoked_at) return 'revoked'
  if (key.expires_at && new Date(key.expires_at).getTime() <= Date.now()) return 'expired'
  return 'active'
}

function formatDate(value: string | null): string {
  return value ? new Date(value).toLocaleString() : 'Never'
}

function fingerprint(value: string): string {
  return value.match(/.{1,8}/g)?.join(':') ?? value
}

export function SigningKeysPage({ embedded = false }: { embedded?: boolean } = {}) {
  const { user } = useAuth()
  const [creating, setCreating] = useState(false)
  const [confirming, setConfirming] = useState<string | null>(null)
  const [revoking, setRevoking] = useState<string | null>(null)
  const [actionError, setActionError] = useState('')
  const tableState = useSecurityTableUrlState()
  const { data, error, loading, reload } = useApi(async () => {
    const [keys, hosts] = await Promise.all([api.signingKeys(), api.hosts()])
    return { keys, hosts }
  }, [])

  async function revoke(keyId: string) {
    setRevoking(keyId)
    setActionError('')
    try {
      await api.revokeSigningKey(keyId)
      setConfirming(null)
      await reload()
    } catch (reason) {
      setActionError(reason instanceof Error ? reason.message : 'Signing key revocation failed')
    } finally {
      setRevoking(null)
    }
  }

  if (user?.role !== 'admin') return <ErrorState message="Administrator role required" retry={() => window.location.assign('/')} />
  const keys = data?.keys ?? []
  const activeCount = keys.filter((item) => keyState(item) === 'active').length
  const scopedCount = keys.filter((item) => item.host_id).length
  const hostnames = new Map((data?.hosts ?? []).map((host) => [host.id, host.hostname]))
  const createAction = <button className="button-primary" onClick={() => setCreating(true)}><Plus size={16} /> Register Key</button>
  const columns: SecurityColumn<SigningKey>[] = [
    { id: 'key', header: 'Signing Key', priority: 'primary', hideable: false, sortValue: (item) => item.name, exportValue: (item) => item.name, cell: (item) => <span className="table-primary">{item.name}<small>ID {item.id} · Created {formatDate(item.created_at)}</small></span> },
    { id: 'scope', header: 'Scope', priority: 'secondary', sortValue: (item) => item.host_id ? hostnames.get(item.host_id) ?? '' : 'All Tenant Hosts', exportValue: (item) => item.host_id ? hostnames.get(item.host_id) ?? 'Unknown Host' : 'All Tenant Hosts', cell: (item) => <span className="table-primary">{item.host_id ? hostnames.get(item.host_id) ?? 'Unknown Host' : 'All Tenant Hosts'}<small>{item.host_id ? 'Host-Scoped' : 'Tenant-Wide'}</small></span> },
    { id: 'fingerprint', header: 'Fingerprint', priority: 'detail', sortValue: (item) => item.fingerprint, exportValue: (item) => item.fingerprint, cell: (item) => <span className="inline-flex items-center gap-2 font-mono text-[10px]"><Fingerprint size={15} className="text-[#4f6f5c]" />{fingerprint(item.fingerprint)}</span> },
    { id: 'status', header: 'Status', priority: 'secondary', sortValue: keyState, exportValue: keyState, cell: (item) => { const state = keyState(item); return <StatusBadge label={state[0].toUpperCase() + state.slice(1)} tone={state === 'active' ? 'online' : state === 'expired' ? 'warning' : 'offline'} /> } },
    { id: 'expires', header: 'Expires', priority: 'detail', sortValue: (item) => item.expires_at ?? '', exportValue: (item) => item.expires_at, cell: (item) => formatDate(item.expires_at) },
    { id: 'actions', header: 'Actions', priority: 'detail', hideable: false, cell: (item) => keyState(item) === 'active' && (confirming === item.id ? <div className="flex gap-2"><button className="button-secondary min-h-9 px-3" onClick={() => setConfirming(null)}>Cancel</button><button className="button-secondary min-h-9 border-rose-900/60 px-3 text-rose-700" disabled={revoking === item.id} onClick={() => void revoke(item.id)}>{revoking === item.id ? 'Revoking' : 'Confirm'}</button></div> : <button className="icon-button" onClick={() => setConfirming(item.id)} aria-label={`Revoke ${item.name}`}><Trash size={15} /></button>) },
  ]

  return (
    <div className={embedded ? 'credential-workspace' : 'page-reveal'}>
      {embedded ? <header className="credential-workspace-heading"><div><p className="section-label">Evidence Provenance</p><h2>Signing Keys</h2><p>Register scanner public keys, constrain their scope, and verify evidence origin.</p></div>{createAction}</header> : <PageHeader eyebrow="Trust Governance" title="Signing Keys" detail="Register scanner public keys, constrain their host scope, and verify that report evidence came from a trusted controller." action={createAction} />}
      {loading ? <LoadingState /> : error ? <ErrorState message={error} retry={reload} /> : (
        <>
          <section className="credential-summary sm:grid-cols-[1.2fr_1fr_1fr]">
            <div className="border-b border-stone-800 px-6 py-5 sm:border-b-0 sm:border-r"><p className="section-label">Evidence trust</p><p className="mt-3 max-w-sm text-sm leading-6 text-stone-400">Ed25519 signatures bind each report manifest to a registered controller key.</p></div>
            <div className="border-b border-stone-800 px-6 py-5 sm:border-b-0 sm:border-r"><p className="font-mono text-2xl text-stone-100">{activeCount}</p><p className="mt-2 text-[10px] capitalize tracking-wider text-stone-600">Active keys</p></div>
            <div className="px-6 py-5"><p className="font-mono text-2xl text-stone-100">{scopedCount}</p><p className="mt-2 text-[10px] capitalize tracking-wider text-stone-600">Host-scoped keys</p></div>
          </section>
          {actionError && <p className="mb-4 rounded-xl border border-rose-900/50 bg-rose-950/20 px-4 py-3 text-xs text-rose-300">{actionError}</p>}
          {!keys.length ? <EmptyState title="No Trusted Signing Keys" detail="Generate a key on the scanner controller, then register its public half to verify future report bundles." action={createAction} /> : (
            <section className="panel overflow-hidden">
              <SecurityTable rows={keys} columns={columns} query={tableState.query} onQueryChange={tableState.setQuery} sort={tableState.sort} onSortChange={tableState.setSort} page={tableState.page} onPageChange={tableState.setPage} searchText={(item) => `${item.name} ${item.id} ${item.fingerprint} ${item.host_id ? hostnames.get(item.host_id) ?? '' : 'all tenant hosts'} ${keyState(item)}`} rowLabel={(item) => item.name} searchPlaceholder="Search Key, Scope, Fingerprint, Or Status" filename="lsa-signing-keys.csv" ariaLabel="Signing Keys" embedded />
              <div className="flex items-start gap-3 border-t border-stone-800 bg-[#f7f3eb] px-6 py-4 text-xs leading-5 text-stone-600"><ShieldCheck size={17} className="mt-0.5 shrink-0 text-[#4f6f5c]" />The platform verifies the exact manifest bytes before accepting signed evidence. Revocation blocks new submissions without invalidating historical provenance.</div>
            </section>
          )}
        </>
      )}
      {creating && <CreateSigningKeyPanel hosts={data?.hosts ?? []} close={() => setCreating(false)} created={() => void reload()} />}
    </div>
  )
}
