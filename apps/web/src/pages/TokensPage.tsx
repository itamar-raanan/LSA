import { Plus, ShieldCheck, Trash } from '@phosphor-icons/react'
import { useEffect, useState } from 'react'
import { api } from '../api/client'
import { CreateTokenPanel } from '../components/CreateTokenPanel'
import { PageHeader } from '../components/PageHeader'
import { EmptyState, ErrorState, LoadingState } from '../components/StatePanel'
import { useAuth } from '../auth/useAuth'
import { useApi } from '../hooks/useApi'
import type { IngestionToken } from '../types'

function tokenState(token: IngestionToken): 'active' | 'expired' | 'revoked' {
  if (token.revoked_at) return 'revoked'
  if (token.expires_at && new Date(token.expires_at).getTime() <= Date.now()) return 'expired'
  return 'active'
}

function formatDate(value: string | null): string {
  return value ? new Date(value).toLocaleString() : 'Never'
}

export function TokensPage({ embedded = false, autoCreate = false }: { embedded?: boolean; autoCreate?: boolean } = {}) {
  const { user } = useAuth()
  const [creating, setCreating] = useState(false)
  const [confirming, setConfirming] = useState<string | null>(null)
  const [revoking, setRevoking] = useState<string | null>(null)
  const [actionError, setActionError] = useState('')
  const { data, error, loading, reload } = useApi(async () => {
    const [tokens, hosts] = await Promise.all([api.tokens(), api.hosts()])
    return { tokens, hosts }
  }, [])

  useEffect(() => {
    if (autoCreate) setCreating(true)
  }, [autoCreate])

  async function revoke(tokenId: string) {
    setRevoking(tokenId)
    setActionError('')
    try {
      await api.revokeToken(tokenId)
      setConfirming(null)
      await reload()
    } catch (reason) {
      setActionError(reason instanceof Error ? reason.message : 'Token revocation failed')
    } finally {
      setRevoking(null)
    }
  }

  if (user?.role !== 'admin') return <ErrorState message="Administrator role required" retry={() => window.location.assign('/')} />
  const tokens = data?.tokens ?? []
  const activeCount = tokens.filter((token) => tokenState(token) === 'active').length
  const usedCount = tokens.filter((token) => token.last_used_at).length
  const hostnames = new Map((data?.hosts ?? []).map((host) => [host.id, host.hostname]))
  const createAction = <button className="button-primary" onClick={() => setCreating(true)}><Plus size={16} /> Issue Token</button>

  return (
    <div className={embedded ? 'credential-workspace' : 'page-reveal'}>
      {embedded ? <header className="credential-workspace-heading"><div><p className="section-label">Submission Authentication</p><h2>Ingestion Tokens</h2><p>Issue narrowly scoped credentials, inspect their activity, and revoke submission access.</p></div>{createAction}</header> : <PageHeader eyebrow="Credential Governance" title="Ingestion Tokens" detail="Issue narrowly scoped scanner credentials, inspect their activity, and revoke access without changing host identities." action={createAction} />}
      {loading ? <LoadingState /> : error ? <ErrorState message={error} retry={reload} /> : (
        <>
          <section className="credential-summary sm:grid-cols-[1.2fr_1fr_1fr]">
            <div className="border-b border-stone-800 px-6 py-5 sm:border-b-0 sm:border-r"><p className="section-label">Credential posture</p><p className="mt-3 max-w-sm text-sm leading-6 text-stone-400">Secrets are displayed once and stored as one-way hashes.</p></div>
            <div className="border-b border-stone-800 px-6 py-5 sm:border-b-0 sm:border-r"><p className="font-mono text-2xl text-stone-100">{activeCount}</p><p className="mt-2 text-[10px] capitalize tracking-wider text-stone-600">Active tokens</p></div>
            <div className="px-6 py-5"><p className="font-mono text-2xl text-stone-100">{usedCount}</p><p className="mt-2 text-[10px] capitalize tracking-wider text-stone-600">Used credentials</p></div>
          </section>
          {actionError && <p className="mb-4 rounded-xl border border-rose-900/50 bg-rose-950/20 px-4 py-3 text-xs text-rose-300">{actionError}</p>}
          {!tokens.length ? <EmptyState title="No Scanner Credentials" detail="Issue a host-scoped token before configuring the first scanner controller." action={createAction} /> : (
            <section className="panel overflow-hidden">
              <div className="overflow-x-auto">
                <table className="data-table min-w-[920px]">
                  <thead><tr><th>Credential</th><th>Scope</th><th>Status</th><th>Last used</th><th>Expires</th><th aria-label="Actions" /></tr></thead>
                  <tbody>{tokens.map((token) => {
                    const state = tokenState(token)
                    return <tr key={token.id}>
                      <td><span className="font-medium text-stone-200">{token.name}</span><span className="table-subtitle">{token.token_prefix}… · created {formatDate(token.created_at)}</span></td>
                      <td>{token.host_id ? hostnames.get(token.host_id) ?? 'Unknown host' : 'All tenant hosts'}<span className="table-subtitle">{token.host_id ? 'Host-scoped' : 'Tenant-wide'}</span></td>
                      <td><span className={`inline-flex items-center gap-2 font-mono text-[10px] capitalize tracking-wider ${state === 'active' ? 'text-[#4f6f5c]' : state === 'expired' ? 'text-amber-300' : 'text-stone-600'}`}><span className={`size-1.5 rounded-full ${state === 'active' ? 'bg-[#edf1eb]' : state === 'expired' ? 'bg-amber-400' : 'bg-stone-700'}`} />{state}</span></td>
                      <td>{formatDate(token.last_used_at)}</td><td>{formatDate(token.expires_at)}</td>
                      <td className="text-right">{state === 'active' && (confirming === token.id ? <div className="flex justify-end gap-2"><button className="button-secondary min-h-9 px-3" onClick={() => setConfirming(null)}>Cancel</button><button className="button-secondary min-h-9 border-rose-900/60 px-3 text-rose-300" disabled={revoking === token.id} onClick={() => void revoke(token.id)}>{revoking === token.id ? 'Revoking' : 'Confirm'}</button></div> : <button className="icon-button ml-auto" onClick={() => setConfirming(token.id)} aria-label={`Revoke ${token.name}`}><Trash size={15} /></button>)}</td>
                    </tr>
                  })}</tbody>
                </table>
              </div>
              <div className="flex items-start gap-3 border-t border-stone-800 bg-[#f7f3eb] px-6 py-4 text-xs leading-5 text-stone-600"><ShieldCheck size={17} className="mt-0.5 shrink-0 text-[#4f6f5c]" />Revocation takes effect immediately. Existing reports and host history remain unchanged.</div>
            </section>
          )}
        </>
      )}
      {creating && <CreateTokenPanel hosts={data?.hosts ?? []} close={() => setCreating(false)} created={() => void reload()} />}
    </div>
  )
}
