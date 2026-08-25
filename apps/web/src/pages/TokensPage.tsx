import { Plus, ShieldCheck, Trash } from '@phosphor-icons/react'
import { useEffect, useState } from 'react'
import { api } from '../api/client'
import { CreateTokenPanel } from '../components/CreateTokenPanel'
import { PageHeader } from '../components/PageHeader'
import { type SecurityColumn, SecurityTable } from '../components/security/SecurityTable'
import { StatusBadge } from '../components/security/StatusBadge'
import { Button } from '../components/ui/Button'
import { EmptyState, ErrorState, LoadingState } from '../components/StatePanel'
import { useAuth } from '../auth/useAuth'
import { useApi } from '../hooks/useApi'
import { useSecurityTableUrlState } from '../hooks/useSecurityTableUrlState'
import { formatDateTime as formatDate } from '../lib/dateTime'
import type { IngestionToken } from '../types'

function tokenState(token: IngestionToken): 'active' | 'expired' | 'revoked' {
  if (token.revoked_at) return 'revoked'
  if (token.expires_at && new Date(token.expires_at).getTime() <= Date.now()) return 'expired'
  return 'active'
}

export function TokensPage({ embedded = false, autoCreate = false }: { embedded?: boolean; autoCreate?: boolean } = {}) {
  const { user } = useAuth()
  const [creating, setCreating] = useState(false)
  const [confirming, setConfirming] = useState<string | null>(null)
  const [revoking, setRevoking] = useState<string | null>(null)
  const [actionError, setActionError] = useState('')
  const tableState = useSecurityTableUrlState()
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
  const createAction = <Button variant="primary" onClick={() => setCreating(true)}><Plus size={16} /> Issue Token</Button>
  const columns: SecurityColumn<IngestionToken>[] = [
    { id: 'credential', header: 'Credential', priority: 'primary', hideable: false, sortValue: (token) => token.name, exportValue: (token) => token.name, cell: (token) => <span className="table-primary">{token.name}<small>{token.token_prefix}… · Created {formatDate(token.created_at)}</small></span> },
    { id: 'scope', header: 'Scope', priority: 'secondary', sortValue: (token) => token.host_id ? hostnames.get(token.host_id) ?? '' : 'All Tenant Hosts', exportValue: (token) => token.host_id ? hostnames.get(token.host_id) ?? 'Unknown Host' : 'All Tenant Hosts', cell: (token) => <span className="table-primary">{token.host_id ? hostnames.get(token.host_id) ?? 'Unknown Host' : 'All Tenant Hosts'}<small>{token.host_id ? 'Host-Scoped' : 'Tenant-Wide'}</small></span> },
    { id: 'status', header: 'Status', priority: 'secondary', sortValue: tokenState, exportValue: tokenState, cell: (token) => { const state = tokenState(token); return <StatusBadge label={state[0].toUpperCase() + state.slice(1)} tone={state === 'active' ? 'online' : state === 'expired' ? 'warning' : 'offline'} /> } },
    { id: 'used', header: 'Last Used', priority: 'detail', sortValue: (token) => token.last_used_at ?? '', exportValue: (token) => token.last_used_at, cell: (token) => formatDate(token.last_used_at) },
    { id: 'expires', header: 'Expires', priority: 'detail', sortValue: (token) => token.expires_at ?? '', exportValue: (token) => token.expires_at, cell: (token) => formatDate(token.expires_at) },
    { id: 'actions', header: 'Actions', priority: 'detail', hideable: false, cell: (token) => tokenState(token) === 'active' && (confirming === token.id ? <div className="flex gap-2"><button className="button-secondary min-h-9 px-3" onClick={() => setConfirming(null)}>Cancel</button><button className="button-secondary min-h-9 border-rose-900/60 px-3 text-rose-700" disabled={revoking === token.id} onClick={() => void revoke(token.id)}>{revoking === token.id ? 'Revoking' : 'Confirm'}</button></div> : <button className="icon-button" onClick={() => setConfirming(token.id)} aria-label={`Revoke ${token.name}`}><Trash size={15} /></button>) },
  ]

  return (
    <div className={embedded ? 'credential-workspace' : 'page-reveal'}>
      {embedded ? <header className="credential-workspace-heading"><div><p className="section-label">Submission Authentication</p><h2>Ingestion Tokens</h2><p>Issue narrowly scoped credentials, inspect their activity, and revoke submission access.</p></div>{createAction}</header> : <PageHeader eyebrow="Credential Governance" title="Ingestion Tokens" detail="Issue narrowly scoped scanner credentials, inspect their activity, and revoke access without changing host identities." action={createAction} />}
      {loading ? <LoadingState variant="table" /> : error ? <ErrorState message={error} retry={reload} /> : (
        <>
          <section className="credential-summary sm:grid-cols-[1.2fr_1fr_1fr]">
            <div className="border-b border-stone-200 px-6 py-5 sm:border-b-0 sm:border-r"><p className="section-label">Credential posture</p><p className="mt-3 max-w-sm text-sm leading-6 text-stone-400">Secrets are displayed once and stored as one-way hashes.</p></div>
            <div className="border-b border-stone-200 px-6 py-5 sm:border-b-0 sm:border-r"><p className="font-mono text-2xl text-stone-800">{activeCount}</p><p className="mt-2 text-[10px] capitalize tracking-wider text-stone-600">Active tokens</p></div>
            <div className="px-6 py-5"><p className="font-mono text-2xl text-stone-800">{usedCount}</p><p className="mt-2 text-[10px] capitalize tracking-wider text-stone-600">Used credentials</p></div>
          </section>
          {actionError && <p className="mb-4 rounded-xl border border-rose-900/50 bg-rose-950/20 px-4 py-3 text-xs text-rose-700">{actionError}</p>}
          {!tokens.length ? <EmptyState title="No Scanner Credentials" detail="Issue a host-scoped token before configuring the first scanner controller." action={createAction} /> : (
            <section className="panel overflow-hidden">
              <SecurityTable rows={tokens} columns={columns} query={tableState.query} onQueryChange={tableState.setQuery} sort={tableState.sort} onSortChange={tableState.setSort} page={tableState.page} onPageChange={tableState.setPage} searchText={(token) => `${token.name} ${token.token_prefix} ${token.host_id ? hostnames.get(token.host_id) ?? '' : 'all tenant hosts'} ${tokenState(token)}`} rowLabel={(token) => token.name} searchPlaceholder="Search Credential, Scope, Or Status" filename="lsa-ingestion-tokens.csv" ariaLabel="Ingestion Tokens" embedded />
              <div className="flex items-start gap-3 border-t border-stone-200 bg-[#f7f3eb] px-6 py-4 text-xs leading-5 text-stone-600"><ShieldCheck size={17} className="mt-0.5 shrink-0 text-[#4f6f5c]" />Revocation takes effect immediately. Existing reports and host history remain unchanged.</div>
            </section>
          )}
        </>
      )}
      {creating && <CreateTokenPanel hosts={data?.hosts ?? []} close={() => setCreating(false)} created={() => void reload()} />}
    </div>
  )
}
