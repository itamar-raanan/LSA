import { Check, Minus, Plus, ShieldCheck, UsersThree, X } from '@phosphor-icons/react'
import { FormEvent, useMemo, useState } from 'react'
import { api } from '../../api/client'
import { useAuth } from '../../auth/useAuth'
import { PageHeader } from '../../components/PageHeader'
import { type SecurityColumn, SecurityTable } from '../../components/security/SecurityTable'
import { StatusBadge } from '../../components/security/StatusBadge'
import { EmptyState, ErrorState, LoadingState } from '../../components/StatePanel'
import { Button } from '../../components/ui/Button'
import { Dialog } from '../../components/ui/Dialog'
import { useApi } from '../../hooks/useApi'
import { useSecurityTableUrlState } from '../../hooks/useSecurityTableUrlState'
import type { ManagedUser } from '../../types'

const permissions = [
  { capability: 'View hosts, findings, and reports', admin: true, analyst: true, auditor: true },
  { capability: 'Download verified evidence', admin: true, analyst: true, auditor: true },
  { capability: 'Manage scanner credentials', admin: true, analyst: false, auditor: false },
  { capability: 'Manage users and authentication', admin: true, analyst: false, auditor: false },
  { capability: 'Delete expired evidence', admin: true, analyst: false, auditor: false },
]

export function UsersSettingsPage() {
  const { user } = useAuth()
  const { data: users, error, loading, reload } = useApi(() => api.users(), [])
  const { data: providers } = useApi(() => api.providers(), [])
  const [adding, setAdding] = useState(false)
  const [saving, setSaving] = useState(false)
  const [formError, setFormError] = useState('')
  const [providerId, setProviderId] = useState('')
  const [pendingChange, setPendingChange] = useState<
    | { kind: 'status'; managed: ManagedUser; active: boolean }
    | { kind: 'role'; managed: ManagedUser; role: string }
    | null
  >(null)
  const [updating, setUpdating] = useState(false)
  const tableState = useSecurityTableUrlState()
  const selectedProvider = useMemo(() => providers?.find((item) => item.id === providerId), [providers, providerId])
  const columns: SecurityColumn<ManagedUser>[] = [
    { id: 'user', header: 'User', priority: 'primary', hideable: false, sortValue: (managed) => managed.name, exportValue: (managed) => managed.name, cell: (managed) => <span className="table-primary">{managed.name}<small>{managed.email}{managed.id === user?.id ? ' · Current User' : ''}</small></span> },
    { id: 'source', header: 'Identity Source', priority: 'detail', sortValue: (managed) => managed.provider_name ?? managed.auth_source, exportValue: (managed) => managed.provider_name ?? managed.auth_source, cell: (managed) => <span className="table-primary">{managed.provider_name ?? (managed.auth_source === 'local' ? 'Emergency local' : managed.auth_source)}<small>{managed.auth_source}</small></span> },
    { id: 'role', header: 'Role', priority: 'secondary', sortValue: (managed) => managed.role, exportValue: (managed) => managed.role, cell: (managed) => <select aria-label={`Role For ${managed.name}`} className="select-input min-h-9" value={managed.role} disabled={managed.id === user?.id} onChange={(event) => requestRoleChange(managed, event.target.value)}><option value="admin">Administrator</option><option value="analyst">Analyst</option><option value="auditor">Auditor</option></select> },
    { id: 'status', header: 'Status', priority: 'secondary', sortValue: (managed) => managed.is_active ? 'Active' : 'Disabled', exportValue: (managed) => managed.is_active ? 'Active' : 'Disabled', cell: (managed) => <StatusBadge label={managed.is_active ? 'Active' : 'Disabled'} tone={managed.is_active ? 'online' : 'offline'} /> },
    { id: 'login', header: 'Last Login', priority: 'detail', sortValue: (managed) => managed.last_login_at ?? '', exportValue: (managed) => managed.last_login_at, cell: (managed) => managed.last_login_at ? new Date(managed.last_login_at).toLocaleString() : 'Never' },
    { id: 'actions', header: 'Actions', priority: 'detail', hideable: false, cell: (managed) => <Button size="sm" disabled={managed.id === user?.id} onClick={() => managed.is_active ? setPendingChange({ kind: 'status', managed, active: false }) : void api.updateUserStatus(managed.id, true).then(reload)}>{managed.is_active ? 'Disable' : 'Enable'}</Button> },
  ]

  async function applyPendingChange() {
    if (!pendingChange) return
    setUpdating(true)
    try {
      if (pendingChange.kind === 'role') await api.updateUserRole(pendingChange.managed.id, pendingChange.role)
      else await api.updateUserStatus(pendingChange.managed.id, pendingChange.active)
      setPendingChange(null)
      await reload()
    } finally {
      setUpdating(false)
    }
  }

  function requestRoleChange(managed: ManagedUser, role: string) {
    if (managed.role === 'admin' || role === 'admin') setPendingChange({ kind: 'role', managed, role })
    else void api.updateUserRole(managed.id, role).then(reload)
  }

  async function createUser(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setSaving(true)
    setFormError('')
    const values = new FormData(event.currentTarget)
    try {
      await api.createUser({
        email: String(values.get('email')),
        display_name: String(values.get('display_name')),
        external_subject: String(values.get('external_subject')),
        provider_id: String(values.get('provider_id')),
        role: String(values.get('role')) as 'admin' | 'analyst' | 'auditor',
      })
      setAdding(false)
      setProviderId('')
      await reload()
    } catch (caught) {
      setFormError(caught instanceof Error ? caught.message : 'Unable to add user')
    } finally {
      setSaving(false)
    }
  }

  return <div className="page-reveal">
    <PageHeader eyebrow="Identity governance" title="Users, roles & permissions" detail="Pre-provision users or allow just-in-time creation after successful organization authentication." action={<button className="button-primary" onClick={() => setAdding(true)} disabled={!providers?.length}><Plus size={16} /> Add user</button>} />
    {adding && <section className="panel mb-6 overflow-hidden">
      <div className="flex items-start justify-between gap-4 border-b border-stone-800 px-6 py-5"><div><p className="section-label">External identity</p><h2 className="mt-2 text-base font-semibold text-stone-100">Pre-provision user</h2><p className="mt-2 text-xs leading-5 text-stone-600">LSA stores the identity link and role; authentication remains with your selected provider.</p></div><button className="icon-button" aria-label="Close add user form" onClick={() => setAdding(false)}><X size={16} /></button></div>
      <form className="grid gap-4 px-6 py-6 md:grid-cols-2" onSubmit={(event) => void createUser(event)}>
        <label className="form-field">Identity provider<select className="select-input min-h-11 w-full" name="provider_id" required value={providerId} onChange={(event) => setProviderId(event.target.value)}><option value="">Select provider</option>{providers?.map((provider) => <option key={provider.id} value={provider.id}>{provider.name} · {provider.provider_type}</option>)}</select></label>
        <label className="form-field">{selectedProvider?.provider_type === 'radius' ? 'RADIUS username' : 'Provider subject / object ID'}<input name="external_subject" required autoComplete="off" placeholder={selectedProvider?.provider_type === 'radius' ? 'itamar' : 'Immutable provider subject'} /><small>{selectedProvider?.provider_type === 'radius' ? 'Must exactly match the username used at sign-in.' : 'Use the immutable sub/object ID issued by the provider.'}</small></label>
        <label className="form-field">Display name<input name="display_name" required autoComplete="name" placeholder="Itamar Raanan" /></label>
        <label className="form-field">Email address<input name="email" type="email" required autoComplete="email" placeholder="itamar@example.com" /></label>
        <label className="form-field">LSA role<select className="select-input min-h-11 w-full" name="role" defaultValue="auditor"><option value="admin">Administrator</option><option value="analyst">Analyst</option><option value="auditor">Auditor</option></select></label>
        <div className="flex items-end justify-end gap-3"><button className="button-secondary" type="button" onClick={() => setAdding(false)}>Cancel</button><button className="button-primary" disabled={saving || !providerId}>{saving ? 'Adding…' : 'Add user'}</button></div>
        {formError && <p className="text-xs text-rose-400 md:col-span-2">{formError}</p>}
      </form>
    </section>}
    {!providers?.length && !loading && <div className="mb-6 rounded-xl border border-amber-900/40 bg-amber-950/10 px-4 py-3 text-xs text-amber-300">Configure an identity provider before pre-provisioning users.</div>}
    {loading ? <LoadingState /> : error ? <ErrorState message={error} retry={reload} /> : !users?.length ? <EmptyState title="No users" detail="Enable an identity provider and complete the first organization sign-in." /> : <section className="panel overflow-hidden">
      <SecurityTable rows={users} columns={columns} query={tableState.query} onQueryChange={tableState.setQuery} sort={tableState.sort} onSortChange={tableState.setSort} page={tableState.page} onPageChange={tableState.setPage} searchText={(managed) => `${managed.name} ${managed.email} ${managed.provider_name ?? ''} ${managed.auth_source} ${managed.role} ${managed.is_active ? 'active' : 'disabled'}`} rowLabel={(managed) => managed.name} searchPlaceholder="Search User, Provider, Role, Or Status" filename="lsa-users.csv" ariaLabel="Users" embedded />
      <div className="flex items-start gap-3 border-t border-stone-800 bg-[#f7f3eb] px-6 py-4 text-xs leading-5 text-stone-600"><UsersThree size={17} className="mt-0.5 shrink-0" />Disabling a user immediately revokes every active browser session. User identities remain linked to their provider subject.</div>
    </section>}
    <section className="mt-8 overflow-hidden rounded-[22px] border border-stone-800 bg-[#f7f3eb]">
      <div className="border-b border-stone-800 px-6 py-5"><p className="section-label">Enforced permission model</p><p className="mt-2 text-xs leading-5 text-stone-600">Administrative APIs enforce these role boundaries independently of the console.</p></div>
      <div className="overflow-x-auto"><table className="data-table min-w-[680px]"><thead><tr><th>Capability</th><th>Administrator</th><th>Analyst</th><th>Auditor</th></tr></thead><tbody>{permissions.map((permission) => <tr key={permission.capability}><td>{permission.capability}</td>{(['admin', 'analyst', 'auditor'] as const).map((role) => <td key={role}>{permission[role] ? <Check size={16} className="text-[#4f6f5c]" aria-label="Allowed" /> : <Minus size={16} className="text-stone-700" aria-label="Not allowed" />}</td>)}</tr>)}</tbody></table></div>
      <div className="flex items-start gap-3 border-t border-stone-800 bg-[#f7f3eb] px-6 py-4 text-xs leading-5 text-stone-600"><ShieldCheck size={17} className="mt-0.5 shrink-0 text-[#4f6f5c]" />Role mapping originates in OIDC groups or the configured RADIUS reply attribute and can be corrected here.</div>
    </section>
    <Dialog
      open={pendingChange !== null}
      onOpenChange={(open) => { if (!open && !updating) setPendingChange(null) }}
      eyebrow="Access safety"
      title={pendingChange?.kind === 'role'
        ? `Change ${pendingChange.managed.name}'s role?`
        : `Disable ${pendingChange?.managed.name ?? 'user'}?`}
      description={pendingChange?.kind === 'role'
        ? `The account will change from ${pendingChange.managed.role} to ${pendingChange.role}. This changes the permissions enforced by both the console and API.`
        : 'The account will be blocked immediately and every active browser session will be revoked. The linked identity record will be retained.'}
    >
      <div className="rounded-lg border border-amber-900/40 bg-amber-950/10 px-4 py-3 text-xs leading-5 text-amber-800">
        {pendingChange?.kind === 'role'
          ? 'Administrator access can manage users, authentication, credentials, agents, and evidence. Confirm this identity requires that scope.'
          : 'The user cannot sign in again until an administrator enables the account.'}
      </div>
      <div className="mt-6 flex justify-end gap-3">
        <Button onClick={() => setPendingChange(null)} disabled={updating}>Cancel</Button>
        <Button variant="danger" disabled={!pendingChange || updating} onClick={() => void applyPendingChange()}>
          {updating ? 'Applying change' : pendingChange?.kind === 'role' ? 'Change role' : 'Disable user'}
        </Button>
      </div>
    </Dialog>
  </div>
}
