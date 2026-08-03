import { Check, Minus, Plus, ShieldCheck, UsersThree, X } from '@phosphor-icons/react'
import { FormEvent, useMemo, useState } from 'react'
import { api } from '../../api/client'
import { useAuth } from '../../auth/useAuth'
import { PageHeader } from '../../components/PageHeader'
import { EmptyState, ErrorState, LoadingState } from '../../components/StatePanel'
import { useApi } from '../../hooks/useApi'

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
  const selectedProvider = useMemo(() => providers?.find((item) => item.id === providerId), [providers, providerId])

  async function changeRole(id: string, role: string) { await api.updateUserRole(id, role); await reload() }
  async function changeStatus(id: string, active: boolean) { await api.updateUserStatus(id, active); await reload() }

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
      <div className="overflow-x-auto"><table className="data-table min-w-[900px]"><thead><tr><th>User</th><th>Identity source</th><th>Role</th><th>Status</th><th>Last login</th></tr></thead><tbody>{users.map((managed) => <tr key={managed.id}>
        <td><span className="font-medium text-stone-200">{managed.name}</span><span className="table-subtitle">{managed.email}{managed.id === user?.id ? ' · current user' : ''}</span></td>
        <td>{managed.provider_name ?? (managed.auth_source === 'local' ? 'Emergency local' : managed.auth_source)}<span className="table-subtitle">{managed.auth_source}</span></td>
        <td><select className="select-input min-h-9" value={managed.role} disabled={managed.id === user?.id} onChange={(event) => void changeRole(managed.id, event.target.value)}><option value="admin">Administrator</option><option value="analyst">Analyst</option><option value="auditor">Auditor</option></select></td>
        <td><button className="button-secondary min-h-9 px-3" disabled={managed.id === user?.id} onClick={() => void changeStatus(managed.id, !managed.is_active)}>{managed.is_active ? 'Active' : 'Disabled'}</button></td>
        <td>{managed.last_login_at ? new Date(managed.last_login_at).toLocaleString() : 'Never'}</td>
      </tr>)}</tbody></table></div>
      <div className="flex items-start gap-3 border-t border-stone-800 bg-[#f7f3eb] px-6 py-4 text-xs leading-5 text-stone-600"><UsersThree size={17} className="mt-0.5 shrink-0" />Disabling a user immediately revokes every active browser session. User identities remain linked to their provider subject.</div>
    </section>}
    <section className="mt-8 overflow-hidden rounded-[22px] border border-stone-800 bg-[#f7f3eb]">
      <div className="border-b border-stone-800 px-6 py-5"><p className="section-label">Enforced permission model</p><p className="mt-2 text-xs leading-5 text-stone-600">Administrative APIs enforce these role boundaries independently of the console.</p></div>
      <div className="overflow-x-auto"><table className="data-table min-w-[680px]"><thead><tr><th>Capability</th><th>Administrator</th><th>Analyst</th><th>Auditor</th></tr></thead><tbody>{permissions.map((permission) => <tr key={permission.capability}><td>{permission.capability}</td>{(['admin', 'analyst', 'auditor'] as const).map((role) => <td key={role}>{permission[role] ? <Check size={16} className="text-[#4f6f5c]" aria-label="Allowed" /> : <Minus size={16} className="text-stone-700" aria-label="Not allowed" />}</td>)}</tr>)}</tbody></table></div>
      <div className="flex items-start gap-3 border-t border-stone-800 bg-[#f7f3eb] px-6 py-4 text-xs leading-5 text-stone-600"><ShieldCheck size={17} className="mt-0.5 shrink-0 text-[#4f6f5c]" />Role mapping originates in OIDC groups or the configured RADIUS reply attribute and can be corrected here.</div>
    </section>
  </div>
}
