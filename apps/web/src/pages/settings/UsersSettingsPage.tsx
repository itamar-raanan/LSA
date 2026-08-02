import { Check, Minus, ShieldCheck, UsersThree } from '@phosphor-icons/react'
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

  async function changeRole(id: string, role: string) { await api.updateUserRole(id, role); await reload() }
  async function changeStatus(id: string, active: boolean) { await api.updateUserStatus(id, active); await reload() }

  return <div className="page-reveal">
    <PageHeader eyebrow="Identity governance" title="Users, roles & permissions" detail="Users appear automatically after successful organization authentication; administrators govern role and lifecycle here." action={<span className="settings-state">JIT provisioning</span>} />
    {loading ? <LoadingState /> : error ? <ErrorState message={error} retry={reload} /> : !users?.length ? <EmptyState title="No users" detail="Enable an identity provider and complete the first organization sign-in." /> : <section className="panel overflow-hidden">
      <div className="overflow-x-auto"><table className="data-table min-w-[900px]"><thead><tr><th>User</th><th>Identity source</th><th>Role</th><th>Status</th><th>Last login</th></tr></thead><tbody>{users.map((managed) => <tr key={managed.id}>
        <td><span className="font-medium text-stone-200">{managed.name}</span><span className="table-subtitle">{managed.email}{managed.id === user?.id ? ' · current user' : ''}</span></td>
        <td>{managed.provider_name ?? (managed.auth_source === 'local' ? 'Emergency local' : managed.auth_source)}<span className="table-subtitle">{managed.auth_source}</span></td>
        <td><select className="select-input min-h-9" value={managed.role} disabled={managed.id === user?.id} onChange={(event) => void changeRole(managed.id, event.target.value)}><option value="admin">Administrator</option><option value="analyst">Analyst</option><option value="auditor">Auditor</option></select></td>
        <td><button className="button-secondary min-h-9 px-3" disabled={managed.id === user?.id} onClick={() => void changeStatus(managed.id, !managed.is_active)}>{managed.is_active ? 'Active' : 'Disabled'}</button></td>
        <td>{managed.last_login_at ? new Date(managed.last_login_at).toLocaleString() : 'Never'}</td>
      </tr>)}</tbody></table></div>
      <div className="flex items-start gap-3 border-t border-stone-800 bg-[#121613] px-6 py-4 text-xs leading-5 text-stone-600"><UsersThree size={17} className="mt-0.5 shrink-0" />Disabling a user immediately revokes every active browser session. User identities remain linked to their provider subject.</div>
    </section>}
    <section className="mt-8 overflow-hidden rounded-[22px] border border-stone-800 bg-[#151916]">
      <div className="border-b border-stone-800 px-6 py-5"><p className="section-label">Enforced permission model</p><p className="mt-2 text-xs leading-5 text-stone-600">Administrative APIs enforce these role boundaries independently of the console.</p></div>
      <div className="overflow-x-auto"><table className="data-table min-w-[680px]"><thead><tr><th>Capability</th><th>Administrator</th><th>Analyst</th><th>Auditor</th></tr></thead><tbody>{permissions.map((permission) => <tr key={permission.capability}><td>{permission.capability}</td>{(['admin', 'analyst', 'auditor'] as const).map((role) => <td key={role}>{permission[role] ? <Check size={16} className="text-emerald-400" aria-label="Allowed" /> : <Minus size={16} className="text-stone-700" aria-label="Not allowed" />}</td>)}</tr>)}</tbody></table></div>
      <div className="flex items-start gap-3 border-t border-stone-800 bg-[#121613] px-6 py-4 text-xs leading-5 text-stone-600"><ShieldCheck size={17} className="mt-0.5 shrink-0 text-emerald-500" />Role mapping originates in OIDC groups or the configured RADIUS reply attribute and can be corrected here.</div>
    </section>
  </div>
}
