import { Check, Minus, ShieldCheck, UserCircle, UsersThree } from '@phosphor-icons/react'
import { useAuth } from '../../auth/useAuth'
import { PageHeader } from '../../components/PageHeader'

const permissions = [
  { capability: 'View hosts, findings, and reports', admin: true, analyst: true, auditor: true },
  { capability: 'Download verified evidence', admin: true, analyst: true, auditor: true },
  { capability: 'Manage scanner credentials', admin: true, analyst: false, auditor: false },
  { capability: 'Manage users and authentication', admin: true, analyst: false, auditor: false },
  { capability: 'Delete expired evidence', admin: true, analyst: false, auditor: false },
]

export function UsersSettingsPage() {
  const { user } = useAuth()
  return (
    <div className="page-reveal">
      <PageHeader eyebrow="Identity governance" title="Users, roles & permissions" detail="Define least-privilege access for administrators, security analysts, and audit reviewers." action={<span className="settings-state">Backend required</span>} />

      <section className="panel overflow-hidden">
        <div className="flex items-center gap-4 border-b border-stone-800 px-6 py-5 md:px-7">
          <span className="grid size-10 place-items-center rounded-full bg-emerald-900/40 text-emerald-200"><UserCircle size={22} weight="duotone" /></span>
          <div className="min-w-0"><p className="truncate text-sm text-stone-200">{user?.name}</p><p className="mt-1 truncate font-mono text-[10px] text-stone-600">{user?.email}</p></div>
          <span className="ml-auto font-mono text-[9px] uppercase tracking-wider text-emerald-300">Current administrator</span>
        </div>
        <div className="flex items-start gap-3 bg-[#121613] px-6 py-4 text-xs leading-5 text-stone-600 md:px-7"><UsersThree size={17} className="mt-0.5 shrink-0" />User invitations, lifecycle state, password resets, and session revocation require tenant-scoped user-management APIs before these controls can be enabled.</div>
      </section>

      <section className="mt-8 overflow-hidden rounded-[22px] border border-stone-800 bg-[#151916]">
        <div className="border-b border-stone-800 px-6 py-5 md:px-7"><p className="section-label">Proposed permission model</p><p className="mt-2 text-xs leading-5 text-stone-600">Permissions must be enforced by the API on every request; hiding a console button is not authorization.</p></div>
        <div className="overflow-x-auto">
          <table className="data-table min-w-[680px]">
            <thead><tr><th>Capability</th><th>Administrator</th><th>Analyst</th><th>Auditor</th></tr></thead>
            <tbody>{permissions.map((permission) => <tr key={permission.capability}><td>{permission.capability}</td>{(['admin', 'analyst', 'auditor'] as const).map((role) => <td key={role}>{permission[role] ? <Check size={16} className="text-emerald-400" aria-label="Allowed" /> : <Minus size={16} className="text-stone-700" aria-label="Not allowed" />}</td>)}</tr>)}</tbody>
          </table>
        </div>
        <div className="flex items-start gap-3 border-t border-stone-800 bg-[#121613] px-6 py-4 text-xs leading-5 text-stone-600 md:px-7"><ShieldCheck size={17} className="mt-0.5 shrink-0 text-emerald-500" />Recommended additions: custom roles, emergency-access accounts, active-session revocation, and quarterly access-review exports.</div>
      </section>
    </div>
  )
}
