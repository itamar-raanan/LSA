import { Buildings, CheckCircle, LockKey, Network, WarningCircle } from '@phosphor-icons/react'
import { PageHeader } from '../../components/PageHeader'

const integrations = [
  { title: 'OpenID Connect / SAML SSO', detail: 'Connect an enterprise identity provider, map groups to roles, and enforce signed assertions.', requirements: 'Issuer metadata, client credentials, redirect URI, group claims', icon: Buildings },
  { title: 'RADIUS', detail: 'Authenticate against an existing AAA service with timeout, fail-closed, and source-network controls.', requirements: 'Server address, shared secret, CA trust, role mapping', icon: Network },
]

export function AuthenticationSettingsPage() {
  return (
    <div className="page-reveal">
      <PageHeader eyebrow="Access control" title="Authentication" detail="Choose how administrators and analysts establish identity before entering the console." />
      <section className="panel overflow-hidden">
        <div className="grid gap-4 px-6 py-6 sm:grid-cols-[44px_1fr_auto] sm:items-center md:px-7">
          <span className="grid size-11 place-items-center rounded-xl border border-emerald-900/50 bg-emerald-950/20 text-emerald-300"><LockKey size={21} weight="duotone" /></span>
          <div><p className="text-sm font-medium text-stone-200">Local password authentication</p><p className="mt-1 text-xs leading-5 text-stone-600">Bootstrap administrator and API-issued browser sessions.</p></div>
          <span className="inline-flex items-center gap-2 font-mono text-[9px] uppercase tracking-wider text-emerald-300"><CheckCircle size={15} weight="fill" /> Enabled</span>
        </div>
      </section>

      <div className="mt-5 divide-y divide-stone-800 overflow-hidden rounded-[22px] border border-stone-800 bg-[#151916]">
        {integrations.map(({ title, detail, requirements, icon: Icon }) => (
          <section key={title} className="grid gap-5 px-6 py-6 md:grid-cols-[44px_1fr_auto] md:items-start md:px-7">
            <span className="grid size-11 place-items-center rounded-xl border border-stone-800 bg-[#111512] text-stone-500"><Icon size={21} weight="duotone" /></span>
            <div><p className="text-sm font-medium text-stone-200">{title}</p><p className="mt-2 max-w-[65ch] text-xs leading-5 text-stone-600">{detail}</p><p className="mt-3 font-mono text-[9px] uppercase tracking-wider text-stone-700">Requires · {requirements}</p></div>
            <span className="settings-state">Not configured</span>
          </section>
        ))}
      </div>

      <div className="mt-5 flex items-start gap-3 rounded-[18px] border border-amber-900/40 bg-amber-950/10 px-5 py-4 text-xs leading-5 text-amber-200/70"><WarningCircle size={18} className="mt-0.5 shrink-0" />SSO and RADIUS must include a tested emergency local account, encrypted secrets, login audit events, and fail-closed behavior before activation.</div>
    </div>
  )
}
