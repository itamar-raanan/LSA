import {
  ArrowRight,
  BellRinging,
  Certificate,
  Database,
  Fingerprint,
  HardDrive,
  Key,
  LockKey,
  PlugsConnected,
  Scroll,
  ShieldCheck,
  UsersThree,
} from '@phosphor-icons/react'
import { Link } from 'react-router-dom'
import { PageHeader } from '../../components/PageHeader'

const primarySettings = [
  { to: '/settings/users', title: 'Users & access', detail: 'Invite users and enforce tenant roles and permissions.', status: 'Backend required', icon: UsersThree },
  { to: '/settings/authentication', title: 'Authentication', detail: 'Configure local login, OIDC or SAML SSO, and RADIUS.', status: 'Local enabled', icon: LockKey },
  { to: '/settings/tokens', title: 'Ingestion tokens', detail: 'Issue and revoke host-scoped scanner credentials.', status: 'Available', icon: Key },
  { to: '/settings/signing-keys', title: 'Signing keys', detail: 'Register public keys used to verify report provenance.', status: 'Available', icon: Fingerprint },
  { to: '/settings/certificates', title: 'TLS certificates', detail: 'Install and rotate the HTTPS certificate chain.', status: 'External TLS', icon: Certificate },
]

const recommended = [
  { title: 'Evidence vault', detail: 'Storage backend, retention, legal hold, and integrity status.', icon: Database },
  { title: 'Audit & export', detail: 'Search administrator events and forward signed audit records.', icon: Scroll },
  { title: 'Notifications', detail: 'Email, Slack, webhook, and severity-based alert routing.', icon: BellRinging },
  { title: 'Scanner policy', detail: 'Required signatures, stale-host windows, and accepted profiles.', icon: ShieldCheck },
  { title: 'API & webhooks', detail: 'Service accounts, outbound events, and rate limits.', icon: PlugsConnected },
  { title: 'Backup & recovery', detail: 'Database and evidence-volume backup verification.', icon: HardDrive },
]

export function SettingsOverviewPage() {
  return (
    <div className="page-reveal">
      <PageHeader eyebrow="Platform administration" title="Settings" detail="Control who can access LSA, how scanners establish trust, and which security boundaries protect the platform." />

      <section className="overflow-hidden rounded-[22px] border border-stone-800 bg-[#151916]">
        <div className="grid border-b border-stone-800 px-6 py-5 md:grid-cols-[1fr_auto] md:items-center md:px-7">
          <div><p className="section-label">Configuration posture</p><p className="mt-2 text-sm text-stone-400">Two controls are operational; identity integrations require backend enablement.</p></div>
          <span className="mt-4 inline-flex w-fit items-center gap-2 font-mono text-[10px] uppercase tracking-wider text-emerald-300 md:mt-0"><span className="status-pulse" /> Evidence trust active</span>
        </div>
        <div className="divide-y divide-stone-800">
          {primarySettings.map(({ to, title, detail, status, icon: Icon }) => (
            <Link key={to} to={to} className="group grid gap-4 px-6 py-5 transition hover:bg-[#191e1a] sm:grid-cols-[40px_1fr_auto] sm:items-center md:px-7">
              <span className="grid size-10 place-items-center rounded-xl border border-stone-800 bg-[#111512] text-emerald-400"><Icon size={19} weight="duotone" /></span>
              <span><strong className="block text-sm font-medium text-stone-200">{title}</strong><small className="mt-1 block text-xs leading-5 text-stone-600">{detail}</small></span>
              <span className="flex items-center gap-3 font-mono text-[9px] uppercase tracking-wider text-stone-600">{status}<ArrowRight size={14} className="transition-transform group-hover:translate-x-1" /></span>
            </Link>
          ))}
        </div>
      </section>

      <section className="mt-10">
        <div className="mb-4"><p className="section-label">Recommended next controls</p><p className="mt-2 text-xs text-stone-600">High-value settings to add as the platform moves into production operations.</p></div>
        <div className="grid overflow-hidden rounded-[22px] border border-stone-800 bg-[#151916] md:grid-cols-2">
          {recommended.map(({ title, detail, icon: Icon }, index) => (
            <div key={title} className={`flex gap-4 px-6 py-5 ${index % 2 === 0 ? 'md:border-r md:border-stone-800' : ''} ${index > 1 ? 'border-t border-stone-800' : index === 1 ? 'border-t border-stone-800 md:border-t-0' : ''}`}>
              <Icon size={18} weight="duotone" className="mt-0.5 shrink-0 text-stone-500" />
              <div><p className="text-sm text-stone-300">{title}</p><p className="mt-1 text-xs leading-5 text-stone-600">{detail}</p></div>
            </div>
          ))}
        </div>
      </section>
    </div>
  )
}
