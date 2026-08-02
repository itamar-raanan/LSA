import { Certificate, LockKey, UploadSimple, WarningCircle } from '@phosphor-icons/react'
import { PageHeader } from '../../components/PageHeader'

export function CertificatesSettingsPage() {
  return (
    <div className="page-reveal">
      <PageHeader eyebrow="Transport security" title="TLS certificates" detail="Install and rotate the certificate chain used for HTTPS access to the LSA console and API." action={<span className="settings-state">External TLS</span>} />
      <section className="panel overflow-hidden">
        <div className="grid gap-6 px-6 py-7 md:grid-cols-[1fr_1.15fr] md:px-7">
          <div><span className="grid size-11 place-items-center rounded-xl border border-stone-800 bg-[#111512] text-emerald-400"><Certificate size={22} weight="duotone" /></span><h2 className="mt-5 text-lg font-medium tracking-tight text-stone-200">Certificate upload</h2><p className="mt-2 max-w-md text-xs leading-5 text-stone-600">The Docker deployment currently expects HTTPS termination at a host reverse proxy or load balancer. In-app upload requires an encrypted certificate store and controlled gateway reload service.</p></div>
          <div className="grid min-h-52 place-items-center rounded-[18px] border border-dashed border-stone-700 bg-[#121613] p-6 text-center" aria-disabled="true">
            <div><UploadSimple size={25} className="mx-auto text-stone-600" /><p className="mt-4 text-sm text-stone-400">PEM certificate chain and private key</p><p className="mt-2 text-xs leading-5 text-stone-700">Upload is disabled until the certificate-management backend is installed.</p><button className="button-secondary mt-5" disabled>Choose certificate files</button></div>
          </div>
        </div>
        <div className="grid divide-y divide-stone-800 border-t border-stone-800 bg-[#121613] sm:grid-cols-3 sm:divide-x sm:divide-y-0">
          <div className="px-5 py-4"><p className="detail-label">Formats</p><p className="mt-2 text-xs text-stone-500">PEM chain + PKCS#8 key</p></div>
          <div className="px-5 py-4"><p className="detail-label">Validation</p><p className="mt-2 text-xs text-stone-500">Hostname, chain, key match</p></div>
          <div className="px-5 py-4"><p className="detail-label">Rotation</p><p className="mt-2 text-xs text-stone-500">Atomic with rollback</p></div>
        </div>
      </section>
      <div className="mt-5 flex items-start gap-3 rounded-[18px] border border-amber-900/40 bg-amber-950/10 px-5 py-4 text-xs leading-5 text-amber-200/70"><WarningCircle size={18} className="mt-0.5 shrink-0" /><span><strong className="font-medium text-amber-200">Do not store private keys in PostgreSQL.</strong> Use a restricted filesystem or secret manager, encrypt at rest, reject unencrypted keys, and never include key material in logs or audit payloads.</span></div>
      <div className="mt-4 flex items-center gap-3 text-xs text-stone-700"><LockKey size={16} />Recommended production path: terminate TLS in Caddy, Nginx, Traefik, or a managed load balancer with automated renewal.</div>
    </div>
  )
}
