import { Certificate, LockKey, UploadSimple, WarningCircle } from '@phosphor-icons/react'
import { useState, type FormEvent } from 'react'
import { api } from '../../api/client'
import { PageHeader } from '../../components/PageHeader'
import { ErrorState, LoadingState } from '../../components/StatePanel'
import { useApi } from '../../hooks/useApi'

export function CertificatesSettingsPage() {
  const { data: certificate, error, loading, reload } = useApi(() => api.tlsCertificate(), [])
  const [uploading, setUploading] = useState(false)
  const [actionError, setActionError] = useState('')
  const [actionMessage, setActionMessage] = useState('')

  async function upload(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    const chain = form.get('certificate')
    const key = form.get('privateKey')
    if (!(chain instanceof File) || !(key instanceof File)) return
    setUploading(true); setActionError(''); setActionMessage('')
    try {
      await api.uploadTlsCertificate(chain, key)
      event.currentTarget.reset()
      setActionMessage('Certificate installed. The HTTPS gateway is reloading for new connections.')
      window.setTimeout(() => { void reload() }, 2500)
    }
    catch (reason) { setActionError(reason instanceof Error ? reason.message : 'Certificate installation failed') }
    finally { setUploading(false) }
  }

  return <div className="page-reveal">
    <PageHeader eyebrow="Transport security" title="TLS certificates" detail="Install and atomically rotate the certificate chain shared by management on port 8443 and the agent gateway on port 8444." action={<span className="settings-state">TLS · 8443 / 8444</span>} />
    {loading ? <LoadingState /> : error ? <ErrorState message={error} retry={reload} /> : <section className="panel overflow-hidden">
      <div className="grid gap-6 px-6 py-7 md:grid-cols-[1fr_1.15fr] md:px-7">
        <div><span className="grid size-11 place-items-center rounded-xl border border-stone-800 bg-[#f7f3eb] text-[#4f6f5c]"><Certificate size={22} weight="duotone" /></span><h2 className="mt-5 text-lg font-medium tracking-tight text-stone-200">{certificate ? 'Active certificate' : 'Certificate upload'}</h2>
          {certificate ? <dl className="mt-4 space-y-3 text-xs text-stone-500"><div><dt className="detail-label">Subject</dt><dd className="mt-1 break-all">{certificate.subject}</dd></div><div><dt className="detail-label">Issuer</dt><dd className="mt-1 break-all">{certificate.issuer}</dd></div><div><dt className="detail-label">DNS names</dt><dd className="mt-1">{certificate.hostnames.join(', ') || 'None'}</dd></div><div><dt className="detail-label">Valid until</dt><dd className="mt-1">{new Date(certificate.not_valid_after).toLocaleString()}</dd></div><div><dt className="detail-label">SHA-256</dt><dd className="mt-1 break-all font-mono text-[10px]">{certificate.fingerprint}</dd></div></dl> : <p className="mt-2 text-xs leading-5 text-stone-600">A short-lived self-signed localhost certificate is generated at first boot so the platform never exposes plaintext HTTP.</p>}</div>
        <form className="rounded-[18px] border border-dashed border-stone-700 bg-[#f7f3eb] p-6" onSubmit={upload}>
          <UploadSimple size={25} className="text-stone-600" /><p className="mt-4 text-sm text-stone-300">Rotate certificate</p><p className="mt-2 text-xs leading-5 text-stone-600">Upload the server certificate or certificate chain as a .crt/.pem file and its matching unencrypted .key/.pem private key. PEM and DER encoding are accepted.</p>
          <label className="form-field mt-5"><span>HTTPS Certificate (.crt)</span><input name="certificate" type="file" accept=".pem,.crt,.cer,application/x-x509-ca-cert,application/pkix-cert,text/plain" required /></label>
          <label className="form-field mt-4"><span>HTTPS Private Key (.key)</span><input name="privateKey" type="file" accept=".pem,.key,application/pkcs8,application/x-pem-file,text/plain" required /></label>
          {actionMessage && <p className="mt-4 text-xs text-emerald-700">{actionMessage}</p>}
          {actionError && <p className="mt-4 text-xs text-rose-300">{actionError}</p>}
          <button className="button-primary mt-5" disabled={uploading}>{uploading ? 'Validating and installing' : 'Install certificate'}</button>
        </form>
      </div>
      <div className="grid divide-y divide-stone-800 border-t border-stone-800 bg-[#f7f3eb] sm:grid-cols-3 sm:divide-x sm:divide-y-0"><div className="px-5 py-4"><p className="detail-label">Formats</p><p className="mt-2 text-xs text-stone-500">CRT + KEY · PEM or DER</p></div><div className="px-5 py-4"><p className="detail-label">Validation</p><p className="mt-2 text-xs text-stone-500">Validity and key match</p></div><div className="px-5 py-4"><p className="detail-label">Rotation</p><p className="mt-2 text-xs text-stone-500">Atomic gateway reload</p></div></div>
    </section>}
    <div className="mt-5 flex items-start gap-3 rounded-[18px] border border-amber-900/40 bg-amber-950/10 px-5 py-4 text-xs leading-5 text-amber-200/70"><WarningCircle size={18} className="mt-0.5 shrink-0" /><span><strong className="font-medium text-amber-200">Private keys never leave the backend response.</strong> They are encrypted in PostgreSQL, materialized with restricted permissions in the internal TLS volume, and omitted from audit data.</span></div>
    <div className="mt-4 flex items-center gap-3 text-xs text-stone-700"><LockKey size={16} />Changing the settings encryption key requires re-encrypting stored secrets first.</div>
  </div>
}
