import { Check, Copy, Key, X } from '@phosphor-icons/react'
import { useState, type FormEvent } from 'react'
import { api } from '../api/client'
import type { Host, TokenCreated } from '../types'

export function CreateTokenPanel({ hosts, close, created }: { hosts: Host[]; close: () => void; created: () => void }) {
  const [name, setName] = useState('')
  const [hostId, setHostId] = useState('')
  const [lifetime, setLifetime] = useState('90')
  const [result, setResult] = useState<TokenCreated | null>(null)
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [copied, setCopied] = useState(false)

  async function submit(event: FormEvent) {
    event.preventDefault()
    setSubmitting(true)
    setError('')
    try {
      const days = Number(lifetime)
      const expiresAt = days > 0 ? new Date(Date.now() + days * 86_400_000).toISOString() : undefined
      const token = await api.createToken({
        name,
        host_id: hostId || undefined,
        expires_at: expiresAt,
      })
      setResult(token)
      created()
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Token creation failed')
    } finally {
      setSubmitting(false)
    }
  }

  async function copyToken() {
    if (!result) return
    await navigator.clipboard.writeText(result.token)
    setCopied(true)
    window.setTimeout(() => setCopied(false), 1600)
  }

  return (
    <div className="fixed inset-0 z-30 grid place-items-center bg-[#080b09]/80 p-4 backdrop-blur-sm" role="dialog" aria-modal="true" aria-labelledby="token-dialog-title">
      <section className="panel max-h-[92dvh] w-full max-w-xl overflow-y-auto p-6 md:p-8">
        <div className="flex items-start justify-between gap-6">
          <div><p className="section-label">Scanner credential</p><h2 id="token-dialog-title" className="mt-3 text-2xl font-medium tracking-[-0.04em]">Issue ingestion token</h2></div>
          <button className="icon-button shrink-0" onClick={close} aria-label="Close token dialog"><X size={17} /></button>
        </div>
        {!result ? (
          <form className="mt-8 space-y-5" onSubmit={submit}>
            <label className="form-field"><span>Credential name</span><input required value={name} onChange={(event) => setName(event.target.value)} placeholder="Production scanner controller" /><small>Use a name that identifies the controller or automation owning this secret.</small></label>
            <label className="form-field"><span>Host scope</span><select className="select-input min-h-11 w-full" value={hostId} onChange={(event) => setHostId(event.target.value)}><option value="">All tenant hosts</option>{hosts.map((host) => <option key={host.id} value={host.id}>{host.hostname}</option>)}</select><small>Host-scoped tokens cannot submit evidence for a different platform identity.</small></label>
            <label className="form-field"><span>Lifetime</span><select className="select-input min-h-11 w-full" value={lifetime} onChange={(event) => setLifetime(event.target.value)}><option value="30">30 days</option><option value="90">90 days</option><option value="180">180 days</option><option value="365">One year</option><option value="0">No expiry</option></select></label>
            {!hostId && <p className="rounded-xl border border-amber-900/40 bg-amber-950/15 px-4 py-3 text-xs leading-5 text-amber-200">This credential will be tenant-wide. Prefer a host scope unless one controller intentionally reports for several systems.</p>}
            {error && <p className="rounded-xl border border-rose-900/50 bg-rose-950/20 px-4 py-3 text-xs text-rose-300">{error}</p>}
            <div className="flex justify-end gap-3 pt-2"><button type="button" className="button-secondary" onClick={close}>Cancel</button><button className="button-primary" disabled={submitting}><Key size={16} />{submitting ? 'Issuing token' : 'Issue token'}</button></div>
          </form>
        ) : (
          <div className="mt-8">
            <p className="rounded-xl border border-emerald-900/50 bg-emerald-950/20 px-4 py-3 text-xs leading-5 text-emerald-300">Copy this secret now. LSA stores only its hash and cannot reveal it again.</p>
            <div className="mt-5 rounded-xl border border-stone-800 bg-stone-950 p-4"><p className="detail-label">Ingestion token</p><div className="mt-3 flex items-center gap-3"><code className="min-w-0 flex-1 overflow-x-auto font-mono text-xs leading-6 text-stone-300">{result.token}</code><button className="icon-button shrink-0" onClick={() => void copyToken()} aria-label="Copy ingestion token">{copied ? <Check size={16} /> : <Copy size={16} />}</button></div></div>
            <p className="mt-4 text-xs leading-5 text-stone-600">Store the secret in a mode-0600 file on the Ansible controller. Never place it directly in inventory or source control.</p>
            <div className="mt-7 flex justify-end"><button className="button-primary" onClick={close}>Done</button></div>
          </div>
        )}
      </section>
    </div>
  )
}
