import { Check, Copy, Key } from '@phosphor-icons/react'
import { useState, type FormEvent } from 'react'
import { api } from '../api/client'
import type { Host, TokenCreated } from '../types'
import { Button } from './ui/Button'
import { Dialog } from './ui/Dialog'

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
    <Dialog open onOpenChange={(open) => { if (!open) close() }} eyebrow="Scanner credential" title="Issue ingestion token">
        {!result ? (
          <form className="space-y-5" onSubmit={submit}>
            <label className="form-field"><span>Credential name</span><input required value={name} onChange={(event) => setName(event.target.value)} placeholder="Production scanner controller" /><small>Use a name that identifies the controller or automation owning this secret.</small></label>
            <label className="form-field"><span>Host scope</span><select className="select-input min-h-11 w-full" value={hostId} onChange={(event) => setHostId(event.target.value)}><option value="">All tenant hosts</option>{hosts.map((host) => <option key={host.id} value={host.id}>{host.hostname}</option>)}</select><small>Host-scoped tokens cannot submit evidence for a different platform identity.</small></label>
            <label className="form-field"><span>Lifetime</span><select className="select-input min-h-11 w-full" value={lifetime} onChange={(event) => setLifetime(event.target.value)}><option value="30">30 days</option><option value="90">90 days</option><option value="180">180 days</option><option value="365">One year</option><option value="0">No expiry</option></select></label>
            {!hostId && <p className="rounded-xl border border-amber-900/40 bg-amber-950/15 px-4 py-3 text-xs leading-5 text-amber-200">This credential will be tenant-wide. Prefer a host scope unless one controller intentionally reports for several systems.</p>}
            {error && <p className="rounded-xl border border-rose-900/50 bg-rose-950/20 px-4 py-3 text-xs text-rose-300">{error}</p>}
            <div className="flex justify-end gap-3 pt-2"><Button type="button" onClick={close}>Cancel</Button><Button variant="primary" disabled={submitting}><Key size={16} />{submitting ? 'Issuing token' : 'Issue token'}</Button></div>
          </form>
        ) : (
          <div className="mt-8">
            <p className="rounded-xl border border-[#b8c5ba] bg-[#edf1eb] px-4 py-3 text-xs leading-5 text-[#4f6f5c]">Copy this secret now. LSA stores only its hash and cannot reveal it again.</p>
            <div className="mt-5 rounded-xl border border-stone-800 bg-[#eee8dd] p-4"><p className="detail-label">Ingestion token</p><div className="mt-3 flex items-center gap-3"><code className="min-w-0 flex-1 overflow-x-auto font-mono text-xs leading-6 text-stone-300">{result.token}</code><Button variant="ghost" size="icon" className="shrink-0" onClick={() => void copyToken()} aria-label="Copy ingestion token">{copied ? <Check size={16} /> : <Copy size={16} />}</Button></div></div>
            <p className="mt-4 text-xs leading-5 text-stone-600">Store the secret in a mode-0600 file on the Ansible controller. Never place it directly in inventory or source control.</p>
            <div className="mt-7 flex justify-end"><Button variant="primary" onClick={close}>Done</Button></div>
          </div>
        )}
    </Dialog>
  )
}
