import { Check, Copy, Key } from '@phosphor-icons/react'
import { useState, type FormEvent } from 'react'
import { api } from '../api/client'
import type { Host, SigningKey } from '../types'
import { Button } from './ui/Button'
import { Dialog } from './ui/Dialog'

export function CreateSigningKeyPanel({ hosts, close, created }: { hosts: Host[]; close: () => void; created: () => void }) {
  const [name, setName] = useState('')
  const [publicKey, setPublicKey] = useState('')
  const [hostId, setHostId] = useState('')
  const [lifetime, setLifetime] = useState('365')
  const [result, setResult] = useState<SigningKey | null>(null)
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [copied, setCopied] = useState(false)

  async function submit(event: FormEvent) {
    event.preventDefault()
    setSubmitting(true)
    setError('')
    try {
      const days = Number(lifetime)
      const key = await api.createSigningKey({
        name,
        public_key: publicKey.trim(),
        host_id: hostId || undefined,
        expires_at: days > 0 ? new Date(Date.now() + days * 86_400_000).toISOString() : undefined,
      })
      setResult(key)
      created()
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Signing key registration failed')
    } finally {
      setSubmitting(false)
    }
  }

  const configuration = result ? `lsa_signing_key_file: /secure/path/lsa-signing-key.pem\nlsa_signing_key_id: ${result.id}` : ''
  async function copyConfiguration() {
    await navigator.clipboard.writeText(configuration)
    setCopied(true)
    window.setTimeout(() => setCopied(false), 1600)
  }

  return (
    <Dialog open onOpenChange={(open) => { if (!open) close() }} eyebrow="Report provenance" title="Register signing key">
        {!result ? (
          <form className="space-y-5" onSubmit={submit}>
            <div className="rounded-xl border border-stone-200 bg-[#eee8dd]/50 px-4 py-3 text-xs leading-5 text-stone-400">
              Generate the private key on the scanner controller: <code className="font-mono text-[#4f6f5c]">python3 scanner/scripts/generate_signing_key.py /secure/path/lsa-signing-key.pem</code>. Paste only the printed public key below.
            </div>
            <label className="form-field"><span>Key name</span><input required value={name} onChange={(event) => setName(event.target.value)} placeholder="Production controller signing key" /></label>
            <label className="form-field"><span>Ed25519 public key</span><input required value={publicKey} onChange={(event) => setPublicKey(event.target.value)} placeholder="Base64-encoded public key" spellCheck={false} autoComplete="off" /><small>The private key never leaves the controller and must not be pasted here.</small></label>
            <label className="form-field"><span>Host scope</span><select className="select-input min-h-11 w-full" value={hostId} onChange={(event) => setHostId(event.target.value)}><option value="">All tenant hosts</option>{hosts.map((host) => <option key={host.id} value={host.id}>{host.hostname}</option>)}</select><small>A scoped key cannot validate a bundle for another host.</small></label>
            <label className="form-field"><span>Lifetime</span><select className="select-input min-h-11 w-full" value={lifetime} onChange={(event) => setLifetime(event.target.value)}><option value="90">90 days</option><option value="180">180 days</option><option value="365">One year</option><option value="730">Two years</option><option value="0">No expiry</option></select></label>
            {!hostId && <p className="rounded-xl border border-amber-900/40 bg-amber-950/15 px-4 py-3 text-xs leading-5 text-amber-800">This key can sign reports for every host in the tenant. Prefer a host scope for dedicated controllers.</p>}
            {error && <p className="rounded-xl border border-rose-900/50 bg-rose-950/20 px-4 py-3 text-xs text-rose-700">{error}</p>}
            <div className="flex justify-end gap-3 pt-2"><Button type="button" onClick={close}>Cancel</Button><Button variant="primary" disabled={submitting}><Key size={16} />{submitting ? 'Registering key' : 'Register key'}</Button></div>
          </form>
        ) : (
          <div className="mt-8">
            <p className="rounded-xl border border-[#b8c5ba] bg-[#edf1eb] px-4 py-3 text-xs leading-5 text-[#4f6f5c]">Key registered. Add this key ID and the private-key path to the scanner configuration.</p>
            <div className="mt-5 rounded-xl border border-stone-200 bg-[#eee8dd] p-4"><p className="detail-label">Ansible variables</p><div className="mt-3 flex items-start gap-3"><code className="min-w-0 flex-1 whitespace-pre-wrap font-mono text-xs leading-6 text-stone-700">{configuration}</code><Button variant="ghost" size="icon" className="shrink-0" onClick={() => void copyConfiguration()} aria-label="Copy signing key configuration">{copied ? <Check size={16} /> : <Copy size={16} />}</Button></div></div>
            <p className="mt-4 text-xs leading-5 text-stone-600">Keep the PEM file mode 0600 and outside source control. Revoking this key immediately blocks future bundles signed by it.</p>
            <div className="mt-7 flex justify-end"><Button variant="primary" onClick={close}>Done</Button></div>
          </div>
        )}
    </Dialog>
  )
}
