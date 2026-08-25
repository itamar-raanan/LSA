import { Check, Copy } from '@phosphor-icons/react'
import { useState, type FormEvent } from 'react'
import { api } from '../api/client'
import type { Host, TokenCreated } from '../types'
import { Button } from './ui/Button'
import { Dialog } from './ui/Dialog'

export function EnrollHostPanel({ close, created }: { close: () => void; created: () => void }) {
  const [form, setForm] = useState({ hostname: '', fqdn: '', os_family: 'debian', os_version: '13', environment: 'production', owner: '' })
  const [result, setResult] = useState<{ host: Host; token: TokenCreated } | null>(null)
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [copied, setCopied] = useState('')

  function update(field: keyof typeof form, value: string) {
    setForm((current) => ({ ...current, [field]: value }))
  }

  async function submit(event: FormEvent) {
    event.preventDefault()
    setSubmitting(true)
    setError('')
    try {
      const host = await api.createHost({
        hostname: form.hostname,
        fqdn: form.fqdn || undefined,
        os_family: form.os_family,
        os_version: form.os_version,
        tags: { environment: form.environment, owner: form.owner || 'unassigned' },
      })
      const token = await api.createToken({ name: `${form.hostname} scanner`, host_id: host.id })
      setResult({ host, token })
      created()
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Enrollment failed')
    } finally {
      setSubmitting(false)
    }
  }

  async function copy(label: string, value: string) {
    await navigator.clipboard.writeText(value)
    setCopied(label)
    window.setTimeout(() => setCopied(''), 1500)
  }

  return (
    <Dialog open onOpenChange={(open) => { if (!open) close() }} eyebrow="Host identity" title="Enroll a Linux host" size="lg">
        {!result ? (
          <form onSubmit={submit}>
            <div className="grid gap-5 sm:grid-cols-2">
              <label className="form-field"><span>Hostname</span><input required value={form.hostname} onChange={(event) => update('hostname', event.target.value)} placeholder="web-prod-01" /></label>
              <label className="form-field"><span>FQDN</span><input value={form.fqdn} onChange={(event) => update('fqdn', event.target.value)} placeholder="web-prod-01.example.com" /></label>
              <label className="form-field"><span>Operating-system family</span><select className="select-input min-h-11 w-full" value={form.os_family} onChange={(event) => update('os_family', event.target.value)}><option value="debian">Debian</option><option value="ubuntu">Ubuntu</option><option value="rhel">RHEL family</option></select></label>
              <label className="form-field"><span>Version</span><input required value={form.os_version} onChange={(event) => update('os_version', event.target.value)} /></label>
              <label className="form-field"><span>Environment</span><input value={form.environment} onChange={(event) => update('environment', event.target.value)} placeholder="production" /></label>
              <label className="form-field"><span>Owner</span><input value={form.owner} onChange={(event) => update('owner', event.target.value)} placeholder="platform" /></label>
            </div>
            {error && <p className="mt-5 rounded-xl border border-rose-900/50 bg-rose-950/20 px-4 py-3 text-xs text-rose-700">{error}</p>}
            <div className="mt-7 flex justify-end gap-3"><Button type="button" onClick={close}>Cancel</Button><Button variant="primary" disabled={submitting}>{submitting ? 'Creating identity' : 'Create host and token'}</Button></div>
          </form>
        ) : (
          <div className="mt-8">
            <div className="rounded-xl border border-[#b8c5ba] bg-[#edf1eb] px-4 py-3 text-xs leading-5 text-[#4f6f5c]">Enrollment created. Copy the token now; the platform stores only its hash and cannot reveal it again.</div>
            <CredentialRow label="Host UUID" value={result.host.id} copied={copied} copy={copy} />
            <CredentialRow label="Ingestion token" value={result.token.token} copied={copied} copy={copy} />
            <div className="mt-6"><p className="detail-label">Ansible inventory variables</p><pre className="evidence-block">{`lsa_host_id=${result.host.id}\nlsa_ingest_token_file=~/.lsa/token`}</pre></div>
            <div className="mt-7 flex justify-end"><Button variant="primary" onClick={close}>Done</Button></div>
          </div>
        )}
    </Dialog>
  )
}

function CredentialRow({ label, value, copied, copy }: { label: string; value: string; copied: string; copy: (label: string, value: string) => Promise<void> }) {
  return <div className="mt-5"><p className="detail-label">{label}</p><div className="mt-2 flex items-center gap-3 rounded-xl border border-stone-200 bg-[#eee8dd] px-4 py-3"><code className="min-w-0 flex-1 overflow-x-auto font-mono text-xs text-stone-700">{value}</code><Button variant="ghost" size="icon" className="shrink-0" aria-label={`Copy ${label}`} onClick={() => void copy(label, value)}>{copied === label ? <Check size={16} /> : <Copy size={16} />}</Button></div></div>
}
