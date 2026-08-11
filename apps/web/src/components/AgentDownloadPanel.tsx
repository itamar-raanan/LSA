import { Check, Copy, DownloadSimple, Package, TerminalWindow } from '@phosphor-icons/react'
import { useMemo, useState } from 'react'
import { api } from '../api/client'
import type { AgentPackage, PlatformCommandTrust } from '../types'
import { Dialog } from './ui/Dialog'

interface AgentDownloadPanelProps {
  packages: AgentPackage[]
  platformUrl: string
  platformTrust: PlatformCommandTrust
  enrollmentToken?: string
  close: () => void
}

function formatBytes(value: number): string {
  if (value < 1024) return `${value} B`
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`
  return `${(value / (1024 * 1024)).toFixed(1)} MB`
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`
}

export function AgentDownloadPanel({ packages, platformUrl, platformTrust, enrollmentToken, close }: AgentDownloadPanelProps) {
  const [downloading, setDownloading] = useState<string | null>(null)
  const [error, setError] = useState('')
  const [copied, setCopied] = useState<string | null>(null)
  const [selectedPackageId, setSelectedPackageId] = useState(packages[0]?.id ?? '')
  const tokenValue = enrollmentToken || 'lsa_enroll_REPLACE_WITH_ONE_TIME_TOKEN'
  const selectedPackage = packages.find(agentPackage => agentPackage.id === selectedPackageId) ?? packages[0]
  const installCommand = useMemo(
    () => {
      if (!selectedPackage) return 'No agent package is available.'
      const trustArgument = `--platform-command-key ${shellQuote(platformTrust.public_key)}`
      const enrollment = `sudo lsa-agent-enroll --platform-url ${shellQuote(platformUrl)} --token ${shellQuote(tokenValue)} ${trustArgument}`
      if (selectedPackage.package_format === 'deb') {
        return `sudo apt install ./${selectedPackage.filename}\n${enrollment}`
      }
      if (selectedPackage.package_format === 'rpm') {
        return `sudo dnf install ./${selectedPackage.filename}\n${enrollment}`
      }
      return `tar -xzf ${selectedPackage.filename}\ncd lsa-agent-${selectedPackage.version}\nsudo ./install.sh --platform-url ${shellQuote(platformUrl)} --token ${shellQuote(tokenValue)} ${trustArgument}`
    },
    [platformTrust.public_key, platformUrl, selectedPackage, tokenValue],
  )

  async function copy(label: string, value: string) {
    await navigator.clipboard.writeText(value)
    setCopied(label)
    window.setTimeout(() => setCopied(null), 1800)
  }

  async function download(agentPackage: AgentPackage) {
    setDownloading(agentPackage.id)
    setError('')
    try {
      const result = await api.downloadAgentPackage(agentPackage.id)
      const url = URL.createObjectURL(result.blob)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = result.filename
      document.body.appendChild(anchor)
      anchor.click()
      anchor.remove()
      URL.revokeObjectURL(url)
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Agent package download failed')
    } finally {
      setDownloading(null)
    }
  }

  return <Dialog open onOpenChange={(open) => { if (!open) close() }} size="lg" eyebrow="Secure distribution" title="Install the unified Linux agent" description="Download the versioned runtime and audit controls, verify the checksum, then enroll the host with the dedicated agent gateway.">
    {error && <div className="mb-5 border border-rose-900/40 bg-rose-950/10 px-4 py-3 text-xs text-rose-300">{error}</div>}

    {!selectedPackage ? <div className="py-10 text-sm text-stone-500">No agent release is available.</div> : <div className="grid gap-5 border-b border-stone-800 pb-6 lg:grid-cols-[minmax(0,1fr)_240px] lg:items-end">
      <div className="flex min-w-0 items-start gap-4">
        <div className="flex size-11 shrink-0 items-center justify-center rounded-xl border border-[#b8c5ba] bg-[#edf1eb] text-[#4f6f5c]"><Package size={21} /></div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2"><h3 className="text-sm font-medium text-stone-200">LSA Agent {selectedPackage.version}</h3><span className="settings-state">{selectedPackage.release_channel}</span>{selectedPackage.audit_only && <span className="settings-state">Audit only</span>}</div>
          <p className="mt-2 text-xs text-stone-500">{selectedPackage.operating_system} · {selectedPackage.architecture} · {formatBytes(selectedPackage.size_bytes)}</p>
          <div className="mt-3 flex min-w-0 items-center gap-2">
            <code className="truncate font-mono text-[10px] text-stone-600" title={selectedPackage.sha256}>SHA-256 {selectedPackage.sha256}</code>
            <button className="text-stone-500 transition hover:text-[#4f6f5c] active:scale-[0.98]" onClick={() => void copy('checksum', selectedPackage.sha256)} aria-label="Copy package checksum">{copied === 'checksum' ? <Check size={14} /> : <Copy size={14} />}</button>
          </div>
        </div>
      </div>
      <div className="grid gap-3">
        <label className="form-field">Package<select className="select-input w-full" aria-label="Agent package" value={selectedPackage.id} onChange={event => setSelectedPackageId(event.target.value)}>{packages.map(agentPackage => <option key={agentPackage.id} value={agentPackage.id}>{agentPackage.package_format.toUpperCase()} · {agentPackage.operating_system}</option>)}</select></label>
        <button className="button-primary w-full" disabled={downloading === selectedPackage.id} onClick={() => void download(selectedPackage)}><DownloadSimple size={16} /> {downloading === selectedPackage.id ? 'Downloading…' : 'Download Package'}</button>
      </div>
    </div>}

    <div className="bg-[#f7f3eb] pt-6">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-2 text-xs font-medium text-stone-300"><TerminalWindow size={16} className="text-[#4f6f5c]" /> Install and enroll {selectedPackage ? `· ${selectedPackage.package_format.toUpperCase()}` : ''}</div>
        <button className="button-secondary min-h-9 px-3" onClick={() => void copy('command', installCommand)}>{copied === 'command' ? <Check size={14} /> : <Copy size={14} />} {copied === 'command' ? 'Copied' : 'Copy command'}</button>
      </div>
      <pre className="mt-4 overflow-x-auto rounded-xl border border-stone-800 bg-[#f7f3eb] p-4 font-mono text-[11px] leading-6 text-[#4f6f5c]"><code>{installCommand}</code></pre>
      <div className="mt-3 flex items-start gap-2 text-[11px] leading-5 text-stone-600"><Check size={14} className="mt-0.5 shrink-0 text-[#4f6f5c]" /><p><strong className="font-medium text-stone-700">Platform identity is pinned during enrollment.</strong> The public key is not secret. The agent verifies the signed enrollment proof before saving credentials. TLS certificate verification remains disabled, while platform responses are authenticated by this pinned Ed25519 identity.</p></div>
      <p className="mt-2 break-all font-mono text-[10px] text-stone-500">Platform fingerprint · SHA256:{platformTrust.fingerprint}</p>
      {!enrollmentToken && <p className="mt-2 text-[11px] text-amber-300/80">Create an enrollment token before running the command and replace the token placeholder.</p>}
    </div>
  </Dialog>
}
