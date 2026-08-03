import { Check, Copy, DownloadSimple, Package, TerminalWindow, X } from '@phosphor-icons/react'
import { useMemo, useState } from 'react'
import { api } from '../api/client'
import type { AgentPackage } from '../types'

interface AgentDownloadPanelProps {
  packages: AgentPackage[]
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

export function AgentDownloadPanel({ packages, enrollmentToken, close }: AgentDownloadPanelProps) {
  const [downloading, setDownloading] = useState<string | null>(null)
  const [error, setError] = useState('')
  const [copied, setCopied] = useState<string | null>(null)
  const [selectedPackageId, setSelectedPackageId] = useState(packages[0]?.id ?? '')
  const platformUrl = window.location.origin
  const tokenValue = enrollmentToken || 'lsa_enroll_REPLACE_WITH_ONE_TIME_TOKEN'
  const selectedPackage = packages.find(agentPackage => agentPackage.id === selectedPackageId) ?? packages[0]
  const installCommand = useMemo(
    () => {
      if (!selectedPackage) return 'No agent package is available.'
      const enrollment = `sudo lsa-agent-enroll --platform-url ${shellQuote(platformUrl)} --token ${shellQuote(tokenValue)}`
      if (selectedPackage.package_format === 'deb') {
        return `sudo apt install ./${selectedPackage.filename}\n${enrollment}`
      }
      if (selectedPackage.package_format === 'rpm') {
        return `sudo dnf install ./${selectedPackage.filename}\n${enrollment}`
      }
      return `tar -xzf ${selectedPackage.filename}\ncd lsa-agent-${selectedPackage.version}\nsudo ./install.sh --platform-url ${shellQuote(platformUrl)} --token ${shellQuote(tokenValue)}`
    },
    [platformUrl, selectedPackage, tokenValue],
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

  return <section className="panel mb-7 overflow-hidden" aria-labelledby="agent-download-title">
    <div className="flex items-start justify-between gap-5 border-b border-stone-800 px-6 py-5">
      <div>
        <p className="section-label">Secure distribution</p>
        <h2 id="agent-download-title" className="mt-2 text-base font-semibold text-stone-100">Install the unified Linux agent</h2>
        <p className="mt-2 max-w-2xl text-xs leading-5 text-stone-500">The signed-in administrator downloads the versioned runtime and all audit controls. Verify its checksum before installing it on a managed host.</p>
      </div>
      <button className="icon-button shrink-0" onClick={close} aria-label="Close agent downloads"><X size={16} /></button>
    </div>

    {error && <div className="border-b border-rose-900/40 bg-rose-950/10 px-6 py-3 text-xs text-rose-300">{error}</div>}

    {!packages.length ? <div className="px-6 py-10 text-sm text-stone-500">No agent release is available.</div> : packages.map(agentPackage => <div key={agentPackage.id} className={`grid gap-6 border-b border-stone-800 px-6 py-6 last:border-b-0 lg:grid-cols-[minmax(0,1fr)_auto] lg:items-center ${selectedPackage?.id === agentPackage.id ? 'bg-emerald-950/10' : ''}`}>
      <div className="flex min-w-0 items-start gap-4">
        <div className="flex size-11 shrink-0 items-center justify-center rounded-xl border border-emerald-900/40 bg-emerald-950/20 text-emerald-300"><Package size={21} /></div>
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2"><h3 className="text-sm font-medium text-stone-200">LSA Agent {agentPackage.version}</h3><span className="settings-state">{agentPackage.package_format.toUpperCase()}</span><span className="settings-state">{agentPackage.release_channel}</span>{agentPackage.audit_only && <span className="settings-state">Audit only</span>}</div>
          <p className="mt-2 text-xs text-stone-500">{agentPackage.operating_system} · {agentPackage.architecture} · {formatBytes(agentPackage.size_bytes)}</p>
          <div className="mt-3 flex min-w-0 items-center gap-2">
            <code className="truncate font-mono text-[10px] text-stone-600" title={agentPackage.sha256}>SHA-256 {agentPackage.sha256}</code>
            <button className="text-stone-500 transition hover:text-emerald-300 active:scale-[0.98]" onClick={() => void copy('checksum', agentPackage.sha256)} aria-label="Copy package checksum">{copied === 'checksum' ? <Check size={14} /> : <Copy size={14} />}</button>
          </div>
        </div>
      </div>
      <div className="flex flex-wrap justify-end gap-2">
        <button className="button-secondary min-w-28" onClick={() => setSelectedPackageId(agentPackage.id)}>{selectedPackage?.id === agentPackage.id ? <Check size={16} /> : <TerminalWindow size={16} />} {selectedPackage?.id === agentPackage.id ? 'Selected' : 'Install steps'}</button>
        <button className="button-primary min-w-40" disabled={downloading === agentPackage.id} onClick={() => { setSelectedPackageId(agentPackage.id); void download(agentPackage) }}><DownloadSimple size={16} /> {downloading === agentPackage.id ? 'Downloading…' : 'Download package'}</button>
      </div>
    </div>)}

    <div className="border-t border-stone-800 bg-[#101411] px-6 py-6">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-2 text-xs font-medium text-stone-300"><TerminalWindow size={16} className="text-emerald-400" /> Install and enroll {selectedPackage ? `· ${selectedPackage.package_format.toUpperCase()}` : ''}</div>
        <button className="button-secondary min-h-9 px-3" onClick={() => void copy('command', installCommand)}>{copied === 'command' ? <Check size={14} /> : <Copy size={14} />} {copied === 'command' ? 'Copied' : 'Copy command'}</button>
      </div>
      <pre className="mt-4 overflow-x-auto rounded-xl border border-stone-800 bg-[#0d110e] p-4 font-mono text-[11px] leading-6 text-emerald-200"><code>{installCommand}</code></pre>
      <p className="mt-3 text-[11px] leading-5 text-stone-600">Package installation stages the audit-only runtime but does not start it. Enrollment requires Python 3.11+, systemd, and network access to install constrained Python dependencies. For a private CA, copy its certificate to the host and add <code className="text-stone-500">--ca-bundle /path/to/ca.pem</code>.</p>
      {!enrollmentToken && <p className="mt-2 text-[11px] text-amber-300/80">Create an enrollment token before running the command and replace the token placeholder.</p>}
    </div>
  </section>
}
