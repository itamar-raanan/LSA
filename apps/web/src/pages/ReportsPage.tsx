import {
  ArrowRight, CheckCircle, DownloadSimple, FileZip, ShieldCheck,
  TerminalWindow, UploadSimple, WarningCircle,
} from '@phosphor-icons/react'
import { useEffect, useRef, useState, type DragEvent } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import { useAuth } from '../auth/useAuth'
import { PageHeader } from '../components/PageHeader'
import type { OfflineScannerPackage } from '../types'

type UploadStatus = 'idle' | 'ready' | 'uploading' | 'success' | 'error'

function fileSize(bytes: number) {
  return bytes >= 1024 * 1024 ? `${(bytes / (1024 * 1024)).toFixed(1)} MB` : `${Math.ceil(bytes / 1024)} KB`
}

export function ReportsPage() {
  const { user } = useAuth()
  const inputRef = useRef<HTMLInputElement>(null)
  const [file, setFile] = useState<File | null>(null)
  const [token, setToken] = useState('')
  const [status, setStatus] = useState<UploadStatus>('idle')
  const [message, setMessage] = useState('')
  const [scannerPackage, setScannerPackage] = useState<OfflineScannerPackage | null>(null)
  const [downloadStatus, setDownloadStatus] = useState<'idle' | 'downloading' | 'error'>('idle')

  useEffect(() => {
    let active = true
    api.offlineScannerPackage()
      .then((packageInfo) => { if (active) setScannerPackage(packageInfo) })
      .catch(() => { if (active) setDownloadStatus('error') })
    return () => { active = false }
  }, [])

  function selectFile(selected?: File) {
    if (!selected) return
    if (!selected.name.toLowerCase().endsWith('.zip')) {
      setStatus('error'); setMessage('Choose the lsa-report-*.zip file created by the offline scanner.'); return
    }
    setFile(selected); setStatus('ready'); setMessage('')
  }

  function drop(event: DragEvent) {
    event.preventDefault()
    selectFile(event.dataTransfer.files[0])
  }

  async function downloadScanner() {
    setDownloadStatus('downloading')
    try {
      const download = await api.downloadOfflineScannerPackage()
      const url = URL.createObjectURL(download.blob)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = download.filename
      document.body.appendChild(anchor)
      anchor.click()
      anchor.remove()
      URL.revokeObjectURL(url)
      setDownloadStatus('idle')
    } catch {
      setDownloadStatus('error')
    }
  }

  async function upload() {
    if (!file || !token) return
    setStatus('uploading'); setMessage('')
    try {
      const result = await api.uploadBundle(file, token)
      setStatus('success')
      setMessage(`Report accepted. LSA imported ${String(result.findings_imported)} findings and updated host ${String(result.host_id)}.`)
    } catch (reason) {
      setStatus('error'); setMessage(reason instanceof Error ? reason.message : 'The report could not be imported. Check the token, signing key, and bundle integrity, then try again.')
    }
  }

  const downloadAction = <button className="button-primary" disabled={downloadStatus === 'downloading'} onClick={() => void downloadScanner()}><DownloadSimple size={16} />{downloadStatus === 'downloading' ? 'Preparing Download' : 'Download Offline Scanner'}</button>

  return <div className="page-reveal">
    <PageHeader eyebrow="Offline Workflow" title="Evidence Intake" detail="Collect read-only posture from an isolated Linux host, then import the signed evidence bundle into LSA." action={downloadAction} />

    <section className="panel overflow-hidden">
      <div className="border-b border-stone-200 px-5 py-5 sm:px-7">
        <h2 className="text-base font-semibold text-stone-800">From scanner download to accepted evidence</h2>
        <p className="mt-2 max-w-3xl text-xs leading-5 text-stone-600">The target host never needs a connection to LSA. Run the included Ansible scanner from your controller, transfer the generated report ZIP through your approved path, and import it below.</p>
      </div>
      <ol className="grid bg-[#f7f3eb] sm:grid-cols-2 xl:grid-cols-4">
        {[
          ['Download', 'Get the scanner, inventory template, runner, checks, and embedded guide.'],
          ['Configure', 'Add the target connection, persistent Host ID, profile, and signing-key ID.'],
          ['Collect', 'Run the audit-only Ansible playbook and keep the generated ZIP unchanged.'],
          ['Import', 'Enter the host-scoped ingestion token and validate the completed report.'],
        ].map(([title, detail], index) => <li key={title} className="flex gap-3 border-b border-stone-200 px-5 py-4 last:border-b-0 sm:[&:nth-child(odd)]:border-r xl:border-b-0 xl:border-r xl:last:border-r-0">
          <span className="grid size-7 shrink-0 place-items-center rounded-full border border-stone-300 bg-[#fbfaf7] text-[10px] font-semibold text-stone-700">{index + 1}</span>
          <div><strong className="block text-xs font-semibold text-stone-800">{title}</strong><p className="mt-1 text-[11px] leading-5 text-stone-600">{detail}</p></div>
        </li>)}
      </ol>
    </section>

    <div className="mt-4 grid min-w-0 gap-4 xl:grid-cols-[minmax(0,.9fr)_minmax(420px,1.1fr)]">
      <section className="panel min-w-0 overflow-hidden">
        <div className="border-b border-stone-200 px-5 py-5 sm:px-7">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
            <div><h2 className="text-sm font-semibold text-stone-800">Prepare The Offline Scan</h2><p className="mt-2 max-w-xl text-xs leading-5 text-stone-600">Complete these steps on the Ansible controller. The ZIP includes the same instructions in `README.md`.</p></div>
            {scannerPackage && <span className="settings-state shrink-0">Scanner {scannerPackage.version} · {fileSize(scannerPackage.size_bytes)}</span>}
          </div>
          <button className="button-secondary mt-5" disabled={downloadStatus === 'downloading'} onClick={() => void downloadScanner()}><DownloadSimple size={15} />{downloadStatus === 'downloading' ? 'Preparing Scanner ZIP' : 'Download Scanner ZIP'}</button>
          {downloadStatus === 'error' && <p className="mt-3 text-xs leading-5 text-rose-700" role="alert">The scanner package could not be downloaded. Confirm your session and API connection, then try again.</p>}
        </div>

        <ol className="divide-y divide-stone-200">
          <li className="grid gap-3 px-5 py-5 sm:grid-cols-[34px_minmax(0,1fr)] sm:px-7">
            <span className="grid size-8 place-items-center rounded-lg border border-stone-300 text-xs font-semibold text-stone-700">1</span>
            <div><h3 className="text-xs font-semibold text-stone-800">Create The Host Identity And Token</h3><p className="mt-2 text-xs leading-5 text-stone-600">Enroll the asset in LSA and securely copy its persistent Host ID and host-scoped ingestion token. The raw token is shown once.</p>{user?.role === 'admin' ? <div className="mt-3 flex flex-wrap gap-4"><Link to="/hosts" className="text-xs font-medium text-[#80551f]">Open Linux Assets <ArrowRight className="inline" size={12} /></Link><Link to="/settings/credentials?view=tokens&action=create" className="text-xs font-medium text-[#80551f]">Create Ingestion Token <ArrowRight className="inline" size={12} /></Link></div> : <p className="mt-3 text-[11px] text-stone-500">Ask an administrator to create the asset identity and issue the token.</p>}</div>
          </li>
          <li className="grid gap-3 px-5 py-5 sm:grid-cols-[34px_minmax(0,1fr)] sm:px-7">
            <span className="grid size-8 place-items-center rounded-lg border border-stone-300 text-xs font-semibold text-stone-700">2</span>
            <div><h3 className="text-xs font-semibold text-stone-800">Register The Scanner Signing Key</h3><p className="mt-2 text-xs leading-5 text-stone-600">Generate the private key on the controller, register only its public half in LSA, then place the returned Signing Key ID in `inventory.ini`.</p><pre className="evidence-block">python3 scanner/scripts/generate_signing_key.py /secure/path/lsa-signing-key.pem{`\n`}chmod 600 /secure/path/lsa-signing-key.pem</pre>{user?.role === 'admin' && <Link to="/settings/credentials?view=signing-keys" className="mt-3 inline-block text-xs font-medium text-[#80551f]">Open Signing Keys <ArrowRight className="inline" size={12} /></Link>}</div>
          </li>
          <li className="grid gap-3 px-5 py-5 sm:grid-cols-[34px_minmax(0,1fr)] sm:px-7">
            <span className="grid size-8 place-items-center rounded-lg border border-stone-300 text-xs font-semibold text-stone-700">3</span>
            <div><h3 className="text-xs font-semibold text-stone-800">Edit Inventory And Run</h3><p className="mt-2 text-xs leading-5 text-stone-600">Set the target address, SSH user, Host ID, deployment profile, signing-key path, and Signing Key ID. Then run from the extracted package directory.</p><pre className="evidence-block">ansible-galaxy collection install -r scanner/requirements.yml{`\n`}chmod +x run-offline.sh{`\n`}./run-offline.sh --ask-become-pass</pre></div>
          </li>
          <li className="grid gap-3 px-5 py-5 sm:grid-cols-[34px_minmax(0,1fr)] sm:px-7">
            <span className="grid size-8 place-items-center rounded-lg border border-stone-300 text-xs font-semibold text-stone-700">4</span>
            <div><h3 className="text-xs font-semibold text-stone-800">Keep The Generated Bundle Intact</h3><p className="mt-2 text-xs leading-5 text-stone-600">Use the file under the path below. Do not extract, rename its contents, or rebuild it before import.</p><code className="mt-3 block break-all rounded-lg border border-stone-200 bg-[#f7f3eb] px-3 py-2 text-[11px] text-stone-700">scanner/reports/&lt;inventory-host&gt;/lsa-report-*.zip</code></div>
          </li>
        </ol>

        <div className="border-t border-stone-200 bg-[#f7f3eb] px-5 py-4 sm:px-7">
          <p className="text-[11px] leading-5 text-stone-600"><strong className="text-stone-800">Included in the download:</strong> scanner roles and controls, application inventory collector, report builder, signing-key generator, example inventory, runner script, README, and SHA-256 manifest. No credentials or private keys are included.</p>
        </div>
      </section>

      <section className="panel min-w-0 self-start p-6 md:p-8">
        <div className="flex items-center gap-3"><div className="grid size-10 place-items-center rounded-xl border border-stone-200 bg-[#eee8dd] text-[#4f6f5c]"><UploadSimple size={20} weight="duotone" /></div><div><h2 className="text-sm font-semibold text-stone-800">Import The Completed Report</h2><p className="mt-1 text-xs text-stone-600">Maximum bundle size: 25 MB</p></div></div>
        <button type="button" className={`upload-zone mt-7 ${file ? 'border-[#b8c5ba] bg-[#edf1eb]' : ''}`} onClick={() => inputRef.current?.click()} onDragOver={(event) => event.preventDefault()} onDrop={drop}>
          <FileZip size={30} weight="duotone" className="text-[#4f6f5c]" />
          <span className="mt-4 text-sm font-medium text-stone-800">{file ? file.name : 'Choose or drop lsa-report-*.zip'}</span>
          <span className="mt-2 text-xs text-stone-600">{file ? `${(file.size / 1024).toFixed(1)} KB selected` : 'Select the report ZIP—not the scanner download ZIP'}</span>
        </button>
        <input ref={inputRef} className="sr-only" type="file" accept=".zip,application/zip" onChange={(event) => selectFile(event.target.files?.[0])} />
        <label className="form-field mt-6"><span>Host-scoped ingestion token</span><input type="password" value={token} onChange={(event) => setToken(event.target.value)} placeholder="lsa_ingest_…" /><small>The token authenticates this submission and is not stored by the browser.</small></label>
        {message && <div className={`mt-5 flex items-start gap-3 rounded-xl border px-4 py-3 text-xs leading-5 ${status === 'success' ? 'border-[#b8c5ba] bg-[#edf1eb] text-[#4f6f5c]' : 'border-rose-900/50 bg-rose-950/20 text-rose-700'}`} role={status === 'error' ? 'alert' : 'status'}>{status === 'success' ? <CheckCircle size={17} className="mt-0.5 shrink-0" /> : <WarningCircle size={17} className="mt-0.5 shrink-0" />}{message}</div>}
        <button className="button-primary mt-6" disabled={!file || !token || status === 'uploading'} onClick={() => void upload()}>{status === 'uploading' ? 'Validating Bundle' : 'Import Report'} <UploadSimple size={16} /></button>

        <div className="mt-7 grid gap-4 border-t border-stone-200 pt-6 sm:grid-cols-2">
          <div className="flex gap-3"><ShieldCheck size={18} className="mt-0.5 shrink-0 text-[#4f6f5c]" /><div><strong className="text-xs text-stone-800">Validated Before Acceptance</strong><p className="mt-1 text-[11px] leading-5 text-stone-600">LSA checks safe paths, hashes, signature, key scope, Host ID, and report schema.</p></div></div>
          <div className="flex gap-3"><TerminalWindow size={18} className="mt-0.5 shrink-0 text-[#4f6f5c]" /><div><strong className="text-xs text-stone-800">No Remote Session</strong><p className="mt-1 text-[11px] leading-5 text-stone-600">Importing evidence cannot open SSH or execute changes on the host.</p></div></div>
        </div>
      </section>
    </div>
  </div>
}
