import { ArrowRight, CheckCircle, FileZip, Key, ShieldCheck, UploadSimple, WarningCircle } from '@phosphor-icons/react'
import { useRef, useState, type DragEvent } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import { useAuth } from '../auth/useAuth'
import { PageHeader } from '../components/PageHeader'

type UploadStatus = 'idle' | 'ready' | 'uploading' | 'success' | 'error'

export function ReportsPage() {
  const { user } = useAuth()
  const inputRef = useRef<HTMLInputElement>(null)
  const [file, setFile] = useState<File | null>(null)
  const [token, setToken] = useState('')
  const [status, setStatus] = useState<UploadStatus>('idle')
  const [message, setMessage] = useState('')

  function selectFile(selected?: File) {
    if (!selected) return
    if (!selected.name.endsWith('.zip')) {
      setStatus('error'); setMessage('Choose an LSA ZIP report bundle.'); return
    }
    setFile(selected); setStatus('ready'); setMessage('')
  }

  function drop(event: DragEvent) {
    event.preventDefault()
    selectFile(event.dataTransfer.files[0])
  }

  async function upload() {
    if (!file || !token) return
    setStatus('uploading'); setMessage('')
    try {
      const result = await api.uploadBundle(file, token)
      setStatus('success')
      setMessage(`Accepted ${String(result.findings_imported)} findings for host ${String(result.host_id)}.`)
    } catch (reason) {
      setStatus('error'); setMessage(reason instanceof Error ? reason.message : 'Upload failed')
    }
  }

  return (
    <div className="page-reveal">
      <PageHeader eyebrow="Offline Workflow" title="Evidence Intake" detail="Upload a portable bundle created by the customer-controlled LSA scanner. The platform validates identity, integrity, and scope before changing fleet state." />
      <section className="evidence-prerequisite">
        <span><Key size={17} /></span>
        <div><strong>An Ingestion Token Is Required</strong><p>The token authenticates this submission and limits which host identity the bundle may update.</p></div>
        {user?.role === 'admin' ? <Link to="/settings/credentials?view=tokens&action=create" className="button-secondary">Create Ingestion Token <ArrowRight size={14} /></Link> : <small>Ask An Administrator To Issue A Token</small>}
      </section>
      <section className="grid gap-4 xl:grid-cols-[1.15fr_0.65fr]">
        <div className="panel p-6 md:p-8">
          <div className="flex items-center gap-3"><div className="grid size-10 place-items-center rounded-xl border border-stone-800 bg-[#eee8dd] text-[#4f6f5c]"><UploadSimple size={20} weight="duotone" /></div><div><h2 className="text-sm font-semibold text-stone-100">Offline report bundle</h2><p className="mt-1 text-xs text-stone-600">Maximum upload size: 25 MB</p></div></div>
          <button type="button" className={`upload-zone mt-7 ${file ? 'border-[#b8c5ba] bg-[#edf1eb]' : ''}`} onClick={() => inputRef.current?.click()} onDragOver={(event) => event.preventDefault()} onDrop={drop}>
            <FileZip size={30} weight="duotone" className="text-[#4f6f5c]" />
            <span className="mt-4 text-sm font-medium text-stone-200">{file ? file.name : 'Choose or drop a report bundle'}</span>
            <span className="mt-2 text-xs text-stone-600">{file ? `${(file.size / 1024).toFixed(1)} KB selected` : 'Only .zip files produced by LSA are accepted'}</span>
          </button>
          <input ref={inputRef} className="sr-only" type="file" accept=".zip,application/zip" onChange={(event) => selectFile(event.target.files?.[0])} />
          <label className="form-field mt-6"><span>Ingestion token</span><input type="password" value={token} onChange={(event) => setToken(event.target.value)} placeholder="lsa_ingest_…" /><small>Tokens are used only for this request and are not stored by the browser.</small></label>
          {message && <div className={`mt-5 flex items-start gap-3 rounded-xl border px-4 py-3 text-xs leading-5 ${status === 'success' ? 'border-[#b8c5ba] bg-[#edf1eb] text-[#4f6f5c]' : 'border-rose-900/50 bg-rose-950/20 text-rose-300'}`}>{status === 'success' ? <CheckCircle size={17} className="mt-0.5 shrink-0" /> : <WarningCircle size={17} className="mt-0.5 shrink-0" />}{message}</div>}
          <button className="button-primary mt-6" disabled={!file || !token || status === 'uploading'} onClick={() => void upload()}>{status === 'uploading' ? 'Validating bundle' : 'Import report'} <UploadSimple size={16} /></button>
        </div>
        <aside className="panel p-6 md:p-8">
          <p className="section-label">Validation pipeline</p>
          <ol className="mt-7 space-y-6">
            {['Authenticate the submitter', 'Validate checksums and safe paths', 'Verify the signer and host scope', 'Compare finding state', 'Update fleet posture'].map((step, index) => <li key={step} className="flex gap-3"><span className="grid size-6 shrink-0 place-items-center rounded-full border border-stone-700 font-mono text-[9px] text-stone-400">{String(index + 1).padStart(2, '0')}</span><span className="pt-1 text-xs text-stone-400">{step}</span></li>)}
          </ol>
          <div className="mt-8 border-t border-stone-800 pt-6"><div className="flex items-center gap-2 text-xs font-medium text-stone-300"><ShieldCheck size={17} className="text-[#4f6f5c]" />No server access required</div><p className="mt-3 text-xs leading-5 text-stone-600">The platform receives evidence only. It cannot open an SSH session or execute remediation on a reporting host.</p></div>
        </aside>
      </section>
    </div>
  )
}
