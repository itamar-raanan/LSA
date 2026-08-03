import { ChevronUp, Clock3, Cpu, ExternalLink, Minus, Server, Trash2, X } from 'lucide-react'
import { motion, useReducedMotion } from 'framer-motion'
import { useState } from 'react'
import { createPortal } from 'react-dom'
import { Link } from 'react-router-dom'
import { api, ApiError } from '../api/client'
import { useAuth } from '../auth/useAuth'
import type { Host } from '../types'

function formatUptime(value: unknown) {
  const seconds = Number(value)
  if (!Number.isFinite(seconds) || seconds <= 0) return 'Not reported'
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  return days ? `${days}d ${hours}h` : `${hours}h`
}

export function HostQuickView({ host, close, deleted }: { host: Host; close: () => void; deleted: () => void }) {
  const { user } = useAuth()
  const [confirming, setConfirming] = useState(false)
  const [minimized, setMinimized] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const info = host.system_info ?? {}
  const reduceMotion = useReducedMotion()
  const motionProps = reduceMotion ? {} : { initial: { opacity: 0, transform: 'translateY(10px) scale(.985)' }, animate: { opacity: 1, transform: 'translateY(0) scale(1)' }, transition: { duration: .22, ease: [0.23, 1, 0.32, 1] as const } }

  async function remove() {
    setBusy(true)
    setError('')
    try {
      await api.deleteHost(host.id)
      deleted()
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'Host deletion failed')
      setBusy(false)
    }
  }

  if (minimized) {
    return createPortal(<motion.aside {...motionProps} className="host-quick-view host-quick-view-minimized" aria-label={`${host.hostname} details`}>
      <button className="host-quick-view-restore" onClick={() => setMinimized(false)} aria-label={`Restore ${host.hostname} details`}>
        <span className="min-w-0"><span className="section-label block">Host card</span><span className="mt-1 block truncate text-xs font-medium text-stone-200">{host.hostname}</span></span>
        <ChevronUp size={16} className="shrink-0 text-stone-500" />
      </button>
      <button className="icon-button mr-3 shrink-0" aria-label="Close host details" onClick={close}><X size={16} /></button>
    </motion.aside>, document.body)
  }

  return createPortal(<motion.aside {...motionProps} className="host-quick-view" aria-label={`${host.hostname} details`}>
    <div className="flex shrink-0 items-start justify-between gap-4 border-b border-stone-800 px-5 py-5">
      <div className="min-w-0"><p className="section-label">Host card</p><h2 className="mt-2 truncate text-lg font-semibold text-stone-100">{host.hostname}</h2><p className="mt-1 truncate font-mono text-[10px] text-stone-600">{host.fqdn ?? host.ip_addresses[0] ?? host.id}</p></div>
      <div className="flex shrink-0 items-center gap-2">
        <button className="icon-button" aria-label="Minimize host details" title="Minimize" onClick={() => { setConfirming(false); setMinimized(true) }}><Minus size={16} /></button>
        <button className="icon-button" aria-label="Close host details" title="Close" onClick={close}><X size={16} /></button>
      </div>
    </div>
    <div className="host-quick-view-body px-5 py-5">
      <div className="grid grid-cols-2 gap-px overflow-hidden rounded-xl border border-stone-800 bg-stone-800">
        <div className="bg-[#151916] p-4"><p className="detail-label">Security</p><p className="mt-2 font-mono text-xl text-stone-100">{host.security_score?.toFixed(1) ?? '—'}</p></div>
        <div className="bg-[#151916] p-4"><p className="detail-label">Compliance</p><p className="mt-2 font-mono text-xl text-stone-100">{host.compliance_score?.toFixed(1) ?? '—'}</p></div>
      </div>
      <div className="mt-5 space-y-4 text-xs text-stone-400">
        <div className="flex gap-3"><Server className="mt-0.5 shrink-0 text-sky-500" size={16} /><div><p className="text-stone-200">{host.operating_system} {host.os_version}</p><p className="mt-1 font-mono text-[10px] text-stone-600">Kernel {host.kernel} · {host.architecture}</p></div></div>
        <div className="flex gap-3"><Cpu className="mt-0.5 shrink-0 text-emerald-500" size={16} /><div><p className="text-stone-200">{String(info.cpu_model ?? 'CPU not reported')}</p><p className="mt-1 font-mono text-[10px] text-stone-600">{String(info.cpu_cores ?? '—')} vCPU · {info.memory_mb ? `${Math.round(Number(info.memory_mb) / 1024)} GB memory` : 'memory not reported'}</p></div></div>
        <div className="flex gap-3"><Clock3 className="mt-0.5 shrink-0 text-sky-500" size={16} /><div><p className="text-stone-200">Uptime {formatUptime(info.uptime_seconds)}</p><p className="mt-1 font-mono text-[10px] text-stone-600">{String(info.timezone ?? 'Timezone not reported')} · {host.last_scan_at ? `scanned ${new Date(host.last_scan_at).toLocaleString()}` : 'never scanned'}</p></div></div>
      </div>
      <div className="mt-5 border-t border-stone-800 pt-5"><p className="detail-label">Platform</p><p className="mt-2 text-xs text-stone-300">{String(info.system_vendor ?? 'Unknown vendor')} · {String(info.product_name ?? 'Unknown model')}</p><p className="mt-1 font-mono text-[10px] text-stone-600">{String(info.virtualization_type ?? 'unknown')} / {String(info.virtualization_role ?? 'unknown')}</p></div>
      <div className="mt-5 border-t border-stone-800 pt-5"><p className="detail-label">Applications</p><p className="mt-2 text-xs text-stone-300">{host.application_count ?? 0} installed packages and services</p><p className="mt-1 font-mono text-[10px] text-stone-600">Open the full record to search the latest inventory.</p></div>
      {error && <p className="mt-4 text-xs text-rose-400">{error}</p>}
    </div>
    <div className="flex shrink-0 items-center justify-between gap-3 border-t border-stone-800 px-5 py-4">
      {user?.role === 'admin' && (confirming ? <div className="flex items-center gap-2"><button className="button-secondary min-h-9 px-3" onClick={() => setConfirming(false)} disabled={busy}>Cancel</button><button className="button-secondary min-h-9 border-rose-900/80 px-3 text-rose-300" onClick={() => void remove()} disabled={busy}>{busy ? 'Deleting…' : 'Confirm delete'}</button></div> : <button className="icon-button text-rose-400" aria-label="Delete host" title="Delete host" onClick={() => setConfirming(true)}><Trash2 size={16} /></button>)}
      <Link className="button-primary ml-auto min-h-9 px-3" to={`/hosts/${host.id}`}>Full record <ExternalLink size={15} /></Link>
    </div>
  </motion.aside>, document.body)
}
