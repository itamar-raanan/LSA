import * as Dialog from '@radix-ui/react-dialog'
import { FileUp, LayoutDashboard, MonitorCog, Search, Server, Settings, ShieldAlert, ShieldCheck, X } from 'lucide-react'
import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'

const commands = [
  { label: 'Security overview', detail: 'Review fleet posture and critical exposure', path: '/', icon: LayoutDashboard, keywords: 'overview home metrics' },
  { label: 'Asset inventory', detail: 'Search reporting Linux systems', path: '/hosts', icon: Server, keywords: 'hosts servers assets' },
  { label: 'Agents & groups', detail: 'Manage agents, enrollment, and fleet groups', path: '/agents', icon: MonitorCog, keywords: 'agents groups endpoints enrollment' },
  { label: 'Security findings', detail: 'Triage findings by control category', path: '/findings', icon: ShieldAlert, keywords: 'findings risk vulnerabilities' },
  { label: 'Import report', detail: 'Upload an offline evidence bundle', path: '/reports', icon: FileUp, keywords: 'offline upload report' },
  { label: 'Administration · TLS certificates', detail: 'Review the console HTTPS identity', path: '/settings/certificates', icon: ShieldCheck, keywords: 'administration tls https certificate' },
  { label: 'Administration', detail: 'Identity, trust, users, and access', path: '/settings', icon: Settings, keywords: 'settings admin users tokens' },
]

export function CommandPalette({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const [query, setQuery] = useState('')
  const navigate = useNavigate()
  const filtered = useMemo(() => {
    const needle = query.toLowerCase().trim()
    return needle ? commands.filter((command) => `${command.label} ${command.detail} ${command.keywords}`.toLowerCase().includes(needle)) : commands
  }, [query])

  function select(path: string) {
    navigate(path); onOpenChange(false); setQuery('')
  }

  return <Dialog.Root open={open} onOpenChange={onOpenChange}>
    <Dialog.Portal>
      <Dialog.Overlay className="command-overlay" />
      <Dialog.Content className="command-palette" aria-describedby={undefined}>
        <Dialog.Title className="sr-only">Global search</Dialog.Title>
        <div className="command-search"><Search size={18} /><input autoFocus value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search assets, findings, reports, or settings…" /><Dialog.Close className="command-close" aria-label="Close search"><X size={16} /></Dialog.Close></div>
        <div className="command-results">
          <p className="command-group-label">Navigate</p>
          {filtered.map((command) => { const Icon = command.icon; return <button key={command.path} className="command-item" onClick={() => select(command.path)}><span className="command-item-icon"><Icon size={16} /></span><span className="min-w-0 flex-1 text-left"><strong>{command.label}</strong><small>{command.detail}</small></span><span className="command-enter">↵</span></button> })}
          {!filtered.length && <div className="px-5 py-12 text-center text-xs text-slate-500">No console destination matches “{query}”.</div>}
        </div>
        <div className="command-footer"><span><kbd>↑</kbd><kbd>↓</kbd> navigate</span><span><kbd>esc</kbd> close</span></div>
      </Dialog.Content>
    </Dialog.Portal>
  </Dialog.Root>
}
