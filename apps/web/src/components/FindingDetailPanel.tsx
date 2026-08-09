import { ArrowSquareOut, X } from '@phosphor-icons/react'
import { motion, useReducedMotion } from 'framer-motion'
import { useEffect, useRef } from 'react'
import { createPortal } from 'react-dom'
import { Link } from 'react-router-dom'
import type { Finding } from '../types'
import { RemediationGuide } from './RemediationGuide'
import { SeverityBadge } from './SeverityBadge'

export function FindingDetailPanel({ finding, close, hostHref }: { finding: Finding; close: () => void; hostHref: string }) {
  const reduceMotion = useReducedMotion()
  const closeButton = useRef<HTMLButtonElement>(null)
  const motionProps = reduceMotion ? {} : {
    initial: { opacity: 0, transform: 'translateX(18px)' },
    animate: { opacity: 1, transform: 'translateX(0)' },
    transition: { duration: .2, ease: [0.23, 1, 0.32, 1] as const },
  }

  useEffect(() => {
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null
    closeButton.current?.focus()
    const handleKeyDown = (event: KeyboardEvent) => { if (event.key === 'Escape') close() }
    window.addEventListener('keydown', handleKeyDown)
    return () => { window.removeEventListener('keydown', handleKeyDown); previousFocus?.focus() }
  }, [close])

  return createPortal(<motion.aside {...motionProps} className="finding-detail-panel" aria-label={`${finding.title} details`}>
    <header className="finding-detail-header">
      <div className="min-w-0">
        <div className="flex items-center gap-3"><SeverityBadge severity={finding.severity} /><span className="font-mono text-[10px] text-stone-500">{finding.control_id}</span></div>
        <h2>{finding.title}</h2>
        <p>{finding.hostname} · {finding.module}</p>
      </div>
      <button ref={closeButton} className="icon-button shrink-0" aria-label="Close finding details" title="Close" onClick={close}><X size={17} /></button>
    </header>
    <div className="finding-detail-context">
      <div><span className="detail-label">Lifecycle</span><strong>{finding.lifecycle}</strong></div>
      <div><span className="detail-label">Scanner Status</span><strong>{finding.status}</strong></div>
      <div><span className="detail-label">Operational Impact</span><strong>{finding.reboot_required ? 'Reboot Required' : finding.service_restart ? 'Service Restart' : 'No Restart Reported'}</strong></div>
    </div>
    <div className="finding-detail-body"><RemediationGuide finding={finding} /></div>
    <footer className="finding-detail-footer">
      <span>Review and apply changes through your approved change process.</span>
      <Link className="button-secondary min-h-9 shrink-0" to={hostHref}>Open Host Record <ArrowSquareOut size={15} /></Link>
    </footer>
  </motion.aside>, document.body)
}
