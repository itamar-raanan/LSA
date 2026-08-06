import { ArrowSquareOut, Gear, Package, ShieldWarning, X } from '@phosphor-icons/react'
import { motion, useReducedMotion } from 'framer-motion'
import { useEffect, useMemo, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { Link } from 'react-router-dom'
import type { ApplicationEstateItem, ApplicationHostCorrelation, ApplicationVulnerability } from '../types'
import { ErrorState } from './StatePanel'

function vulnerabilityLabel(item: ApplicationVulnerability) {
  return item.cve_id ?? item.id
}

export function ApplicationInvestigationPanel({
  application,
  hosts,
  hostsLoading,
  hostsError,
  retryHosts,
  vulnerabilities,
  vulnerabilitiesLoading,
  vulnerabilitiesError,
  retryVulnerabilities,
  close,
}: {
  application: ApplicationEstateItem
  hosts: ApplicationHostCorrelation[]
  hostsLoading: boolean
  hostsError: string | null
  retryHosts: () => Promise<void>
  vulnerabilities: ApplicationVulnerability[]
  vulnerabilitiesLoading: boolean
  vulnerabilitiesError: string | null
  retryVulnerabilities: () => Promise<void>
  close: () => void
}) {
  const [selectedVulnerability, setSelectedVulnerability] = useState<ApplicationVulnerability | null>(null)
  const closeButton = useRef<HTMLButtonElement>(null)
  const reduceMotion = useReducedMotion()
  const visibleHosts = useMemo(() => {
    if (!selectedVulnerability) return hosts
    const affected = new Set(selectedVulnerability.affected_host_ids)
    return hosts.filter((host) => affected.has(host.host_id))
  }, [hosts, selectedVulnerability])
  const versions = useMemo(() => {
    const distribution = new Map<string, number>()
    for (const host of visibleHosts) {
      const version = host.version ?? 'Version Not Reported'
      distribution.set(version, (distribution.get(version) ?? 0) + 1)
    }
    return [...distribution.entries()].sort((a, b) => b[1] - a[1])
  }, [visibleHosts])
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

  return createPortal(<motion.aside {...motionProps} className="application-investigation-panel" aria-label={`${application.name} investigation`}>
    <header className="application-investigation-header">
      <span className="application-kind-icon">{application.kind === 'package' ? <Package size={18} /> : <Gear size={18} />}</span>
      <div className="min-w-0 flex-1"><p className="section-label">Application Investigation</p><h2>{application.name}</h2><p>{application.kind} · {application.source} · Last Observed {new Date(application.last_seen_at).toLocaleDateString()}</p></div>
      <button ref={closeButton} className="icon-button shrink-0" aria-label="Close application investigation" title="Close" onClick={close}><X size={17} /></button>
    </header>

    <div className="application-investigation-summary">
      <div><span className="detail-label">Observed Hosts</span><strong>{application.host_count}</strong></div>
      <div><span className="detail-label">Versions</span><strong>{application.version_count || 1}</strong></div>
      <div><span className="detail-label">Advisories</span><strong>{application.vulnerability_count}</strong></div>
      <div><span className="detail-label">Known Exploited</span><strong className={application.known_exploited_count ? 'text-rose-500' : ''}>{application.known_exploited_count}</strong></div>
    </div>

    <div className="application-investigation-body">
      {application.kind === 'package' && <section className="application-vulnerability-block">
        <div className="application-investigation-section-heading"><div><p className="detail-label">Vulnerability Intelligence</p><p>Prioritize known exploitation and available vendor fixes.</p></div><span>{vulnerabilities.length}</span></div>
        {vulnerabilitiesLoading ? <div className="skeleton mt-4 h-24 rounded-lg" /> : vulnerabilitiesError ? <div className="mt-4"><ErrorState message={vulnerabilitiesError} retry={retryVulnerabilities} /></div> : !vulnerabilities.length ? <p className="application-vulnerability-empty">No cached advisories match the observed package versions.</p> : <div className="application-vulnerability-list">{vulnerabilities.map((item) => <button key={item.id} className={`application-vulnerability-item ${selectedVulnerability?.id === item.id ? 'application-vulnerability-item-active' : ''}`} aria-pressed={selectedVulnerability?.id === item.id} onClick={() => setSelectedVulnerability(selectedVulnerability?.id === item.id ? null : item)}>
          <span className="flex min-w-0 flex-wrap items-center gap-2"><span className={`severity-badge severity-${item.severity}`}>{item.severity}</span><strong>{vulnerabilityLabel(item)}</strong>{item.known_exploited && <span className="kev-badge">Known Exploited</span>}</span>
          <small>{item.summary || 'Security Advisory'}</small>
          <span className="application-vulnerability-meta">{item.affected_hosts} Host{item.affected_hosts === 1 ? '' : 's'} · {item.affected_versions.length} Affected Version{item.affected_versions.length === 1 ? '' : 's'}{item.fixed_versions.length ? ` · Fixed In ${item.fixed_versions[0]}` : ' · No Fixed Version Reported'}</span>
        </button>)}</div>}

        {selectedVulnerability && <article className="application-advisory-detail">
          <div className="application-advisory-title"><div><span className="detail-label">Selected Advisory</span><h3>{vulnerabilityLabel(selectedVulnerability)}</h3></div>{selectedVulnerability.cvss_score !== null && <span>CVSS {selectedVulnerability.cvss_score.toFixed(1)}</span>}</div>
          <p>{selectedVulnerability.summary || 'No advisory summary was provided.'}</p>
          <dl>
            <div><dt>Affected Versions</dt><dd>{selectedVulnerability.affected_versions.join(', ') || 'Not Reported'}</dd></div>
            <div><dt>Fixed Versions</dt><dd>{selectedVulnerability.fixed_versions.join(', ') || 'Vendor Guidance Required'}</dd></div>
            <div><dt>Required Action</dt><dd>{selectedVulnerability.kev_required_action || 'Apply the vendor-supported security update after validation.'}</dd></div>
            <div><dt>KEV Due Date</dt><dd>{selectedVulnerability.kev_due_date ? new Date(selectedVulnerability.kev_due_date).toLocaleDateString() : 'Not In CISA KEV'}</dd></div>
          </dl>
          {selectedVulnerability.references.find((reference) => reference.url)?.url && <a href={selectedVulnerability.references.find((reference) => reference.url)?.url} target="_blank" rel="noreferrer">Open Advisory <ArrowSquareOut size={13} /></a>}
        </article>}
      </section>}

      {hostsLoading ? <div className="skeleton m-5 h-52 rounded-lg" /> : hostsError ? <div className="p-5"><ErrorState message={hostsError} retry={retryHosts} /></div> : <>
        {versions.length > 0 && <section className="application-version-block"><div className="application-investigation-section-heading"><div><p className="detail-label">Version Distribution</p><p>{selectedVulnerability ? 'Hosts affected by the selected advisory.' : 'Versions observed across reporting hosts.'}</p></div>{selectedVulnerability && <button className="text-button" onClick={() => setSelectedVulnerability(null)}>Show All Hosts</button>}</div><div className="mt-4 grid gap-3">{versions.map(([version, count]) => <div key={version}><div className="flex items-center justify-between gap-3 text-xs"><span className="min-w-0 truncate font-mono">{version}</span><span className="font-mono text-stone-600">{count}</span></div><div className="application-version-track"><span style={{ width: `${(count / Math.max(visibleHosts.length, 1)) * 100}%` }} /></div></div>)}</div></section>}
        <section className="application-host-list"><div className="application-investigation-section-heading"><div><p className="detail-label">{selectedVulnerability ? 'Affected Hosts' : 'Observed Hosts'}</p><p>Open a host record to review its complete software and finding context.</p></div><span>{visibleHosts.length}</span></div>{visibleHosts.length ? visibleHosts.map((host) => <Link key={host.application_id} to={`/hosts/${host.host_id}`} className="application-host-link"><span className="min-w-0"><strong>{host.hostname}</strong><small>{host.os_family} {host.os_version} · {host.environment ?? 'Environment Not Set'}</small><small className="font-mono">{host.version ?? host.status}{host.architecture ? ` · ${host.architecture}` : ''}</small></span><span className="application-host-score"><strong>{host.security_score?.toFixed(0) ?? '—'}</strong><small>Security</small></span></Link>) : <div className="application-vulnerability-empty"><ShieldWarning size={15} />No reporting hosts match the selected advisory.</div>}</section>
      </>}
    </div>
    <footer className="application-investigation-footer"><span>Cached OSV advisories enriched with CISA KEV intelligence.</span><button className="button-secondary min-h-9" onClick={close}>Return To Inventory</button></footer>
  </motion.aside>, document.body)
}
