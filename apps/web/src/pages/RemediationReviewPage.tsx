import {
  ArrowRight, CheckCircle2, ChevronDown, CircleSlash2, FileText, History,
  ListChecks, RotateCcw, Search, ShieldCheck, ShieldX, TriangleAlert, XCircle,
} from 'lucide-react'
import { useEffect, useMemo, useRef, useState, type ReactNode, type Ref } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api } from '../api/client'
import { useAuth } from '../auth/useAuth'
import { PageHeader } from '../components/PageHeader'
import { SeverityBadge } from '../components/SeverityBadge'
import { ErrorState, LoadingState } from '../components/StatePanel'
import { Button } from '../components/ui/Button'
import { Dialog } from '../components/ui/Dialog'
import { useApi } from '../hooks/useApi'
import { formatDateTime } from '../lib/dateTime'
import type { RemediationActionOperation, RemediationPlan, RemediationPlanStatus } from '../types'

type PlanFilter = RemediationPlanStatus | 'all'
type DecisionKind = 'approve' | 'reject' | 'cancel'

const filters: Array<{ id: PlanFilter; label: string; detail: string }> = [
  { id: 'pending_approval', label: 'Pending Decision', detail: 'Awaiting Review' },
  { id: 'approved', label: 'Approved', detail: 'Intent Recorded' },
  { id: 'rejected', label: 'Rejected', detail: 'Change Declined' },
  { id: 'canceled', label: 'Canceled', detail: 'Decision Withdrawn' },
  { id: 'all', label: 'All Plans', detail: 'Complete History' },
]

const statusLabels: Record<RemediationPlanStatus, string> = {
  pending_approval: 'Pending Decision',
  approved: 'Approved',
  rejected: 'Rejected',
  canceled: 'Canceled',
}

function PlanStatus({ status }: { status: RemediationPlanStatus }) {
  const icon = status === 'approved' ? <CheckCircle2 size={13} /> : status === 'rejected' ? <XCircle size={13} /> : status === 'canceled' ? <CircleSlash2 size={13} /> : <History size={13} />
  return <span className={`remediation-plan-status remediation-plan-status-${status}`}>{icon}{statusLabels[status]}</span>
}

function DecisionDialog({ kind, plan, busy, error, close, submit }: { kind: DecisionKind; plan: RemediationPlan; busy: boolean; error: string; close: () => void; submit: (reason: string) => void }) {
  const [reason, setReason] = useState('')
  const requiresReason = kind !== 'approve'
  const action = kind === 'approve' ? 'Approve Plan' : kind === 'reject' ? 'Reject Plan' : 'Cancel Approval'
  const description = kind === 'approve'
    ? 'Record approval for this reviewed configuration change. This does not execute commands or modify the host.'
    : kind === 'reject'
      ? 'Record why this proposed change should not proceed.'
      : 'Withdraw the recorded approval while preserving its decision history.'
  return <Dialog open onOpenChange={(open) => { if (!open && !busy) close() }} eyebrow="Protected Decision" title={`${action}?`} description={`${plan.hostname} · ${plan.control_id}`}>
    <div className="remediation-decision-copy"><ShieldCheck size={18} /><div><strong>{description}</strong><p>The source evidence and every decision actor remain in the audit ledger.</p></div></div>
    {requiresReason && <label className="form-field mt-5"><span>Decision Reason</span><textarea className="remediation-decision-reason" value={reason} onChange={(event) => setReason(event.target.value)} placeholder="Explain The Decision For Future Reviewers" rows={4} /><small>This reason becomes part of the permanent plan record.</small></label>}
    {error && <p className="remediation-decision-error" role="alert">{error}</p>}
    <div className="remediation-dialog-actions"><Button variant="ghost" disabled={busy} onClick={close}>Keep Reviewing</Button><Button variant={kind === 'approve' ? 'primary' : 'danger'} disabled={busy || (requiresReason && !reason.trim())} onClick={() => submit(reason.trim())}>{busy ? 'Recording Decision' : action}</Button></div>
  </Dialog>
}

function readableToken(value: string) {
  return value.split('_').map((part) => part.charAt(0).toUpperCase() + part.slice(1)).join(' ')
}

function OperationList({ title, icon, operations }: { title: string; icon: ReactNode; operations: RemediationActionOperation[] }) {
  return <section className="remediation-action-procedure">
    <h4>{icon}{title}</h4>
    <ol>{operations.map((operation, index) => <li key={`${operation.kind}:${operation.resource}:${operation.path ?? index}`}>
      <span>{index + 1}</span>
      <div><strong>{readableToken(operation.kind)}</strong><p>{operation.key ? `${operation.key} · ` : ''}{operation.path ?? readableToken(operation.resource)}{operation.value_from ? ` · Reviewed Parameter: ${operation.value_from}` : ''}</p></div>
    </li>)}</ol>
  </section>
}

function ActionCatalogSection({ plan }: { plan: RemediationPlan }) {
  const action = plan.action
  if (!action) {
    const unsupported = plan.action_catalog_status === 'unsupported_system'
    return <section className="remediation-dossier-section remediation-action-coverage">
      <h3>Declarative Action Coverage</h3>
      <div className={unsupported ? 'remediation-action-coverage-warning' : ''}><ShieldX size={16} /><div><strong>{unsupported ? 'Action Not Reviewed For This Host OS' : 'No Reviewed Action For This Control'}</strong><p>{unsupported ? 'The control is cataloged, but this host family or version is outside the reviewed support matrix.' : 'The plan remains available for accountable human review, but no structured change procedure is attached.'} Approval remains non-executable.</p></div></div>
    </section>
  }
  return <section className="remediation-dossier-section remediation-action-catalog">
    <header><div><h3>Reviewed Declarative Action</h3><p>{action.action_id} · Version {action.version}</p></div><span><ShieldCheck size={13} />Catalog Only · Non-Executable</span></header>
    <p>{action.description}</p>
    <dl className="remediation-action-facts">
      <div><dt>Risk</dt><dd>{readableToken(action.risk)}</dd></div>
      <div><dt>Availability</dt><dd>{readableToken(action.impact.availability)}</dd></div>
      <div><dt>Integrity</dt><dd className="remediation-action-digest">SHA-256 {action.digest}</dd></div>
    </dl>
    <div className="remediation-action-preconditions"><h4>Stop Conditions</h4><ul>{action.preconditions.map((condition) => <li key={`${condition.kind}:${condition.resource}`}><ListChecks size={14} /><span><strong>{readableToken(condition.kind)}</strong>{condition.description}</span></li>)}</ul></div>
    <details className="remediation-action-details">
      <summary>Review Structured Procedure <ChevronDown size={15} /></summary>
      <div>
        <OperationList title="Reviewed Change" icon={<ListChecks size={14} />} operations={action.operations} />
        <section className="remediation-action-procedure"><h4><ShieldCheck size={14} />Validation</h4><ol>{action.validation.map((validation, index) => <li key={`${validation.kind}:${validation.key}`}><span>{index + 1}</span><div><strong>{readableToken(validation.kind)}</strong><p>{validation.key} Must Equal {String(validation.expected)}</p></div></li>)}</ol></section>
        <OperationList title="Rollback" icon={<RotateCcw size={14} />} operations={action.rollback} />
      </div>
    </details>
  </section>
}

function PlanDossier({ plan, admin, onDecision, containerRef }: { plan: RemediationPlan; admin: boolean; onDecision: (kind: DecisionKind) => void; containerRef: Ref<HTMLElement> }) {
  const stale = !plan.source_is_current || !plan.finding_still_open
  const timeline = [
    { label: 'Requested', actor: plan.requested_by_name, at: plan.requested_at, reason: plan.rationale },
    plan.approved_at ? { label: 'Approved', actor: plan.approved_by_name ?? 'Unknown User', at: plan.approved_at, reason: null } : null,
    plan.rejected_at ? { label: 'Rejected', actor: plan.rejected_by_name ?? 'Unknown User', at: plan.rejected_at, reason: plan.rejection_reason } : null,
    plan.canceled_at ? { label: 'Canceled', actor: plan.canceled_by_name ?? 'Unknown User', at: plan.canceled_at, reason: plan.cancellation_reason } : null,
  ].filter((item): item is { label: string; actor: string; at: string; reason: string | null } => item !== null)

  return <aside ref={containerRef} tabIndex={-1} className="remediation-dossier" aria-label={`${plan.title} Review Dossier`}>
    <header className="remediation-dossier-header">
      <div className="flex items-center gap-2"><SeverityBadge severity={plan.severity} /><PlanStatus status={plan.status} /></div>
      <h2>{plan.title}</h2>
      <p>{plan.hostname} · {plan.control_id}</p>
    </header>
    <div className="remediation-execution-lock"><ShieldX size={17} /><div><strong>Approval Records Intent Only</strong><p>{plan.execution_reason}</p></div></div>
    {stale && <div className="remediation-stale-warning" role="status"><TriangleAlert size={17} /><div><strong>Source Evidence Is No Longer Current</strong><p>{plan.finding_still_open ? 'The control is still open in a newer report. Create a replacement plan from the latest finding before approval.' : 'The latest report no longer shows this control as open. Approval is blocked.'}</p></div></div>}
    <section className="remediation-dossier-section">
      <h3>Change Comparison</h3>
      <div className="remediation-review-states">
        <div><span>Current State</span><p>{plan.current_state || 'No Concrete Value Was Reported.'}</p></div>
        <div><span>Required State</span><p>{plan.required_state || 'Use The Approved Security Baseline.'}</p></div>
      </div>
    </section>
    <ActionCatalogSection plan={plan} />
    <section className="remediation-dossier-section">
      <h3>Change Guidance</h3>
      <p>{plan.remediation_summary}</p>
      {plan.affected_paths.length > 0 && <div className="remediation-review-paths">{plan.affected_paths.map((path) => <code key={path}>{path}</code>)}</div>}
      <dl className="remediation-impact-list">
        <div><dt>Service Restart</dt><dd>{plan.service_restart ? 'Required' : 'Not Reported'}</dd></div>
        <div><dt>Host Reboot</dt><dd>{plan.reboot_required ? 'Required' : 'Not Reported'}</dd></div>
        <div><dt>Plan Version</dt><dd>Version {plan.version}</dd></div>
      </dl>
    </section>
    <section className="remediation-dossier-section">
      <h3>Decision History</h3>
      <ol className="remediation-plan-timeline">{timeline.map((item) => <li key={`${item.label}:${item.at}`}><span /><div><strong>{item.label} By {item.actor}</strong><small>{formatDateTime(item.at)}</small>{item.reason && <p>{item.reason}</p>}</div></li>)}</ol>
    </section>
    <footer className="remediation-dossier-actions">
      {!admin && <p>Your Role Can Review This Plan But Cannot Change Its Decision.</p>}
      {admin && plan.status === 'pending_approval' && <><Button variant="secondary" onClick={() => onDecision('reject')}>{stale ? 'Reject Stale Plan' : 'Reject Plan'}</Button><Button variant="primary" disabled={stale} onClick={() => onDecision('approve')}>Approve Plan</Button></>}
      {admin && plan.status === 'approved' && <Button variant="danger" onClick={() => onDecision('cancel')}>Cancel Approval</Button>}
      {admin && (plan.status === 'rejected' || plan.status === 'canceled') && <p>This Decision Is Final. Create A New Plan From A Current Finding If Review Must Restart.</p>}
    </footer>
  </aside>
}

export function RemediationReviewPage() {
  const { user } = useAuth()
  const [searchParams, setSearchParams] = useSearchParams()
  const requestedStatus = searchParams.get('status') as PlanFilter | null
  const [status, setStatus] = useState<PlanFilter>(filters.some((item) => item.id === requestedStatus) ? requestedStatus! : 'pending_approval')
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState<RemediationPlan | null>(null)
  const [decision, setDecision] = useState<DecisionKind | null>(null)
  const [decisionBusy, setDecisionBusy] = useState(false)
  const [decisionError, setDecisionError] = useState('')
  const dossierRef = useRef<HTMLElement>(null)
  const plans = useApi(() => api.remediationPlans(), [])
  const requestedPlan = searchParams.get('plan')
  const counts = useMemo(() => Object.fromEntries(filters.map((item) => [item.id, item.id === 'all' ? plans.data?.length ?? 0 : plans.data?.filter((plan) => plan.status === item.id).length ?? 0])) as Record<PlanFilter, number>, [plans.data])
  const visiblePlans = useMemo(() => (plans.data ?? []).filter((plan) => {
    if (status !== 'all' && plan.status !== status) return false
    const needle = query.trim().toLowerCase()
    return !needle || `${plan.title} ${plan.control_id} ${plan.hostname} ${plan.category} ${plan.requested_by_name}`.toLowerCase().includes(needle)
  }), [plans.data, query, status])

  useEffect(() => {
    if (!plans.data) return
    const fromUrl = requestedPlan ? plans.data.find((plan) => plan.id === requestedPlan) : null
    if (fromUrl) { setSelected(fromUrl); return }
    if (selected) {
      const refreshed = plans.data.find((plan) => plan.id === selected.id)
      if (refreshed) { if (refreshed !== selected) setSelected(refreshed); return }
    }
    setSelected(visiblePlans[0] ?? null)
  }, [plans.data, requestedPlan, selected, visiblePlans])

  function updateParams(updates: Record<string, string | null>) {
    const next = new URLSearchParams(searchParams)
    next.set('view', 'remediation')
    Object.entries(updates).forEach(([key, value]) => value ? next.set(key, value) : next.delete(key))
    setSearchParams(next, { replace: true })
  }

  function selectStatus(nextStatus: PlanFilter) {
    setStatus(nextStatus)
    setSelected(null)
    updateParams({ status: nextStatus === 'pending_approval' ? null : nextStatus, plan: null })
  }

  function selectPlan(plan: RemediationPlan) {
    setSelected(plan)
    updateParams({ plan: plan.id })
    window.requestAnimationFrame(() => {
      if (!window.matchMedia('(max-width: 760px)').matches || !dossierRef.current) return
      const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches
      dossierRef.current.scrollIntoView({ behavior: reducedMotion ? 'auto' : 'smooth', block: 'start' })
      dossierRef.current.focus({ preventScroll: true })
    })
  }

  async function submitDecision(reason: string) {
    if (!selected || !decision) return
    setDecisionBusy(true)
    setDecisionError('')
    try {
      const updated = decision === 'approve'
        ? await api.approveRemediationPlan(selected.id)
        : decision === 'reject'
          ? await api.rejectRemediationPlan(selected.id, reason)
          : await api.cancelRemediationPlan(selected.id, reason)
      setSelected(updated)
      setDecision(null)
      await plans.refresh()
    } catch (error) {
      setDecisionError(error instanceof Error ? error.message : 'The Decision Could Not Be Recorded. Try Again.')
    } finally {
      setDecisionBusy(false)
    }
  }

  function openDecision(kind: DecisionKind) {
    setDecisionError('')
    setDecision(kind)
  }

  function closeDecision() {
    setDecisionError('')
    setDecision(null)
  }

  return <div className="page-reveal">
    <PageHeader eyebrow="Change Governance" title="Remediation Review" detail="Review current finding evidence, record accountable decisions, and preserve a complete change history without granting the console permission to modify a host." />
    <nav className="findings-view-tabs" aria-label="Security Finding Workspaces">
      <Link className="findings-view-tab" to="/findings">Findings Queue</Link>
      <Link className="findings-view-tab findings-view-tab-active" to="/findings?view=remediation" aria-current="page">Remediation Review</Link>
    </nav>
    <div className="remediation-safety-banner"><ShieldCheck size={18} /><div><strong>Review And Approval Are Non-Executable</strong><p>Plans contain evidence snapshots and human decisions only. The agent remains audit-only and no action on this page changes host configuration.</p></div></div>
    {plans.loading && !plans.data ? <LoadingState variant="table" /> : plans.error ? <ErrorState message={plans.error} retry={() => void plans.reload()} /> : <section className="panel remediation-review-desk" aria-label="Remediation Review Desk">
      <aside className="remediation-status-rail">
        <header><History size={17} /><div><strong>Decision Queue</strong><small>Filter By Review State</small></div></header>
        <nav aria-label="Remediation Plan Status">{filters.map((filter) => <button key={filter.id} className={`remediation-status-filter ${status === filter.id ? 'remediation-status-filter-active' : ''}`} aria-pressed={status === filter.id} onClick={() => selectStatus(filter.id)}><span><strong>{filter.label}</strong><small>{filter.detail}</small></span><b>{counts[filter.id]}</b></button>)}</nav>
      </aside>
      <div className="remediation-plan-queue">
        <header className="remediation-plan-queue-header">
          <div><h2>{filters.find((item) => item.id === status)?.label}</h2><p>{visiblePlans.length} Plan{visiblePlans.length === 1 ? '' : 's'} In This View</p></div>
          <label className="remediation-plan-search"><Search size={15} /><span className="sr-only">Search Remediation Plans</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search Plan, Host, Or Control" /></label>
        </header>
        <ul className="remediation-plan-list" aria-label="Remediation Plans">
          {visiblePlans.map((plan) => <li key={plan.id}><button className={`remediation-plan-row ${selected?.id === plan.id ? 'remediation-plan-row-active' : ''}`} onClick={() => selectPlan(plan)}>
            <span className="remediation-plan-row-main"><span className="flex items-center gap-2"><SeverityBadge severity={plan.severity} />{(!plan.source_is_current || !plan.finding_still_open) && <span className="remediation-stale-mark"><TriangleAlert size={11} />Stale</span>}</span><strong>{plan.title}</strong><small>{plan.hostname} · {plan.control_id}</small></span>
            <span className="remediation-plan-row-meta"><PlanStatus status={plan.status} /><small>Requested {formatDateTime(plan.requested_at)}</small></span>
            <ArrowRight size={15} />
          </button></li>)}
          {!visiblePlans.length && <li className="remediation-plan-empty"><FileText size={23} /><h2>No Plans Match This View</h2><p>{plans.data?.length ? 'Choose Another Status Or Adjust The Search.' : 'Open A Current Finding And Request Change Review To Start The Approval Record.'}</p>{!plans.data?.length && <Link className="button-secondary" to="/findings">Open Findings Queue</Link>}</li>}
        </ul>
      </div>
      {selected ? <PlanDossier plan={selected} admin={user?.role === 'admin'} onDecision={openDecision} containerRef={dossierRef} /> : <aside className="remediation-dossier remediation-dossier-empty"><ShieldCheck size={24} /><h2>Select A Plan To Review</h2><p>The Evidence Snapshot, Change Impact, And Decision History Will Appear Here.</p></aside>}
    </section>}
    {decision && selected && <DecisionDialog kind={decision} plan={selected} busy={decisionBusy} error={decisionError} close={closeDecision} submit={(reason) => void submitDecision(reason)} />}
  </div>
}
