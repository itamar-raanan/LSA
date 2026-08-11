import {
  CalendarClock, CheckCircle2, CircleSlash2, Fingerprint, KeyRound,
  Layers3, LockKeyhole, ShieldCheck, ShieldX, TriangleAlert,
} from 'lucide-react'
import { FormEvent, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import { useAuth } from '../auth/useAuth'
import { PageHeader } from '../components/PageHeader'
import { ErrorState, LoadingState } from '../components/StatePanel'
import { Button } from '../components/ui/Button'
import { Dialog } from '../components/ui/Dialog'
import { useApi } from '../hooks/useApi'
import { formatDateTime } from '../lib/dateTime'
import type { RemediationChangeSet, RemediationPlan } from '../types'

function localDateTime(hoursFromNow: number) {
  const date = new Date(Date.now() + hoursFromNow * 60 * 60_000)
  date.setMinutes(Math.ceil(date.getMinutes() / 15) * 15, 0, 0)
  const offset = date.getTimezoneOffset() * 60_000
  return new Date(date.getTime() - offset).toISOString().slice(0, 16)
}

function statusLabel(changeSet: RemediationChangeSet) {
  if (changeSet.status === 'authorized') return 'Signed And Authorized'
  if (changeSet.status === 'canceled') return 'Canceled'
  return changeSet.gates.some(gate => gate.status === 'blocked' && gate.code !== 'four_eyes') ? 'Readiness Blocked' : 'Awaiting Independent Authorization'
}

function ChangeSetStatus({ changeSet }: { changeSet: RemediationChangeSet }) {
  const Icon = changeSet.status === 'authorized' ? CheckCircle2 : changeSet.status === 'canceled' ? CircleSlash2 : changeSet.gates.some(gate => gate.status === 'blocked' && gate.code !== 'four_eyes') ? TriangleAlert : LockKeyhole
  return <span className={`change-set-status change-set-status-${changeSet.status}`}><Icon size={13} />{statusLabel(changeSet)}</span>
}

function CreateChangeSetDialog({ plans, busy, error, close, submit }: { plans: RemediationPlan[]; busy: boolean; error: string; close: () => void; submit: (input: { plan_ids: string[]; canary_host_ids: string[]; maintenance_window_start: string; maintenance_window_end: string; batch_size: number; batch_interval_minutes: number }) => void }) {
  const [selectedPlans, setSelectedPlans] = useState<Set<string>>(new Set())
  const [canaries, setCanaries] = useState<Set<string>>(new Set())
  const [windowStart, setWindowStart] = useState(localDateTime(1))
  const [windowEnd, setWindowEnd] = useState(localDateTime(3))
  const [batchSize, setBatchSize] = useState(1)
  const [batchInterval, setBatchInterval] = useState(15)
  const selected = plans.filter(plan => selectedPlans.has(plan.id))
  const hosts = [...new Map(selected.map(plan => [plan.host_id, plan.hostname])).entries()]

  function togglePlan(plan: RemediationPlan) {
    const next = new Set(selectedPlans)
    if (next.has(plan.id)) next.delete(plan.id); else next.add(plan.id)
    setSelectedPlans(next)
    const remainingHosts = new Set(plans.filter(item => next.has(item.id)).map(item => item.host_id))
    setCanaries(new Set([...canaries].filter(hostId => remainingHosts.has(hostId))))
  }

  function toggleCanary(hostId: string) {
    const next = new Set(canaries)
    if (next.has(hostId)) next.delete(hostId); else next.add(hostId)
    setCanaries(next)
  }

  function handleSubmit(event: FormEvent) {
    event.preventDefault()
    submit({
      plan_ids: [...selectedPlans],
      canary_host_ids: [...canaries],
      maintenance_window_start: new Date(windowStart).toISOString(),
      maintenance_window_end: new Date(windowEnd).toISOString(),
      batch_size: batchSize,
      batch_interval_minutes: batchInterval,
    })
  }

  return <Dialog open onOpenChange={(open) => { if (!open && !busy) close() }} eyebrow="Governed Change" title="Prepare A Change Set" description="Select approved plans, define the first canary scope, and schedule a bounded maintenance window." size="lg">
    <form className="change-set-create-form" onSubmit={handleSubmit}>
      <section><h3>Approved Plans</h3><p>Only plans with reviewed declarative actions can enter a signed envelope.</p>
        <div className="change-set-plan-options">{plans.map(plan => <label key={plan.id}><input type="checkbox" checked={selectedPlans.has(plan.id)} onChange={() => togglePlan(plan)} /><span><strong>{plan.title}</strong><small>{plan.hostname} · {plan.control_id}</small></span></label>)}</div>
        {!plans.length && <div className="change-set-form-empty">No Approved Catalog-Backed Plans Are Available.</div>}
      </section>
      {hosts.length > 0 && <section><h3>Canary Hosts</h3><p>At least one selected host must be observed first. Remaining hosts stay deferred.</p>
        <div className="change-set-canary-options">{hosts.map(([hostId, hostname]) => <label key={hostId}><input type="checkbox" checked={canaries.has(hostId)} onChange={() => toggleCanary(hostId)} /><span>{hostname}</span></label>)}</div>
      </section>}
      <section className="change-set-window-grid"><label className="form-field"><span>Window Start</span><input type="datetime-local" required value={windowStart} onChange={event => setWindowStart(event.target.value)} /></label><label className="form-field"><span>Window End</span><input type="datetime-local" required value={windowEnd} onChange={event => setWindowEnd(event.target.value)} /></label><label className="form-field"><span>Batch Size</span><input type="number" min="1" max="25" required value={batchSize} onChange={event => setBatchSize(Number(event.target.value))} /></label><label className="form-field"><span>Interval Minutes</span><input type="number" min="15" max="1440" step="15" required value={batchInterval} onChange={event => setBatchInterval(Number(event.target.value))} /></label></section>
      <div className="change-set-form-lock"><ShieldX size={16} /><p><strong>Compilation Does Not Dispatch Work.</strong> The envelope remains non-executable even after authorization.</p></div>
      {error && <p className="remediation-decision-error" role="alert">{error}</p>}
      <div className="remediation-dialog-actions"><Button type="button" variant="ghost" disabled={busy} onClick={close}>Keep Reviewing</Button><Button type="submit" variant="primary" disabled={busy || selectedPlans.size === 0 || canaries.size === 0}>{busy ? 'Preparing Change Set' : 'Prepare Change Set'}</Button></div>
    </form>
  </Dialog>
}

function CancelDialog({ busy, error, close, submit }: { busy: boolean; error: string; close: () => void; submit: (reason: string) => void }) {
  const [reason, setReason] = useState('')
  return <Dialog open onOpenChange={(open) => { if (!open && !busy) close() }} eyebrow="Protected Decision" title="Cancel Change Set?" description="The envelope and its audit history remain retained.">
    <label className="form-field"><span>Cancellation Reason</span><textarea rows={4} value={reason} onChange={event => setReason(event.target.value)} placeholder="Explain Why This Change Set Must Not Proceed" /></label>
    {error && <p className="remediation-decision-error" role="alert">{error}</p>}
    <div className="remediation-dialog-actions"><Button variant="ghost" disabled={busy} onClick={close}>Keep Change Set</Button><Button variant="danger" disabled={busy || reason.trim().length < 3} onClick={() => submit(reason.trim())}>{busy ? 'Canceling' : 'Cancel Change Set'}</Button></div>
  </Dialog>
}

function ChangeSetDossier({ changeSet, admin, currentUserId, authorize, cancel }: { changeSet: RemediationChangeSet; admin: boolean; currentUserId?: string; authorize: () => void; cancel: () => void }) {
  const operationalBlocks = changeSet.gates.filter(gate => gate.status === 'blocked' && gate.code !== 'four_eyes')
  const independent = currentUserId !== changeSet.requested_by && changeSet.plans.every(plan => plan.plan_approved_by !== currentUserId)
  return <aside className="change-set-dossier" aria-label={`Change Set ${changeSet.id} Dossier`}>
    <header><div><ChangeSetStatus changeSet={changeSet} /><h2>{changeSet.plans.length} Reviewed Change{changeSet.plans.length === 1 ? '' : 's'}</h2><p>{changeSet.targets.length} Target{changeSet.targets.length === 1 ? '' : 's'} · Requested By {changeSet.requested_by_name}</p></div><span className="change-set-short-id">{changeSet.id.slice(0, 8)}</span></header>
    <div className="remediation-execution-lock"><ShieldX size={17} /><div><strong>Signed Governance Record Only</strong><p>{changeSet.execution_reason}</p></div></div>
    <section className="change-set-section"><div className="change-set-section-heading"><h3>Readiness Gates</h3><span>{changeSet.gates.filter(gate => gate.status === 'passed').length} Of {changeSet.gates.length} Passed</span></div><ul className="change-set-gates">{changeSet.gates.map(gate => <li key={gate.code} className={gate.status === 'passed' ? 'change-set-gate-passed' : 'change-set-gate-blocked'}>{gate.status === 'passed' ? <CheckCircle2 size={15} /> : <TriangleAlert size={15} />}<div><strong>{gate.code.replaceAll('_', ' ')}</strong><p>{gate.detail}</p></div></li>)}</ul></section>
    <section className="change-set-section"><div className="change-set-section-heading"><h3>Canary Rollout</h3><span>Batch {changeSet.batch_size} · Every {changeSet.batch_interval_minutes} Minutes</span></div><div className="change-set-targets">{changeSet.targets.map(target => <div key={target.host_id}><span className={`change-set-phase change-set-phase-${target.rollout_phase}`}>{target.rollout_phase}</span><div><strong>{target.hostname}</strong><p>{target.group_name} · {target.policy_name} V{target.policy_version}</p></div><span>{target.capability_attested ? 'Capability Attested' : 'Capability Missing'}</span></div>)}</div><div className="change-set-window"><CalendarClock size={16} /><span><strong>{formatDateTime(changeSet.maintenance_window_start)}</strong><small>Through {formatDateTime(changeSet.maintenance_window_end)}</small></span></div></section>
    <section className="change-set-section"><div className="change-set-section-heading"><h3>Signed Envelope</h3><span>{changeSet.signature ? 'Signature Verified' : 'Pending Authorization'}</span></div><dl className="change-set-integrity"><div><dt>Payload Digest</dt><dd>{changeSet.digest}</dd></div><div><dt>Signing Key</dt><dd>{changeSet.signing_key_fingerprint ?? 'Created Only After Independent Authorization'}</dd></div>{changeSet.signature && <div><dt>Ed25519 Signature</dt><dd>{changeSet.signature}</dd></div>}</dl></section>
    <section className="change-set-section"><div className="change-set-section-heading"><h3>Included Plans</h3><span>{changeSet.plans.length}</span></div><div className="change-set-plans">{changeSet.plans.map(plan => <div key={plan.plan_id}><Layers3 size={15} /><span><strong>{plan.title}</strong><small>{plan.hostname} · {plan.control_id} · {plan.action_id} V{plan.action_version}</small></span></div>)}</div></section>
    <footer className="change-set-actions">
      {!admin && <p>Your Role Can Review This Envelope But Cannot Change Its State.</p>}
      {admin && changeSet.status === 'pending_authorization' && <><Button variant="danger" onClick={cancel}>Cancel Change Set</Button><div><Button variant="primary" disabled={!independent || operationalBlocks.length > 0} onClick={authorize}>Authorize And Sign</Button>{!independent && <small>A Different Administrator Must Authorize.</small>}{operationalBlocks.length > 0 && <small>Resolve Every Operational Gate Before Authorization.</small>}</div></>}
      {admin && changeSet.status === 'authorized' && <><p><ShieldCheck size={14} />Authorized By {changeSet.authorized_by_name} On {formatDateTime(changeSet.authorized_at)}</p><Button variant="danger" onClick={cancel}>Cancel Change Set</Button></>}
      {changeSet.status === 'canceled' && <p><CircleSlash2 size={14} />Canceled By {changeSet.canceled_by_name}: {changeSet.cancellation_reason}</p>}
    </footer>
  </aside>
}

export function ChangeSetsPage() {
  const { user } = useAuth()
  const workspace = useApi(async () => {
    const [changeSets, plans] = await Promise.all([api.remediationChangeSets(), api.remediationPlans({ status: 'approved' })])
    return { changeSets, plans }
  }, [])
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)
  const [canceling, setCanceling] = useState(false)
  const [busy, setBusy] = useState(false)
  const [mutationError, setMutationError] = useState('')
  const changeSets = useMemo(() => workspace.data?.changeSets ?? [], [workspace.data?.changeSets])
  const selected = useMemo(() => changeSets.find(item => item.id === selectedId) ?? changeSets[0] ?? null, [changeSets, selectedId])
  const eligiblePlans = (workspace.data?.plans ?? []).filter(plan => plan.action_catalog_status === 'matched' && plan.action !== null)

  async function mutate(action: () => Promise<RemediationChangeSet>, close?: () => void) {
    setBusy(true); setMutationError('')
    try { const updated = await action(); setSelectedId(updated.id); close?.(); await workspace.reload() }
    catch (error) { setMutationError(error instanceof Error ? error.message : 'The Change Set Could Not Be Updated.') }
    finally { setBusy(false) }
  }

  return <div className="page-reveal">
    <PageHeader eyebrow="Change Governance" title="Signed Change Sets" detail="Compile approved plans into immutable canary envelopes, verify every readiness gate, and require independent authorization before signing." action={user?.role === 'admin' ? <Button variant="primary" onClick={() => { setMutationError(''); setCreating(true) }}>Prepare Change Set</Button> : undefined} />
    <nav className="findings-view-tabs" aria-label="Security Finding Workspaces"><Link className="findings-view-tab" to="/findings">Findings Queue</Link><Link className="findings-view-tab" to="/findings?view=remediation">Remediation Review</Link><Link className="findings-view-tab findings-view-tab-active" to="/findings?view=change-sets" aria-current="page">Change Sets</Link></nav>
    <div className="remediation-safety-banner"><KeyRound size={18} /><div><strong>Signing Does Not Enable Execution</strong><p>Change sets are retained governance artifacts. The agent protocol remains audit-only and the agent gateway does not expose this workflow.</p></div></div>
    {workspace.loading && !workspace.data ? <LoadingState variant="table" /> : workspace.error ? <ErrorState message={workspace.error} retry={() => void workspace.reload()} /> : <section className="panel change-set-workspace" aria-label="Signed Change Set Workspace">
      <div className="change-set-queue"><header><div><h2>Authorization Queue</h2><p>{changeSets.length} Retained Envelope{changeSets.length === 1 ? '' : 's'}</p></div><Fingerprint size={18} /></header><ul>{changeSets.map(changeSet => <li key={changeSet.id}><button className={selected?.id === changeSet.id ? 'change-set-row change-set-row-active' : 'change-set-row'} onClick={() => setSelectedId(changeSet.id)}><ChangeSetStatus changeSet={changeSet} /><strong>{changeSet.plans.length} Change{changeSet.plans.length === 1 ? '' : 's'} · {changeSet.targets.length} Target{changeSet.targets.length === 1 ? '' : 's'}</strong><small>{formatDateTime(changeSet.maintenance_window_start)} · {changeSet.id.slice(0, 8)}</small></button></li>)}{!changeSets.length && <li className="change-set-empty"><LockKeyhole size={24} /><h2>No Change Sets Yet</h2><p>Approve a catalog-backed remediation plan, then prepare its canary and maintenance boundaries here.</p></li>}</ul></div>
      {selected ? <ChangeSetDossier changeSet={selected} admin={user?.role === 'admin'} currentUserId={user?.id} authorize={() => void mutate(() => api.authorizeRemediationChangeSet(selected.id))} cancel={() => { setMutationError(''); setCanceling(true) }} /> : <aside className="change-set-dossier change-set-dossier-empty"><ShieldCheck size={24} /><h2>Select Or Prepare A Change Set</h2><p>Readiness gates, canary scope, cryptographic proof, and authorization history will appear here.</p></aside>}
    </section>}
    {creating && <CreateChangeSetDialog plans={eligiblePlans} busy={busy} error={mutationError} close={() => setCreating(false)} submit={input => void mutate(() => api.createRemediationChangeSet(input), () => setCreating(false))} />}
    {canceling && selected && <CancelDialog busy={busy} error={mutationError} close={() => setCanceling(false)} submit={reason => void mutate(() => api.cancelRemediationChangeSet(selected.id, reason), () => setCanceling(false))} />}
  </div>
}
