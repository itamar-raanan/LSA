import { CheckCircle, Copy, ShieldCheck, SlidersHorizontal } from '@phosphor-icons/react'
import { FormEvent, useEffect, useMemo, useState } from 'react'
import { api } from '../../api/client'
import { formatDateTime } from '../../lib/dateTime'
import type { AgentGroup, AgentPolicy, AgentPolicyVersion, ControlCatalogItem, PolicyMode } from '../../types'
import { Button } from '../ui/Button'

const modes: PolicyMode[] = ['audit', 'manual', 'remediate', 'disabled']
type PolicyStage = 'configure' | 'review'

export function AgentPolicyWorkspace({ assignedPolicy, controls, policies, saving, selectedGroup, submit }: {
  assignedPolicy: AgentPolicy
  controls: ControlCatalogItem[]
  policies: AgentPolicy[]
  saving: boolean
  selectedGroup: AgentGroup
  submit: (action: () => Promise<unknown>, close?: () => void) => Promise<void>
}) {
  const [policyVersions, setPolicyVersions] = useState<AgentPolicyVersion[]>([])
  const [historyError, setHistoryError] = useState('')
  const [showPolicy, setShowPolicy] = useState(false)
  const [controlModes, setControlModes] = useState<Record<string, PolicyMode>>({})
  const [selectedCategory, setSelectedCategory] = useState('overview')
  const [draftDescription, setDraftDescription] = useState('')
  const [draftDefaultMode, setDraftDefaultMode] = useState<PolicyMode>('audit')
  const [draftSchedule, setDraftSchedule] = useState(60)
  const [policyStage, setPolicyStage] = useState<PolicyStage>('configure')

  const categories = useMemo(() => {
    const grouped = new Map<string, ControlCatalogItem[]>()
    for (const control of controls) {
      const current = grouped.get(control.category) ?? []
      current.push(control)
      grouped.set(control.category, current)
    }
    return [...grouped.entries()]
  }, [controls])

  const policyChanges = useMemo(() => {
    const controlIds = new Set([...Object.keys(assignedPolicy.control_modes), ...Object.keys(controlModes)])
    return {
      defaultMode: draftDefaultMode !== assignedPolicy.default_mode,
      schedule: draftSchedule !== Number(assignedPolicy.settings.schedule_minutes ?? 60),
      description: draftDescription !== assignedPolicy.description,
      controls: [...controlIds].filter(controlId => (assignedPolicy.control_modes[controlId] ?? null) !== (controlModes[controlId] ?? null)).map(controlId => {
        const catalogControl = controls.find(control => control.control_id === controlId)
        return {
          controlId,
          title: catalogControl?.title ?? controlId,
          from: assignedPolicy.control_modes[controlId] ?? `Inherit ${assignedPolicy.default_mode}`,
          to: controlModes[controlId] ?? `Inherit ${draftDefaultMode}`,
        }
      }),
    }
  }, [assignedPolicy, controlModes, controls, draftDefaultMode, draftDescription, draftSchedule])

  const hasPolicyChanges = policyChanges.defaultMode || policyChanges.schedule || policyChanges.description || policyChanges.controls.length > 0
  const policyChangeCount = Number(policyChanges.defaultMode) + Number(policyChanges.schedule) + Number(policyChanges.description) + policyChanges.controls.length
  const categoryControls = selectedCategory === 'overview' ? [] : categories.find(([category]) => category === selectedCategory)?.[1] ?? []

  useEffect(() => {
    setControlModes({ ...assignedPolicy.control_modes })
    setDraftDescription(assignedPolicy.description)
    setDraftDefaultMode(assignedPolicy.default_mode)
    setDraftSchedule(Number(assignedPolicy.settings.schedule_minutes ?? 60))
    setSelectedCategory('overview')
    setPolicyStage('configure')
  }, [assignedPolicy])

  useEffect(() => {
    let active = true
    setHistoryError('')
    api.agentPolicyVersions(assignedPolicy.id)
      .then(versions => { if (active) setPolicyVersions(versions) })
      .catch(caught => { if (active) setHistoryError(caught instanceof Error ? caught.message : 'Unable to load policy history') })
    return () => { active = false }
  }, [assignedPolicy])

  function createGroupPolicy(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const values = new FormData(event.currentTarget)
    void submit(async () => {
      const policy = await api.createAgentPolicy({
        name: String(values.get('name')),
        description: String(values.get('description')),
        default_mode: String(values.get('default_mode')) as PolicyMode,
        control_modes: {},
        settings: { schedule_minutes: Number(values.get('schedule_minutes')), jitter_seconds: 300, profile: 'level2_server' },
      })
      await api.updateAgentGroup(selectedGroup.id, { name: selectedGroup.name, description: selectedGroup.description, policy_id: policy.id })
    }, () => setShowPolicy(false))
  }

  function applyExistingPolicy(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const values = new FormData(event.currentTarget)
    void submit(() => api.updateAgentGroup(selectedGroup.id, {
      name: selectedGroup.name,
      description: selectedGroup.description,
      policy_id: String(values.get('policy_id')),
    }))
  }

  function clonePolicyForGroup() {
    void submit(async () => {
      const policy = await api.createAgentPolicy({
        name: `${selectedGroup.name} policy`,
        description: assignedPolicy.description,
        default_mode: assignedPolicy.default_mode,
        control_modes: assignedPolicy.control_modes,
        settings: assignedPolicy.settings,
      })
      await api.updateAgentGroup(selectedGroup.id, { name: selectedGroup.name, description: selectedGroup.description, policy_id: policy.id })
    })
  }

  function publishPolicy() {
    if (assignedPolicy.assigned_groups > 1 || !hasPolicyChanges) return
    void submit(() => api.updateAgentPolicy(assignedPolicy.id, {
      description: draftDescription,
      default_mode: draftDefaultMode,
      control_modes: controlModes,
      settings: { ...assignedPolicy.settings, schedule_minutes: draftSchedule, profile: String(assignedPolicy.settings.profile ?? 'level2_server') },
    }), () => setPolicyStage('configure'))
  }

  return <div className="min-h-[570px] min-w-0">
    {policyStage === 'configure' && <div className="flex flex-col gap-3 border-b border-stone-200 bg-[#f7f3eb] px-5 py-4 sm:flex-row sm:items-center sm:justify-between sm:px-7">
      <div><p className="text-xs font-semibold text-stone-800">Policy workspace</p><p className="mt-1 text-[11px] text-stone-600">Choose the policy overview or one control category.</p></div>
      <label className="flex min-w-0 items-center gap-3 text-xs font-medium text-stone-600"><SlidersHorizontal size={15} /><span className="sr-only">Policy section</span><select className="select-input min-h-9 w-full min-w-52 sm:w-auto" aria-label="Policy section" value={selectedCategory} onChange={(event) => setSelectedCategory(event.target.value)}><option value="overview">Overview</option>{categories.map(([category, categoryItems]) => <option key={category} value={category}>{category.replaceAll('_', ' ')} · {categoryItems.length}</option>)}</select></label>
    </div>}

    <div className="min-w-0">
      {policyStage === 'review' ? <div>
        <div className="policy-safety-note flex items-start gap-3 border-b px-5 py-4 text-xs leading-5 sm:px-7">
          <ShieldCheck size={17} className="mt-0.5 shrink-0" />
          <span><strong>Audit-Only Safety Lock Is Active.</strong> Publishing changes what the agent audits, but this release still cannot modify host configuration.</span>
        </div>
        <div className="border-b border-stone-200 px-5 py-6 sm:px-7">
          <div className="flex flex-col gap-5 xl:flex-row xl:items-start xl:justify-between">
            <div>
              <p className="section-label">Review Policy Changes</p>
              <h3 className="mt-2 text-xl font-semibold text-stone-800">Confirm Version {assignedPolicy.version + 1}</h3>
              <p className="mt-2 max-w-2xl text-xs leading-5 text-stone-500">Review the differences below before publishing an immutable policy version for {selectedGroup.name}.</p>
            </div>
            <span className="settings-state">{policyChangeCount} {policyChangeCount === 1 ? 'Change' : 'Changes'}</span>
          </div>
          <ol className="mt-6 grid max-w-2xl grid-cols-3 border-y border-stone-200 py-3 text-[11px]">
            <li className="text-stone-500"><span className="mr-2 font-mono">01</span>Configure</li>
            <li className="font-semibold text-[#80551f]"><span className="mr-2 font-mono">02</span>Review</li>
            <li className="text-stone-500"><span className="mr-2 font-mono">03</span>Publish</li>
          </ol>
        </div>

        <div className="px-5 py-6 sm:px-7">
          <div className="grid gap-px overflow-hidden rounded-xl border border-stone-200 bg-stone-200 sm:grid-cols-2">
            <div className="bg-[#fbfaf7] p-4"><span className="detail-label">Policy</span><strong className="mt-2 block text-sm text-stone-800">{assignedPolicy.name}</strong><span className="table-subtitle">Version {assignedPolicy.version} → {assignedPolicy.version + 1}</span></div>
            <div className="bg-[#fbfaf7] p-4"><span className="detail-label">Assigned Group</span><strong className="mt-2 block text-sm text-stone-800">{selectedGroup.name}</strong><span className="table-subtitle">{selectedGroup.agent_count} Enrolled Hosts</span></div>
          </div>

          <div className="mt-6 border-y border-stone-200">
            {policyChanges.defaultMode && <div className="grid gap-2 border-b border-stone-200 py-4 sm:grid-cols-[180px_minmax(0,1fr)]"><span className="detail-label">Default Mode</span><span className="text-xs text-stone-700"><s className="mr-3 text-stone-500">{assignedPolicy.default_mode}</s><strong>{draftDefaultMode}</strong></span></div>}
            {policyChanges.schedule && <div className="grid gap-2 border-b border-stone-200 py-4 sm:grid-cols-[180px_minmax(0,1fr)]"><span className="detail-label">Audit Schedule</span><span className="text-xs text-stone-700"><s className="mr-3 text-stone-500">{Number(assignedPolicy.settings.schedule_minutes ?? 60)} Minutes</s><strong>{draftSchedule} Minutes</strong></span></div>}
            {policyChanges.description && <div className="grid gap-2 border-b border-stone-200 py-4 sm:grid-cols-[180px_minmax(0,1fr)]"><span className="detail-label">Description</span><div className="text-xs leading-5 text-stone-700"><p className="text-stone-500">{assignedPolicy.description || 'No Description'}</p><p className="mt-1 font-medium">{draftDescription || 'No Description'}</p></div></div>}
            {policyChanges.controls.length > 0 && <div className="py-4">
              <div className="mb-3 flex items-center justify-between gap-3"><span className="detail-label">Control Overrides</span><span className="font-mono text-[10px] text-stone-500">{policyChanges.controls.length} Changed</span></div>
              <div className="divide-y divide-stone-200">{policyChanges.controls.map(change => <div key={change.controlId} className="grid gap-2 py-3 sm:grid-cols-[180px_minmax(0,1fr)_160px] sm:items-center">
                <code className="text-[10px] text-stone-500">{change.controlId}</code>
                <span className="text-xs text-stone-700">{change.title}</span>
                <span className="text-[11px] text-stone-500"><s>{change.from}</s><strong className="ml-2 text-stone-700">{change.to}</strong></span>
              </div>)}</div>
            </div>}
          </div>
        </div>

        <div className="flex flex-col gap-3 border-t border-stone-200 px-5 py-5 sm:flex-row sm:items-center sm:justify-between sm:px-7">
          <Button disabled={saving} onClick={() => setPolicyStage('configure')}>Back To Configuration</Button>
          <div className="flex flex-col items-start gap-3 sm:flex-row sm:items-center"><span className="flex items-center gap-2 text-xs text-stone-600"><CheckCircle size={16} /> Version {assignedPolicy.version + 1} Cannot Be Edited After Publication</span><Button variant="primary" disabled={saving || !hasPolicyChanges} onClick={publishPolicy}>{saving ? 'Publishing…' : `Publish Version ${assignedPolicy.version + 1}`}</Button></div>
        </div>
      </div> : selectedCategory === 'overview' ? <div>
        <div className="policy-safety-note flex items-start gap-3 border-b px-5 py-4 text-xs leading-5 sm:px-7">
          <ShieldCheck size={17} className="mt-0.5 shrink-0" />
          <span><strong>Audit-Only Safety Lock Is Active.</strong> Remediation modes can be staged here, but this agent release cannot change host configuration.</span>
        </div>
        <div className="border-b border-stone-200 px-5 py-5 sm:px-7">
          <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
            <div><p className="section-label">Effective policy</p><h3 className="mt-2 text-base font-semibold text-stone-800">{assignedPolicy.name}</h3><p className="mt-2 max-w-xl text-xs leading-5 text-stone-500">{assignedPolicy.description || 'No policy description.'}</p></div>
            <span className="settings-state">Version {assignedPolicy.version} · {Object.keys(controlModes).length} Overrides</span>
          </div>
        </div>

        {assignedPolicy.assigned_groups > 1 && <div className="flex flex-col gap-4 border-b border-amber-900/30 bg-amber-950/10 px-5 py-4 sm:flex-row sm:items-center sm:justify-between sm:px-7">
          <div><p className="text-xs font-medium text-amber-800">Shared by {assignedPolicy.assigned_groups} groups</p><p className="mt-1 text-[11px] leading-5 text-stone-500">Create a group-owned copy before changing controls, so other groups keep their current policy.</p></div>
          <button className="button-secondary shrink-0" disabled={saving} onClick={clonePolicyForGroup}><Copy size={14} /> Make group-specific copy</button>
        </div>}

        <div className="grid min-w-0 gap-5 border-b border-stone-200 px-5 py-6 sm:px-7 2xl:grid-cols-[minmax(0,1fr)_260px]">
          <div className="grid gap-4 sm:grid-cols-2">
            <label className="form-field">Default mode<select className="select-input w-full" value={draftDefaultMode} disabled={assignedPolicy.assigned_groups > 1} onChange={event => setDraftDefaultMode(event.target.value as PolicyMode)}>{modes.map(mode => <option key={mode}>{mode}</option>)}</select></label>
            <label className="form-field">Schedule minutes<input type="number" min="5" max="10080" value={draftSchedule} disabled={assignedPolicy.assigned_groups > 1} onChange={event => setDraftSchedule(Number(event.target.value))} /></label>
            <label className="form-field sm:col-span-2">Description<input value={draftDescription} disabled={assignedPolicy.assigned_groups > 1} onChange={event => setDraftDescription(event.target.value)} /></label>
          </div>
          <div className="min-w-0 border-t border-stone-200 pt-5 2xl:border-l 2xl:border-t-0 2xl:pl-5 2xl:pt-0">
            <p className="section-label">Apply another policy</p>
            <form key={assignedPolicy.id} className="mt-3 grid gap-3" onSubmit={applyExistingPolicy}>
              <select name="policy_id" className="select-input w-full" defaultValue={assignedPolicy.id}>{policies.map(policy => <option key={policy.id} value={policy.id}>{policy.name} · v{policy.version}</option>)}</select>
              <button className="button-secondary min-h-9" disabled={saving}>Apply to {selectedGroup.name}</button>
            </form>
            <button className="mt-3 text-xs text-[#4f6f5c] transition hover:text-[#4f6f5c]" onClick={() => setShowPolicy(!showPolicy)}>Create a new policy for this group</button>
          </div>
        </div>

        {showPolicy && <form className="grid gap-4 border-b border-stone-200 bg-[#f7f3eb] px-5 py-5 sm:grid-cols-2 sm:px-7" onSubmit={createGroupPolicy}>
          <label className="form-field sm:col-span-2">Policy name<input name="name" required placeholder={`${selectedGroup.name} policy`} /></label>
          <label className="form-field sm:col-span-2">Description<input name="description" placeholder="Policy owned by this group" /></label>
          <label className="form-field">Default mode<select name="default_mode" className="select-input w-full" defaultValue="audit">{modes.map(mode => <option key={mode}>{mode}</option>)}</select></label>
          <label className="form-field">Schedule<select name="schedule_minutes" className="select-input w-full" defaultValue="60"><option value="15">15 minutes</option><option value="60">Hourly</option><option value="1440">Daily</option></select></label>
          <div className="flex justify-end gap-2 sm:col-span-2"><button type="button" className="button-secondary" onClick={() => setShowPolicy(false)}>Cancel</button><button className="button-primary" disabled={saving}>Create and apply</button></div>
        </form>}

        <div className="border-b border-stone-200 px-5 py-5 sm:px-7">
          <div className="flex items-end justify-between gap-4"><div><p className="section-label">Version history</p><p className="mt-2 text-xs text-stone-500">Every publication is immutable. Restoring publishes a new version from the selected snapshot.</p></div><span className="font-mono text-[10px] text-stone-600">{policyVersions.length} versions</span></div>
          {historyError ? <p className="mt-4 text-xs text-rose-700">{historyError}</p> : <div className="mt-4 divide-y divide-stone-200 border-y border-stone-200">{policyVersions.map(version => <div key={version.version} className="flex flex-col gap-3 py-3 sm:flex-row sm:items-center">
            <div className="min-w-0 flex-1"><strong className="text-xs text-stone-700">Version {version.version}{version.version === assignedPolicy.version ? ' · current' : ''}</strong><span className="table-subtitle">{version.default_mode} default · {Object.keys(version.control_modes).length} overrides · {version.created_by_name ?? 'system'} · {formatDateTime(version.created_at)}</span></div>
            {version.version !== assignedPolicy.version && <button className="button-secondary min-h-9 shrink-0" disabled={saving || assignedPolicy.assigned_groups > 1} onClick={() => void submit(() => api.restoreAgentPolicy(assignedPolicy.id, version.version))}>Restore as v{assignedPolicy.version + 1}</button>}
          </div>)}</div>}
        </div>

        <div className="flex flex-col items-start justify-between gap-4 px-5 py-5 sm:flex-row sm:items-center sm:px-7">
          <span className="flex items-center gap-2 text-xs text-stone-600"><CheckCircle size={16} /> {hasPolicyChanges ? `${policyChangeCount} Pending ${policyChangeCount === 1 ? 'Change' : 'Changes'}` : 'No Unpublished Changes'}</span>
          <Button variant="primary" disabled={saving || assignedPolicy.assigned_groups > 1 || !hasPolicyChanges} onClick={() => setPolicyStage('review')}>Review Changes</Button>
        </div>
      </div> : <div>
        <div className="border-b border-stone-200 px-5 py-5 sm:px-7">
          <p className="section-label">Policy category</p>
          <div className="mt-2 flex items-end justify-between gap-4"><div><h3 className="text-base font-semibold capitalize text-stone-800">{selectedCategory.replaceAll('_', ' ')}</h3><p className="mt-1 text-xs text-stone-500">Override individual controls for {selectedGroup.name}, or inherit the policy default.</p></div><span className="font-mono text-[10px] text-stone-600">{categoryControls.length} controls</span></div>
        </div>
        <div>{categoryControls.map(control => <div key={control.control_id} className="grid min-w-0 gap-3 border-b border-stone-200/70 px-5 py-4 sm:px-7 2xl:grid-cols-[155px_minmax(0,1fr)_170px] 2xl:items-center">
          <code className="text-[10px] text-stone-500">{control.control_id}</code>
          <span className="text-xs text-stone-700">{control.title}<small className="table-subtitle">{control.module}</small></span>
          <select
            aria-label={`Mode for ${control.control_id}`}
            className="select-input w-full"
            disabled={assignedPolicy.assigned_groups > 1}
            value={controlModes[control.control_id] ?? ''}
            onChange={event => {
              const value = event.target.value as PolicyMode | ''
              setControlModes(current => {
                const next = { ...current }
                if (value) next[control.control_id] = value
                else delete next[control.control_id]
                return next
              })
            }}
          ><option value="">Inherit {draftDefaultMode}</option>{modes.map(mode => <option key={mode}>{mode}</option>)}</select>
        </div>)}</div>
        <div className="sticky bottom-0 flex flex-col items-start justify-between gap-4 border-t border-stone-200 bg-[#f7f3eb]/95 px-5 py-4 backdrop-blur sm:flex-row sm:items-center sm:px-7">
          <span className="text-xs text-stone-600">{hasPolicyChanges ? `${policyChangeCount} Pending ${policyChangeCount === 1 ? 'Change' : 'Changes'}` : 'No Unpublished Changes'}</span>
          <button className="button-primary" disabled={saving || assignedPolicy.assigned_groups > 1 || !hasPolicyChanges} onClick={() => setPolicyStage('review')}>Review Changes</button>
        </div>
      </div>}
    </div>
  </div>
}
