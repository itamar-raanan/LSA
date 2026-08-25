import {
  CheckCircle,
  Copy,
  DownloadSimple,
  Key,
  Play,
  Prohibit,
  ShieldCheck,
  SlidersHorizontal,
} from '@phosphor-icons/react'
import { FormEvent, useEffect, useMemo, useState } from 'react'
import { api } from '../../api/client'
import { AgentDownloadPanel } from '../../components/AgentDownloadPanel'
import { AgentFleetTable } from '../../components/agents/AgentFleetTable'
import { AgentGroupRail } from '../../components/agents/AgentGroupRail'
import { AgentWorkspaceHeader, type AgentWorkspaceTab } from '../../components/agents/AgentWorkspaceHeader'
import { agentStatus, type AgentStatus } from '../../components/agents/agentStatus'
import { PageHeader } from '../../components/PageHeader'
import { ErrorState, LoadingState } from '../../components/StatePanel'
import { Button } from '../../components/ui/Button'
import { Dialog } from '../../components/ui/Dialog'
import { useApi } from '../../hooks/useApi'
import { formatDateTime } from '../../lib/dateTime'
import type { AgentPolicyVersion, ControlCatalogItem, PlatformCommandTrust, PolicyMode } from '../../types'

const modes: PolicyMode[] = ['audit', 'manual', 'remediate', 'disabled']
type PolicyStage = 'configure' | 'review'

export function AgentsSettingsPage() {
  const { data, error, loading, reload, refresh } = useApi(async () => {
    const [agents, groups, policies, controls, enrollmentTokens, packages, connectivity] = await Promise.all([
      api.agents(), api.agentGroups(), api.agentPolicies(), api.controlCatalog(), api.agentEnrollmentTokens(), api.agentPackages(), api.agentConnectivity(),
    ])
    return { agents, groups, policies, controls, enrollmentTokens, packages, connectivity }
  }, [])
  const [selectedGroupId, setSelectedGroupId] = useState('all')
  const [activeTab, setActiveTab] = useState<AgentWorkspaceTab>('hosts')
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState<'all' | AgentStatus>('all')
  const [selectedAgents, setSelectedAgents] = useState<Set<string>>(new Set())
  const [bulkGroupId, setBulkGroupId] = useState('')
  const [confirmBulkRevoke, setConfirmBulkRevoke] = useState(false)
  const [policyVersions, setPolicyVersions] = useState<AgentPolicyVersion[]>([])
  const [historyError, setHistoryError] = useState('')
  const [showGroup, setShowGroup] = useState(false)
  const [showPolicy, setShowPolicy] = useState(false)
  const [showDownloads, setShowDownloads] = useState(false)
  const [token, setToken] = useState('')
  const [enrollmentTrust, setEnrollmentTrust] = useState<PlatformCommandTrust | null>(null)
  const [enrollmentType, setEnrollmentType] = useState<'one_time' | 'reusable'>('one_time')
  const [createdTokenType, setCreatedTokenType] = useState<'one_time' | 'reusable'>('one_time')
  const [createdTokenMaxUses, setCreatedTokenMaxUses] = useState<number | null>(null)
  const [formError, setFormError] = useState('')
  const [saving, setSaving] = useState(false)
  const [controlModes, setControlModes] = useState<Record<string, PolicyMode>>({})
  const [selectedCategory, setSelectedCategory] = useState('overview')
  const [draftDescription, setDraftDescription] = useState('')
  const [draftDefaultMode, setDraftDefaultMode] = useState<PolicyMode>('audit')
  const [draftSchedule, setDraftSchedule] = useState(60)
  const [policyStage, setPolicyStage] = useState<PolicyStage>('configure')
  const [rotationDecision, setRotationDecision] = useState<'activate' | 'abort' | null>(null)

  const selectedGroup = data?.groups.find(group => group.id === selectedGroupId) ?? null

  const assignedPolicy = selectedGroup ? data?.policies.find(policy => policy.id === selectedGroup.policy_id) ?? null : null
  const policyChanges = useMemo(() => {
    if (!assignedPolicy) return { defaultMode: false, schedule: false, description: false, controls: [] }
    const controlIds = new Set([...Object.keys(assignedPolicy.control_modes), ...Object.keys(controlModes)])
    return {
      defaultMode: draftDefaultMode !== assignedPolicy.default_mode,
      schedule: draftSchedule !== Number(assignedPolicy.settings.schedule_minutes ?? 60),
      description: draftDescription !== assignedPolicy.description,
      controls: [...controlIds].filter(controlId => (assignedPolicy.control_modes[controlId] ?? null) !== (controlModes[controlId] ?? null)).map(controlId => {
        const catalogControl = data?.controls.find(control => control.control_id === controlId)
        return {
          controlId,
          title: catalogControl?.title ?? controlId,
          from: assignedPolicy.control_modes[controlId] ?? `Inherit ${assignedPolicy.default_mode}`,
          to: controlModes[controlId] ?? `Inherit ${draftDefaultMode}`,
        }
      }),
    }
  }, [assignedPolicy, controlModes, data?.controls, draftDefaultMode, draftDescription, draftSchedule])
  const hasPolicyChanges = policyChanges.defaultMode || policyChanges.schedule || policyChanges.description || policyChanges.controls.length > 0
  const policyChangeCount = Number(policyChanges.defaultMode) + Number(policyChanges.schedule) + Number(policyChanges.description) + policyChanges.controls.length
  const categories = useMemo(() => {
    const grouped = new Map<string, ControlCatalogItem[]>()
    for (const control of data?.controls ?? []) {
      const current = grouped.get(control.category) ?? []
      current.push(control)
      grouped.set(control.category, current)
    }
    return [...grouped.entries()]
  }, [data?.controls])

  useEffect(() => {
    if (!assignedPolicy) return
    setControlModes({ ...assignedPolicy.control_modes })
    setDraftDescription(assignedPolicy.description)
    setDraftDefaultMode(assignedPolicy.default_mode)
    setDraftSchedule(Number(assignedPolicy.settings.schedule_minutes ?? 60))
    setSelectedCategory('overview')
    setPolicyStage('configure')
  }, [assignedPolicy])

  useEffect(() => {
    const timer = window.setInterval(() => void refresh(), 30_000)
    return () => window.clearInterval(timer)
  }, [refresh])

  useEffect(() => {
    setSelectedAgents(new Set())
    setConfirmBulkRevoke(false)
  }, [selectedGroupId])

  useEffect(() => {
    if (!assignedPolicy) {
      setPolicyVersions([])
      return
    }
    let active = true
    setHistoryError('')
    api.agentPolicyVersions(assignedPolicy.id)
      .then(versions => { if (active) setPolicyVersions(versions) })
      .catch(caught => { if (active) setHistoryError(caught instanceof Error ? caught.message : 'Unable to load policy history') })
    return () => { active = false }
  }, [assignedPolicy])

  async function submit(action: () => Promise<unknown>, close?: () => void) {
    setSaving(true)
    setFormError('')
    try {
      await action()
      close?.()
      await reload()
    } catch (caught) {
      setFormError(caught instanceof Error ? caught.message : 'Unable to save changes')
    } finally {
      setSaving(false)
    }
  }

  function selectGroup(groupId: string) {
    setSelectedGroupId(groupId)
    setActiveTab('hosts')
    setSearch('')
    setFormError('')
  }

  function createGroup(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const values = new FormData(event.currentTarget)
    void submit(() => api.createAgentGroup({
      name: String(values.get('name')),
      description: String(values.get('description')),
      policy_id: String(values.get('policy_id')),
    }), () => setShowGroup(false))
  }

  function createEnrollment(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const values = new FormData(event.currentTarget)
    void submit(async () => {
      const maxUsesText = String(values.get('max_uses') ?? '').trim()
      const created = await api.createAgentEnrollmentToken({
        name: String(values.get('name')),
        group_id: String(values.get('group_id')),
        expires_at: new Date(Date.now() + Number(values.get('hours')) * 3600000).toISOString(),
        token_type: enrollmentType,
        max_uses: enrollmentType === 'reusable' && maxUsesText ? Number(maxUsesText) : null,
      })
      setToken(created.token)
      setEnrollmentTrust(created.platform_trust)
      setCreatedTokenType(created.token_type)
      setCreatedTokenMaxUses(created.max_uses)
    })
  }

  function createGroupPolicy(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!selectedGroup) return
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
    if (!selectedGroup) return
    const values = new FormData(event.currentTarget)
    void submit(() => api.updateAgentGroup(selectedGroup.id, {
      name: selectedGroup.name,
      description: selectedGroup.description,
      policy_id: String(values.get('policy_id')),
    }))
  }

  function clonePolicyForGroup() {
    if (!selectedGroup || !assignedPolicy) return
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
    if (!assignedPolicy || assignedPolicy.assigned_groups > 1 || !hasPolicyChanges) return
    void submit(() => api.updateAgentPolicy(assignedPolicy.id, {
      description: draftDescription,
      default_mode: draftDefaultMode,
      control_modes: controlModes,
      settings: { ...assignedPolicy.settings, schedule_minutes: draftSchedule, profile: String(assignedPolicy.settings.profile ?? 'level2_server') },
    }), () => setPolicyStage('configure'))
  }

  if (loading) return <LoadingState variant="settings" />
  if (error || !data) return <ErrorState message={error ?? 'Unable to load agents'} retry={reload} />

  const scopedAgents = data.agents.filter(agent => selectedGroupId === 'all' || agent.group_id === selectedGroupId)
  const visibleAgents = scopedAgents.filter(agent => statusFilter === 'all' || agentStatus(agent) === statusFilter)
  const activeCount = scopedAgents.filter(agent => !agent.revoked_at).length
  const activeReusableToken = data.enrollmentTokens.find(item => item.token_type === 'reusable' && !item.revoked_at && new Date(item.expires_at).getTime() > Date.now() && (item.max_uses === null || item.use_count < item.max_uses))
  const categoryControls = selectedCategory === 'overview' ? [] : categories.find(([category]) => category === selectedCategory)?.[1] ?? []

  return <div className="page-reveal">
    <PageHeader
      eyebrow="Managed Linux fleet"
      title="Agents"
      detail="Monitor agent connectivity, review accepted report freshness, and manage group-specific policy and deployment."
      action={<button className="button-primary" onClick={() => { setActiveTab('deployment'); setToken(''); setEnrollmentTrust(null); setEnrollmentType('one_time') }}><Key size={16} /> Deploy agent</button>}
    />
    {formError && <div className="mb-5 rounded-xl border border-rose-900/40 bg-rose-950/10 px-4 py-3 text-xs text-rose-700">{formError}</div>}
    {showDownloads && <AgentDownloadPanel packages={data.packages} platformUrl={data.connectivity.public_url} platformTrust={enrollmentTrust ?? data.connectivity.platform_trust} enrollmentToken={token || undefined} close={() => setShowDownloads(false)} />}

    <section className="panel overflow-hidden">
      <div className="grid min-w-0 lg:grid-cols-[260px_minmax(0,1fr)]">
        <AgentGroupRail
          groups={data.groups}
          agents={data.agents}
          selectedGroupId={selectedGroupId}
          selectGroup={selectGroup}
          showCreate={showGroup}
          setShowCreate={setShowGroup}
          createGroup={createGroup}
          policies={data.policies}
          saving={saving}
        />

        <div className="min-w-0">
          <AgentWorkspaceHeader group={selectedGroup} activeCount={activeCount} activeTab={activeTab} onTabChange={setActiveTab} />

          {activeTab === 'hosts' && <div>
            {selectedAgents.size > 0 && <div className="flex flex-col gap-3 border-b border-[#b8c5ba] bg-[#edf1eb] px-5 py-4 sm:px-7 xl:flex-row xl:items-center">
              <strong className="mr-auto text-xs text-[#4f6f5c]">{selectedAgents.size} selected</strong>
              <button className="button-secondary min-h-9" disabled={saving} onClick={() => void submit(() => api.runAgentAudits([...selectedAgents])).then(() => setSelectedAgents(new Set()))}><Play size={14} /> Run audit now</button>
              <div className="flex gap-2"><select className="select-input min-h-9" aria-label="Bulk destination group" value={bulkGroupId} onChange={event => setBulkGroupId(event.target.value)}><option value="">Move to group…</option>{data.groups.map(group => <option key={group.id} value={group.id}>{group.name}</option>)}</select><button className="button-secondary min-h-9" disabled={saving || !bulkGroupId} onClick={() => void submit(() => api.bulkAssignAgentGroup([...selectedAgents], bulkGroupId)).then(() => { setSelectedAgents(new Set()); setBulkGroupId('') })}>Apply</button></div>
              <Button variant="danger" disabled={saving} onClick={() => setConfirmBulkRevoke(true)}>Revoke selected</Button>
            </div>}
            <AgentFleetTable agents={visibleAgents} groups={data.groups} packageVersion={data.packages[0]?.version} submit={action => submit(action)} selected={selectedAgents} setSelected={setSelectedAgents} search={search} setSearch={setSearch} statusFilter={statusFilter} setStatusFilter={setStatusFilter} />
          </div>}

          {activeTab === 'deployment' && <div>
            <div className="border-b border-stone-200 px-5 py-5 sm:px-7">
              <p className="section-label">Agent deployment</p>
              <h3 className="mt-2 text-base font-semibold text-stone-800">Enroll Linux hosts</h3>
              <p className="mt-2 max-w-2xl text-xs leading-5 text-stone-500">Use a short-lived token for one host or a controlled reusable tenant token for automated fleet enrollment. Every host enters the selected group and verifies the pinned platform identity.</p>
            </div>
            <div className="grid min-w-0 lg:grid-cols-[minmax(0,1fr)_minmax(320px,.8fr)]">
              <section className="min-w-0 border-b border-stone-200 px-5 py-6 sm:px-7 lg:border-b-0 lg:border-r">
                <div className="flex items-start justify-between gap-4">
                  <div><p className="section-label">Connection destination</p><p className="mt-3 text-sm font-medium text-stone-800">Dedicated agent gateway</p><code className="mt-2 block break-all text-[11px] text-stone-500">{data.connectivity.public_url}</code></div>
                  <span className="status-pill status-pill-online">Identity Pinned</span>
                </div>
                <div className="mt-6 grid gap-4 border-t border-stone-200 pt-5 sm:grid-cols-2">
                  <div><span className="detail-label">Current release</span><strong className="mt-2 block text-sm font-semibold text-stone-800">{data.packages[0]?.version ?? 'Unavailable'}</strong><span className="table-subtitle">{data.packages.length} package formats</span></div>
                  <div><span className="detail-label">Operating mode</span><strong className="mt-2 block text-sm font-semibold text-stone-800">Audit only</strong><span className="table-subtitle">Host configuration is not changed</span></div>
                </div>
                <div className="mt-4 border-t border-stone-200 pt-4"><span className="detail-label">Platform identity fingerprint</span><code className="mt-2 block break-all text-[10px] text-stone-500">SHA256:{data.connectivity.platform_trust.fingerprint}</code></div>
                <div className="mt-5 border-t border-stone-200 pt-5">
                  <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
                    <div className="min-w-0">
                      <span className="detail-label">Signing Key Rotation</span>
                      {data.connectivity.key_rotation ? <>
                        <strong className="mt-2 block text-sm font-semibold text-stone-800">{data.connectivity.key_rotation.status === 'ready' ? 'Ready To Activate' : 'Waiting For Agent Acknowledgement'}</strong>
                        <p className="mt-1 text-xs leading-5 text-stone-500">{data.connectivity.key_rotation.acknowledged_agents} of {data.connectivity.key_rotation.eligible_agents} supported agents acknowledged version {data.connectivity.key_rotation.next_key.key_version}. {data.connectivity.key_rotation.blocking_agents > 0 ? `${data.connectivity.key_rotation.blocking_agents} agent(s) still block activation.` : 'Every managed agent can verify the new identity.'}</p>
                        <code className="mt-3 block break-all text-[10px] text-stone-500">Next SHA256:{data.connectivity.key_rotation.next_key.fingerprint}</code>
                      </> : <>
                        <strong className="mt-2 block text-sm font-semibold text-stone-800">Version {data.connectivity.platform_trust.key_version} Active</strong>
                        <p className="mt-1 text-xs leading-5 text-stone-500">Stage a replacement without interrupting agents. Activation remains locked until every active agent acknowledges it.</p>
                      </>}
                    </div>
                    {data.connectivity.key_rotation ? <div className="flex shrink-0 flex-wrap gap-2">
                      <Button disabled={saving} onClick={() => setRotationDecision('abort')}>Abort</Button>
                      <Button variant="primary" disabled={saving || data.connectivity.key_rotation.blocking_agents > 0} onClick={() => setRotationDecision('activate')}>Activate</Button>
                    </div> : <Button className="shrink-0" disabled={saving} onClick={() => void submit(() => api.stagePlatformCommandKeyRotation())}>Stage New Key</Button>}
                  </div>
                </div>
                <Button className="mt-6" disabled={!data.packages.length} onClick={() => setShowDownloads(true)}><DownloadSimple size={15} /> View packages and commands</Button>
              </section>

              <section className="min-w-0 px-5 py-6 sm:px-7">
                <p className="section-label">Enrollment credential</p>
                {token ? <div className="mt-4">
                  <p className="text-xs leading-5 text-stone-500">Copy this token now; it will not be shown again. {createdTokenType === 'one_time' ? 'It becomes invalid after one successful enrollment.' : `It can enroll multiple hosts until expiry${createdTokenMaxUses ? ` or ${createdTokenMaxUses} successful uses` : ''}. Store it in your deployment secret manager.`}</p>
                  <code className="mt-4 block min-w-0 overflow-x-auto rounded-lg border border-stone-200 bg-[#f7f3eb] px-4 py-3 text-xs text-[#4f6f5c]">{token}</code>
                  <div className="mt-4 flex flex-wrap gap-2"><Button onClick={() => void navigator.clipboard.writeText(token)}><Copy size={15} /> Copy token</Button><Button variant="primary" onClick={() => setShowDownloads(true)}><DownloadSimple size={15} /> Continue to installation</Button></div>
                </div> : <form className="mt-4 grid gap-4" onSubmit={createEnrollment}>
                  {activeReusableToken && <div className="rounded-xl border border-[#b8c5ba] bg-[#edf1eb] p-4 text-xs leading-5 text-stone-600"><div className="flex min-w-0 items-start justify-between gap-4"><div className="min-w-0"><strong className="block truncate font-medium text-stone-800">{activeReusableToken.name}</strong><span className="mt-1 block">Reusable tenant token · {activeReusableToken.group_name}</span><span className="mt-1 block">{activeReusableToken.use_count}{activeReusableToken.max_uses === null ? ' uses' : ` of ${activeReusableToken.max_uses} uses`} · Expires {formatDateTime(activeReusableToken.expires_at)}</span></div><Button type="button" disabled={saving} onClick={() => void submit(() => api.revokeAgentEnrollmentToken(activeReusableToken.id))}><Prohibit size={14} /> Revoke</Button></div></div>}
                  <label className="form-field">Credential type<select name="token_type" className="select-input w-full" value={enrollmentType} onChange={event => setEnrollmentType(event.target.value as 'one_time' | 'reusable')}><option value="one_time">One-time token</option><option value="reusable">Reusable tenant token</option></select><small>{enrollmentType === 'one_time' ? 'Best for manual enrollment of one host.' : 'Best for automated provisioning. Only one reusable token can be active per tenant.'}</small></label>
                  <label className="form-field">Token name<input name="name" required placeholder="Production enrollment" /></label>
                  <label className="form-field">Destination group<select name="group_id" required className="select-input w-full" defaultValue={selectedGroup?.id ?? data.groups[0]?.id}>{data.groups.map(group => <option key={group.id} value={group.id}>{group.name}</option>)}</select></label>
                  <label className="form-field">Expires after<select name="hours" className="select-input w-full" defaultValue={enrollmentType === 'one_time' ? '24' : '2160'} key={enrollmentType}>{enrollmentType === 'one_time' ? <><option value="1">1 hour</option><option value="24">24 hours</option><option value="168">7 days</option></> : <><option value="720">30 days</option><option value="2160">90 days</option><option value="8760">365 days</option></>}</select></label>
                  {enrollmentType === 'reusable' && <label className="form-field">Maximum enrollments <input name="max_uses" type="number" min="2" max="100000" placeholder="Unlimited" /><small>Leave blank for unlimited use until expiration.</small></label>}
                  <Button variant="primary" disabled={saving || !data.groups.length || (enrollmentType === 'reusable' && !!activeReusableToken)}>{saving ? 'Creating token' : enrollmentType === 'reusable' ? 'Create reusable token' : 'Create one-time token'}</Button>
                </form>}
              </section>
            </div>
          </div>}

          {activeTab === 'policy' && selectedGroup && assignedPolicy && <div className="min-h-[570px] min-w-0">
            {policyStage === 'configure' && <div className="flex flex-col gap-3 border-b border-stone-200 bg-[#f7f3eb] px-5 py-4 sm:flex-row sm:items-center sm:justify-between sm:px-7">
              <div><p className="text-xs font-semibold text-stone-800">Policy workspace</p><p className="mt-1 text-[11px] text-stone-600">Choose the policy overview or one control category.</p></div>
              <label className="flex min-w-0 items-center gap-3 text-xs font-medium text-stone-600"><SlidersHorizontal size={15} /><span className="sr-only">Policy section</span><select className="select-input min-h-9 w-full min-w-52 sm:w-auto" aria-label="Policy section" value={selectedCategory} onChange={(event) => setSelectedCategory(event.target.value)}><option value="overview">Overview</option>{categories.map(([category, controls]) => <option key={category} value={category}>{category.replaceAll('_', ' ')} · {controls.length}</option>)}</select></label>
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
                      <select name="policy_id" className="select-input w-full" defaultValue={assignedPolicy.id}>{data.policies.map(policy => <option key={policy.id} value={policy.id}>{policy.name} · v{policy.version}</option>)}</select>
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
          </div>}
        </div>
      </div>
    </section>
    <Dialog
      open={rotationDecision !== null}
      onOpenChange={(open) => { if (!open && !saving) setRotationDecision(null) }}
      eyebrow="Platform Trust"
      title={rotationDecision === 'activate' ? 'Activate The New Signing Key?' : 'Abort This Key Rotation?'}
      description={rotationDecision === 'activate' ? 'The platform will sign future agent control responses with the acknowledged key. Enrollment tokens tied to the previous identity will be revoked.' : 'Agents will keep the current signing key. Any staged acknowledgements will be cleared safely.'}
    >
      {rotationDecision === 'activate' && <div className="rounded-lg border border-amber-900/30 bg-amber-950/10 px-4 py-3 text-xs leading-5 text-amber-900">Create a new enrollment token after activation. Existing hosts remain connected because they acknowledged the replacement key before this action became available.</div>}
      <div className="mt-6 flex justify-end gap-3"><Button disabled={saving} onClick={() => setRotationDecision(null)}>Cancel</Button><Button variant={rotationDecision === 'activate' ? 'primary' : 'danger'} disabled={saving} onClick={() => void submit(() => rotationDecision === 'activate' ? api.activatePlatformCommandKeyRotation() : api.abortPlatformCommandKeyRotation()).then(() => setRotationDecision(null))}>{saving ? 'Updating Trust' : rotationDecision === 'activate' ? 'Activate Key' : 'Abort Rotation'}</Button></div>
    </Dialog>
    <Dialog
      open={confirmBulkRevoke}
      onOpenChange={(open) => { if (!open && !saving) setConfirmBulkRevoke(false) }}
      eyebrow="Fleet trust"
      title={`Revoke ${selectedAgents.size} selected agents?`}
      description="Every selected agent identity will be rejected immediately. Existing host records and reports remain available, but these installations cannot reconnect or submit new evidence."
    >
      <div className="rounded-lg border border-rose-900/40 bg-rose-950/10 px-4 py-3 text-xs leading-5 text-rose-700">Restoring connectivity requires reinstalling or re-enrolling every affected host with a new one-time token.</div>
      <div className="mt-6 flex justify-end gap-3"><Button onClick={() => setConfirmBulkRevoke(false)} disabled={saving}>Cancel</Button><Button variant="danger" disabled={saving || selectedAgents.size === 0} onClick={() => void submit(() => api.bulkRevokeAgents([...selectedAgents])).then(() => { setSelectedAgents(new Set()); setConfirmBulkRevoke(false) })}>{saving ? 'Revoking agents' : 'Revoke agents'}</Button></div>
    </Dialog>
  </div>
}
