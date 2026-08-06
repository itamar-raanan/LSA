import {
  CheckCircle,
  Copy,
  DesktopTower,
  DownloadSimple,
  FolderSimple,
  Key,
  MagnifyingGlass,
  Play,
  Plus,
  Prohibit,
  ShieldCheck,
  SlidersHorizontal,
  UsersThree,
} from '@phosphor-icons/react'
import { FormEvent, useEffect, useMemo, useState } from 'react'
import { api } from '../../api/client'
import { AgentDownloadPanel } from '../../components/AgentDownloadPanel'
import { PageHeader } from '../../components/PageHeader'
import { EmptyState, ErrorState, LoadingState } from '../../components/StatePanel'
import { Button } from '../../components/ui/Button'
import { Dialog } from '../../components/ui/Dialog'
import { useApi } from '../../hooks/useApi'
import type { AgentGroup, AgentPolicy, AgentPolicyVersion, ControlCatalogItem, LinuxAgent, PolicyMode } from '../../types'

const modes: PolicyMode[] = ['audit', 'manual', 'remediate', 'disabled']
type WorkspaceTab = 'hosts' | 'policy' | 'deployment'
type AgentStatus = 'online' | 'stale' | 'offline' | 'never' | 'revoked'
type ReportStatus = 'fresh' | 'stale' | 'never'

function agentStatus(agent: LinuxAgent): AgentStatus {
  if (agent.revoked_at) return 'revoked'
  if (!agent.last_seen_at) return 'never'
  const age = Date.now() - new Date(agent.last_seen_at).getTime()
  if (age <= 5 * 60_000) return 'online'
  if (age <= 24 * 60 * 60_000) return 'stale'
  return 'offline'
}

function reportStatus(agent: LinuxAgent): ReportStatus {
  if (!agent.last_scan_at) return 'never'
  return Date.now() - new Date(agent.last_scan_at).getTime() <= 24 * 60 * 60_000 ? 'fresh' : 'stale'
}

function AgentTable({ agents, groups, packageVersion, submit, selected, toggle, toggleAll }: {
  agents: LinuxAgent[]
  groups: AgentGroup[]
  packageVersion?: string
  submit: (action: () => Promise<unknown>) => Promise<void>
  selected: Set<string>
  toggle: (id: string) => void
  toggleAll: () => void
}) {
  const [revoking, setRevoking] = useState<LinuxAgent | null>(null)
  if (!agents.length) {
    return <EmptyState title="No agents in this scope" detail="Create an enrollment token for this group, install the Linux package, and the host will appear here after enrollment." />
  }

  return <>
  <div className="overflow-x-auto">
    <table className="data-table min-w-[920px]">
      <thead><tr><th><input type="checkbox" aria-label="Select all visible agents" checked={agents.length > 0 && agents.every(agent => selected.has(agent.id))} onChange={toggleAll} /></th><th>Host</th><th>Connection</th><th>Report freshness</th><th>Group</th><th>Policy</th><th>Last heartbeat</th><th /></tr></thead>
      <tbody>{agents.map(agent => <tr key={agent.id}>
        <td><input type="checkbox" aria-label={`Select ${agent.hostname}`} checked={selected.has(agent.id)} disabled={!!agent.revoked_at} onChange={() => toggle(agent.id)} /></td>
        <td>
          <span className="font-medium text-stone-200">{agent.hostname}</span>
          <span className="table-subtitle">agent {agent.agent_version} · {packageVersion && agent.agent_version !== packageVersion ? `upgrade ${packageVersion} available` : agent.capabilities.join(', ') || 'no capabilities'}</span>
        </td>
        <td><span className={`status-pill status-pill-${agentStatus(agent)}`}>{agentStatus(agent)}</span><span className="table-subtitle">Outbound agent heartbeat</span></td>
        <td><span className={`status-pill status-pill-${reportStatus(agent) === 'fresh' ? 'online' : reportStatus(agent)}`}>{reportStatus(agent)}</span><span className="table-subtitle">{agent.last_scan_at ? new Date(agent.last_scan_at).toLocaleString() : 'No accepted report'}</span></td>
        <td>
          <select
            aria-label={`Group for ${agent.hostname}`}
            className="select-input min-h-9"
            value={agent.group_id}
            disabled={!!agent.revoked_at}
            onChange={event => void submit(() => api.assignAgentGroup(agent.id, event.target.value))}
          >{groups.map(group => <option key={group.id} value={group.id}>{group.name}</option>)}</select>
        </td>
        <td>{agent.policy_name}<span className="table-subtitle">Expected v{agent.policy_version} · reported v{agent.last_policy_version ?? '—'}</span></td>
        <td>{agent.last_seen_at ? new Date(agent.last_seen_at).toLocaleString() : 'Never'}<span className="table-subtitle">{agent.latest_task_status ? `Latest audit ${agent.latest_task_status}` : 'No requested audit'}</span></td>
        <td><button className="icon-button ml-auto" aria-label={`Revoke ${agent.hostname}`} title="Revoke agent" disabled={!!agent.revoked_at} onClick={() => setRevoking(agent)}><Prohibit size={15} /></button></td>
      </tr>)}</tbody>
    </table>
  </div>
  <Dialog
    open={revoking !== null}
    onOpenChange={(open) => { if (!open) setRevoking(null) }}
    eyebrow="Agent trust"
    title={`Revoke ${revoking?.hostname ?? 'agent'}?`}
    description="The agent identity will be rejected immediately. Existing reports remain available, but this installation cannot reconnect or submit new evidence."
  >
    <div className="rounded-lg border border-rose-900/40 bg-rose-950/10 px-4 py-3 text-xs leading-5 text-rose-300">Re-enrolling this host later creates a new agent identity and requires a new one-time enrollment token.</div>
    <div className="mt-6 flex justify-end gap-3"><Button onClick={() => setRevoking(null)}>Cancel</Button><Button variant="danger" disabled={!revoking} onClick={() => { if (revoking) void submit(() => api.revokeAgent(revoking.id)).finally(() => setRevoking(null)) }}>Revoke agent</Button></div>
  </Dialog>
  </>
}

function GroupRail({ groups, agents, selectedGroupId, selectGroup, showCreate, setShowCreate, createGroup, policies, saving }: {
  groups: AgentGroup[]
  agents: LinuxAgent[]
  selectedGroupId: string
  selectGroup: (groupId: string) => void
  showCreate: boolean
  setShowCreate: (value: boolean) => void
  createGroup: (event: FormEvent<HTMLFormElement>) => void
  policies: AgentPolicy[]
  saving: boolean
}) {
  const activeAgents = agents.filter(agent => !agent.revoked_at)
  return <aside className="min-w-0 overflow-hidden border-b border-stone-800 bg-[#f7f3eb] lg:min-h-[690px] lg:border-b-0 lg:border-r" aria-label="Agent groups">
    <div className="flex items-center justify-between border-b border-stone-800 px-4 py-4">
      <div><p className="section-label">Fleet scope</p><p className="mt-1 text-xs text-stone-500">{groups.length} groups</p></div>
      <button className="icon-button" onClick={() => setShowCreate(!showCreate)} aria-label="Create group"><Plus size={15} /></button>
    </div>

    {showCreate && <form className="grid min-w-0 gap-3 border-b border-stone-800 bg-[#f7f3eb] p-4" onSubmit={createGroup}>
      <label className="form-field">Group name<input name="name" required placeholder="Database servers" /></label>
      <label className="form-field">Description<input name="description" placeholder="Production database fleet" /></label>
      <label className="form-field">Initial policy<select name="policy_id" className="select-input w-full" required>{policies.map(policy => <option key={policy.id} value={policy.id}>{policy.name}</option>)}</select></label>
      <button className="button-primary min-h-9" disabled={saving || !policies.length}>Create group</button>
    </form>}

    <nav className="flex gap-2 overflow-x-auto p-3 lg:block lg:space-y-1" aria-label="Fleet groups">
      <button className={`group-scope-item min-w-48 lg:min-w-0 ${selectedGroupId === 'all' ? 'group-scope-item-active' : ''}`} onClick={() => selectGroup('all')}>
        <span className="group-scope-icon"><UsersThree size={17} /></span>
        <span className="min-w-0 flex-1 text-left"><strong>All Agents</strong><small>Every Managed Linux Agent</small></span>
        <span className="font-mono text-[10px] text-stone-500">{activeAgents.length}</span>
      </button>
      <div className="hidden px-3 pb-2 pt-5 lg:block"><span className="section-label">Groups</span></div>
      {groups.map(group => {
        const count = activeAgents.filter(agent => agent.group_id === group.id).length
        return <button key={group.id} className={`group-scope-item min-w-48 lg:min-w-0 ${selectedGroupId === group.id ? 'group-scope-item-active' : ''}`} onClick={() => selectGroup(group.id)}>
          <span className="group-scope-icon"><FolderSimple size={17} /></span>
          <span className="min-w-0 flex-1 text-left"><strong>{group.name}</strong><small>{group.policy_name} · v{group.policy_version}</small></span>
          <span className="font-mono text-[10px] text-stone-500">{count}</span>
        </button>
      })}
    </nav>
  </aside>
}

export function AgentsSettingsPage() {
  const { data, error, loading, reload, refresh } = useApi(async () => {
    const [agents, groups, policies, controls, enrollmentTokens, packages, connectivity] = await Promise.all([
      api.agents(), api.agentGroups(), api.agentPolicies(), api.controlCatalog(), api.agentEnrollmentTokens(), api.agentPackages(), api.agentConnectivity(),
    ])
    return { agents, groups, policies, controls, enrollmentTokens, packages, connectivity }
  }, [])
  const [selectedGroupId, setSelectedGroupId] = useState('all')
  const [activeTab, setActiveTab] = useState<WorkspaceTab>('hosts')
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
  const [formError, setFormError] = useState('')
  const [saving, setSaving] = useState(false)
  const [controlModes, setControlModes] = useState<Record<string, PolicyMode>>({})
  const [selectedCategory, setSelectedCategory] = useState('overview')
  const [draftDescription, setDraftDescription] = useState('')
  const [draftDefaultMode, setDraftDefaultMode] = useState<PolicyMode>('audit')
  const [draftSchedule, setDraftSchedule] = useState(60)

  const selectedGroup = data?.groups.find(group => group.id === selectedGroupId) ?? null

  const assignedPolicy = selectedGroup ? data?.policies.find(policy => policy.id === selectedGroup.policy_id) ?? null : null
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
      const created = await api.createAgentEnrollmentToken({
        name: String(values.get('name')),
        group_id: String(values.get('group_id')),
        expires_at: new Date(Date.now() + Number(values.get('hours')) * 3600000).toISOString(),
      })
      setToken(created.token)
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
    if (!assignedPolicy || assignedPolicy.assigned_groups > 1) return
    void submit(() => api.updateAgentPolicy(assignedPolicy.id, {
      description: draftDescription,
      default_mode: draftDefaultMode,
      control_modes: controlModes,
      settings: { ...assignedPolicy.settings, schedule_minutes: draftSchedule, profile: String(assignedPolicy.settings.profile ?? 'level2_server') },
    }))
  }

  if (loading) return <LoadingState />
  if (error || !data) return <ErrorState message={error ?? 'Unable to load agents'} retry={reload} />

  const scopedAgents = data.agents.filter(agent => selectedGroupId === 'all' || agent.group_id === selectedGroupId)
  const visibleAgents = scopedAgents.filter(agent => agent.hostname.toLowerCase().includes(search.trim().toLowerCase()) && (statusFilter === 'all' || agentStatus(agent) === statusFilter))
  const activeCount = scopedAgents.filter(agent => !agent.revoked_at).length
  const categoryControls = selectedCategory === 'overview' ? [] : categories.find(([category]) => category === selectedCategory)?.[1] ?? []

  return <div className="page-reveal">
    <PageHeader
      eyebrow="Managed Linux fleet"
      title="Agents"
      detail="Monitor agent connectivity, review accepted report freshness, and manage group-specific policy and deployment."
      action={<button className="button-primary" onClick={() => { setActiveTab('deployment'); setToken('') }}><Key size={16} /> Deploy agent</button>}
    />
    {formError && <div className="mb-5 rounded-xl border border-rose-900/40 bg-rose-950/10 px-4 py-3 text-xs text-rose-300">{formError}</div>}
    {showDownloads && <AgentDownloadPanel packages={data.packages} platformUrl={data.connectivity.public_url} enrollmentToken={token || undefined} close={() => setShowDownloads(false)} />}

    <section className="panel overflow-hidden">
      <div className="grid min-w-0 lg:grid-cols-[260px_minmax(0,1fr)]">
        <GroupRail
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
          <header className="border-b border-stone-800 px-5 pt-5 sm:px-7 sm:pt-6">
            <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <div className="flex items-center gap-2 text-stone-500">{selectedGroup ? <FolderSimple size={16} /> : <UsersThree size={16} />}<span className="section-label">{selectedGroup ? 'Agent group' : 'Fleet inventory'}</span></div>
                <h2 className="mt-2 text-xl font-semibold tracking-[-0.025em] text-stone-100">{selectedGroup?.name ?? 'All Agents'}</h2>
                <p className="mt-1 text-xs leading-5 text-stone-500">{selectedGroup?.description || (selectedGroup ? `${selectedGroup.policy_name} is applied to this group.` : 'Every agent across all policy groups.')}</p>
              </div>
              <div className="flex items-center gap-6 border-l border-stone-800 pl-5">
                <div><strong className="block font-mono text-lg font-medium text-stone-200">{activeCount}</strong><span className="text-[10px] text-stone-600">active hosts</span></div>
                {selectedGroup && <div><strong className="block font-mono text-lg font-medium text-stone-200">v{selectedGroup.policy_version}</strong><span className="text-[10px] text-stone-600">policy version</span></div>}
              </div>
            </div>
            <nav className="mt-6 flex gap-6" aria-label="Group workspace tabs">
              <button className={`workspace-tab ${activeTab === 'hosts' ? 'workspace-tab-active' : ''}`} onClick={() => setActiveTab('hosts')}><DesktopTower size={15} /> Hosts</button>
              {selectedGroup && <button className={`workspace-tab ${activeTab === 'policy' ? 'workspace-tab-active' : ''}`} onClick={() => setActiveTab('policy')}><SlidersHorizontal size={15} /> Policy</button>}
              <button className={`workspace-tab ${activeTab === 'deployment' ? 'workspace-tab-active' : ''}`} onClick={() => setActiveTab('deployment')}><DownloadSimple size={15} /> Deployment</button>
            </nav>
          </header>

          {activeTab === 'hosts' && <div>
            <div className="flex flex-col gap-3 border-b border-stone-800 px-5 py-4 sm:flex-row sm:items-center sm:justify-between sm:px-7">
              <div className="relative w-full max-w-md"><MagnifyingGlass size={15} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-stone-600" /><input className="search-input" value={search} onChange={event => setSearch(event.target.value)} placeholder="Search hostname" aria-label="Search agents" /></div>
              <div className="flex items-center gap-3"><select className="select-input min-h-9" aria-label="Filter agent status" value={statusFilter} onChange={event => setStatusFilter(event.target.value as 'all' | AgentStatus)}><option value="all">All statuses</option><option value="online">Online</option><option value="stale">Stale</option><option value="offline">Offline</option><option value="never">Never connected</option><option value="revoked">Revoked</option></select><span className="font-mono text-[10px] text-stone-600">{visibleAgents.length} of {scopedAgents.length} hosts</span></div>
            </div>
            {selectedAgents.size > 0 && <div className="flex flex-col gap-3 border-b border-[#b8c5ba] bg-[#edf1eb] px-5 py-4 sm:px-7 xl:flex-row xl:items-center">
              <strong className="mr-auto text-xs text-[#4f6f5c]">{selectedAgents.size} selected</strong>
              <button className="button-secondary min-h-9" disabled={saving} onClick={() => void submit(() => api.runAgentAudits([...selectedAgents])).then(() => setSelectedAgents(new Set()))}><Play size={14} /> Run audit now</button>
              <div className="flex gap-2"><select className="select-input min-h-9" aria-label="Bulk destination group" value={bulkGroupId} onChange={event => setBulkGroupId(event.target.value)}><option value="">Move to group…</option>{data.groups.map(group => <option key={group.id} value={group.id}>{group.name}</option>)}</select><button className="button-secondary min-h-9" disabled={saving || !bulkGroupId} onClick={() => void submit(() => api.bulkAssignAgentGroup([...selectedAgents], bulkGroupId)).then(() => { setSelectedAgents(new Set()); setBulkGroupId('') })}>Apply</button></div>
              <Button variant="danger" disabled={saving} onClick={() => setConfirmBulkRevoke(true)}>Revoke selected</Button>
            </div>}
            <AgentTable agents={visibleAgents} groups={data.groups} packageVersion={data.packages[0]?.version} submit={action => submit(action)} selected={selectedAgents} toggle={id => setSelectedAgents(current => { const next = new Set(current); if (next.has(id)) next.delete(id); else next.add(id); return next })} toggleAll={() => setSelectedAgents(current => { const selectable = visibleAgents.filter(agent => !agent.revoked_at); const allSelected = selectable.length > 0 && selectable.every(agent => current.has(agent.id)); const next = new Set(current); selectable.forEach(agent => allSelected ? next.delete(agent.id) : next.add(agent.id)); return next })} />
          </div>}

          {activeTab === 'deployment' && <div>
            <div className="border-b border-stone-800 px-5 py-5 sm:px-7">
              <p className="section-label">Agent deployment</p>
              <h3 className="mt-2 text-base font-semibold text-stone-100">Enroll Linux hosts</h3>
              <p className="mt-2 max-w-2xl text-xs leading-5 text-stone-500">Create one short-lived token for the destination group, download the signed package, verify its checksum, then run the generated installation command on each host.</p>
            </div>
            <div className="grid min-w-0 lg:grid-cols-[minmax(0,1fr)_minmax(320px,.8fr)]">
              <section className="min-w-0 border-b border-stone-800 px-5 py-6 sm:px-7 lg:border-b-0 lg:border-r">
                <div className="flex items-start justify-between gap-4">
                  <div><p className="section-label">Connection destination</p><p className="mt-3 text-sm font-medium text-stone-200">Dedicated agent gateway</p><code className="mt-2 block break-all text-[11px] text-stone-500">{data.connectivity.public_url}</code></div>
                  <span className="status-pill status-pill-online">HTTPS</span>
                </div>
                <div className="mt-6 grid gap-4 border-t border-stone-800 pt-5 sm:grid-cols-2">
                  <div><span className="detail-label">Current release</span><strong className="mt-2 block text-sm font-semibold text-stone-200">{data.packages[0]?.version ?? 'Unavailable'}</strong><span className="table-subtitle">{data.packages.length} package formats</span></div>
                  <div><span className="detail-label">Operating mode</span><strong className="mt-2 block text-sm font-semibold text-stone-200">Audit only</strong><span className="table-subtitle">Host configuration is not changed</span></div>
                </div>
                <Button className="mt-6" disabled={!data.packages.length} onClick={() => setShowDownloads(true)}><DownloadSimple size={15} /> View packages and commands</Button>
              </section>

              <section className="min-w-0 px-5 py-6 sm:px-7">
                <p className="section-label">One-time enrollment</p>
                {token ? <div className="mt-4">
                  <p className="text-xs leading-5 text-stone-500">Copy this token now. It is displayed once and becomes invalid after the first successful enrollment.</p>
                  <code className="mt-4 block min-w-0 overflow-x-auto rounded-lg border border-stone-800 bg-[#f7f3eb] px-4 py-3 text-xs text-[#4f6f5c]">{token}</code>
                  <div className="mt-4 flex flex-wrap gap-2"><Button onClick={() => void navigator.clipboard.writeText(token)}><Copy size={15} /> Copy token</Button><Button variant="primary" onClick={() => setShowDownloads(true)}><DownloadSimple size={15} /> Continue to installation</Button></div>
                </div> : <form className="mt-4 grid gap-4" onSubmit={createEnrollment}>
                  <label className="form-field">Token name<input name="name" required placeholder="Production enrollment" /></label>
                  <label className="form-field">Destination group<select name="group_id" required className="select-input w-full" defaultValue={selectedGroup?.id ?? data.groups[0]?.id}>{data.groups.map(group => <option key={group.id} value={group.id}>{group.name}</option>)}</select></label>
                  <label className="form-field">Expires after<select name="hours" className="select-input w-full" defaultValue="24"><option value="1">1 hour</option><option value="24">24 hours</option><option value="168">7 days</option></select></label>
                  <Button variant="primary" disabled={saving || !data.groups.length}>{saving ? 'Creating token' : 'Create enrollment token'}</Button>
                </form>}
              </section>
            </div>
          </div>}

          {activeTab === 'policy' && selectedGroup && assignedPolicy && <div className="grid min-h-[570px] min-w-0 md:grid-cols-[210px_minmax(0,1fr)]">
            <nav className="min-w-0 overflow-hidden border-b border-stone-800 bg-[#f7f3eb] p-3 md:border-b-0 md:border-r" aria-label="Policy categories">
              <button className={`policy-category-item ${selectedCategory === 'overview' ? 'policy-category-item-active' : ''}`} onClick={() => setSelectedCategory('overview')}><SlidersHorizontal size={15} /><span>Overview</span></button>
              <div className="px-3 pb-2 pt-5"><span className="section-label">Control categories</span></div>
              <div className="flex gap-1 overflow-x-auto md:block md:space-y-1">{categories.map(([category, controls]) => <button key={category} className={`policy-category-item min-w-44 md:min-w-0 ${selectedCategory === category ? 'policy-category-item-active' : ''}`} onClick={() => setSelectedCategory(category)}><span className="min-w-0 flex-1 truncate text-left capitalize">{category.replaceAll('_', ' ')}</span><span className="font-mono text-[9px] text-stone-600">{controls.length}</span></button>)}</div>
            </nav>

            <div className="min-w-0">
              {selectedCategory === 'overview' ? <div>
                <div className="policy-safety-note flex items-start gap-3 border-b px-5 py-4 text-xs leading-5 sm:px-7">
                  <ShieldCheck size={17} className="mt-0.5 shrink-0" />
                  <span><strong>Audit-Only Safety Lock Is Active.</strong> Remediation modes can be staged here, but this agent release cannot change host configuration.</span>
                </div>
                <div className="border-b border-stone-800 px-5 py-5 sm:px-7">
                  <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
                    <div><p className="section-label">Effective policy</p><h3 className="mt-2 text-base font-semibold text-stone-100">{assignedPolicy.name}</h3><p className="mt-2 max-w-xl text-xs leading-5 text-stone-500">{assignedPolicy.description || 'No policy description.'}</p></div>
                    <span className="settings-state">Version {assignedPolicy.version} · {Object.keys(controlModes).length} Overrides</span>
                  </div>
                </div>

                {assignedPolicy.assigned_groups > 1 && <div className="flex flex-col gap-4 border-b border-amber-900/30 bg-amber-950/10 px-5 py-4 sm:flex-row sm:items-center sm:justify-between sm:px-7">
                  <div><p className="text-xs font-medium text-amber-200">Shared by {assignedPolicy.assigned_groups} groups</p><p className="mt-1 text-[11px] leading-5 text-stone-500">Create a group-owned copy before changing controls, so other groups keep their current policy.</p></div>
                  <button className="button-secondary shrink-0" disabled={saving} onClick={clonePolicyForGroup}><Copy size={14} /> Make group-specific copy</button>
                </div>}

                <div className="grid min-w-0 gap-5 border-b border-stone-800 px-5 py-6 sm:px-7 2xl:grid-cols-[minmax(0,1fr)_260px]">
                  <div className="grid gap-4 sm:grid-cols-2">
                    <label className="form-field">Default mode<select className="select-input w-full" value={draftDefaultMode} disabled={assignedPolicy.assigned_groups > 1} onChange={event => setDraftDefaultMode(event.target.value as PolicyMode)}>{modes.map(mode => <option key={mode}>{mode}</option>)}</select></label>
                    <label className="form-field">Schedule minutes<input type="number" min="5" max="10080" value={draftSchedule} disabled={assignedPolicy.assigned_groups > 1} onChange={event => setDraftSchedule(Number(event.target.value))} /></label>
                    <label className="form-field sm:col-span-2">Description<input value={draftDescription} disabled={assignedPolicy.assigned_groups > 1} onChange={event => setDraftDescription(event.target.value)} /></label>
                  </div>
                  <div className="min-w-0 border-t border-stone-800 pt-5 2xl:border-l 2xl:border-t-0 2xl:pl-5 2xl:pt-0">
                    <p className="section-label">Apply another policy</p>
                    <form key={assignedPolicy.id} className="mt-3 grid gap-3" onSubmit={applyExistingPolicy}>
                      <select name="policy_id" className="select-input w-full" defaultValue={assignedPolicy.id}>{data.policies.map(policy => <option key={policy.id} value={policy.id}>{policy.name} · v{policy.version}</option>)}</select>
                      <button className="button-secondary min-h-9" disabled={saving}>Apply to {selectedGroup.name}</button>
                    </form>
                    <button className="mt-3 text-xs text-[#4f6f5c] transition hover:text-[#4f6f5c]" onClick={() => setShowPolicy(!showPolicy)}>Create a new policy for this group</button>
                  </div>
                </div>

                {showPolicy && <form className="grid gap-4 border-b border-stone-800 bg-[#f7f3eb] px-5 py-5 sm:grid-cols-2 sm:px-7" onSubmit={createGroupPolicy}>
                  <label className="form-field sm:col-span-2">Policy name<input name="name" required placeholder={`${selectedGroup.name} policy`} /></label>
                  <label className="form-field sm:col-span-2">Description<input name="description" placeholder="Policy owned by this group" /></label>
                  <label className="form-field">Default mode<select name="default_mode" className="select-input w-full" defaultValue="audit">{modes.map(mode => <option key={mode}>{mode}</option>)}</select></label>
                  <label className="form-field">Schedule<select name="schedule_minutes" className="select-input w-full" defaultValue="60"><option value="15">15 minutes</option><option value="60">Hourly</option><option value="1440">Daily</option></select></label>
                  <div className="flex justify-end gap-2 sm:col-span-2"><button type="button" className="button-secondary" onClick={() => setShowPolicy(false)}>Cancel</button><button className="button-primary" disabled={saving}>Create and apply</button></div>
                </form>}

                <div className="border-b border-stone-800 px-5 py-5 sm:px-7">
                  <div className="flex items-end justify-between gap-4"><div><p className="section-label">Version history</p><p className="mt-2 text-xs text-stone-500">Every publication is immutable. Restoring publishes a new version from the selected snapshot.</p></div><span className="font-mono text-[10px] text-stone-600">{policyVersions.length} versions</span></div>
                  {historyError ? <p className="mt-4 text-xs text-rose-300">{historyError}</p> : <div className="mt-4 divide-y divide-stone-800 border-y border-stone-800">{policyVersions.map(version => <div key={version.version} className="flex flex-col gap-3 py-3 sm:flex-row sm:items-center">
                    <div className="min-w-0 flex-1"><strong className="text-xs text-stone-300">Version {version.version}{version.version === assignedPolicy.version ? ' · current' : ''}</strong><span className="table-subtitle">{version.default_mode} default · {Object.keys(version.control_modes).length} overrides · {version.created_by_name ?? 'system'} · {new Date(version.created_at).toLocaleString()}</span></div>
                    {version.version !== assignedPolicy.version && <button className="button-secondary min-h-9 shrink-0" disabled={saving || assignedPolicy.assigned_groups > 1} onClick={() => void submit(() => api.restoreAgentPolicy(assignedPolicy.id, version.version))}>Restore as v{assignedPolicy.version + 1}</button>}
                  </div>)}</div>}
                </div>

                <div className="flex items-center justify-between gap-4 px-5 py-5 sm:px-7">
                  <span className="flex items-center gap-2 text-xs text-stone-600"><CheckCircle size={16} /> Saving publishes immutable version {assignedPolicy.version + 1}</span>
                  <button className="button-primary" disabled={saving || assignedPolicy.assigned_groups > 1} onClick={publishPolicy}>{saving ? 'Publishing…' : `Publish version ${assignedPolicy.version + 1}`}</button>
                </div>
              </div> : <div>
                <div className="border-b border-stone-800 px-5 py-5 sm:px-7">
                  <p className="section-label">Policy category</p>
                  <div className="mt-2 flex items-end justify-between gap-4"><div><h3 className="text-base font-semibold capitalize text-stone-100">{selectedCategory.replaceAll('_', ' ')}</h3><p className="mt-1 text-xs text-stone-500">Override individual controls for {selectedGroup.name}, or inherit the policy default.</p></div><span className="font-mono text-[10px] text-stone-600">{categoryControls.length} controls</span></div>
                </div>
                <div>{categoryControls.map(control => <div key={control.control_id} className="grid min-w-0 gap-3 border-b border-stone-800/70 px-5 py-4 sm:px-7 2xl:grid-cols-[155px_minmax(0,1fr)_170px] 2xl:items-center">
                  <code className="text-[10px] text-stone-500">{control.control_id}</code>
                  <span className="text-xs text-stone-300">{control.title}<small className="table-subtitle">{control.module}</small></span>
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
                <div className="sticky bottom-0 flex items-center justify-between gap-4 border-t border-stone-800 bg-[#f7f3eb]/95 px-5 py-4 backdrop-blur sm:px-7">
                  <span className="text-xs text-stone-600">{Object.keys(controlModes).length} explicit overrides across all categories</span>
                  <button className="button-primary" disabled={saving || assignedPolicy.assigned_groups > 1} onClick={publishPolicy}>{saving ? 'Publishing…' : `Publish version ${assignedPolicy.version + 1}`}</button>
                </div>
              </div>}
            </div>
          </div>}
        </div>
      </div>
    </section>
    <Dialog
      open={confirmBulkRevoke}
      onOpenChange={(open) => { if (!open && !saving) setConfirmBulkRevoke(false) }}
      eyebrow="Fleet trust"
      title={`Revoke ${selectedAgents.size} selected agents?`}
      description="Every selected agent identity will be rejected immediately. Existing host records and reports remain available, but these installations cannot reconnect or submit new evidence."
    >
      <div className="rounded-lg border border-rose-900/40 bg-rose-950/10 px-4 py-3 text-xs leading-5 text-rose-300">Restoring connectivity requires reinstalling or re-enrolling every affected host with a new one-time token.</div>
      <div className="mt-6 flex justify-end gap-3"><Button onClick={() => setConfirmBulkRevoke(false)} disabled={saving}>Cancel</Button><Button variant="danger" disabled={saving || selectedAgents.size === 0} onClick={() => void submit(() => api.bulkRevokeAgents([...selectedAgents])).then(() => { setSelectedAgents(new Set()); setConfirmBulkRevoke(false) })}>{saving ? 'Revoking agents' : 'Revoke agents'}</Button></div>
    </Dialog>
  </div>
}
