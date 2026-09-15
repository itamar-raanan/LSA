import { Key, Play } from '@phosphor-icons/react'
import { FormEvent, useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api } from '../../api/client'
import { AgentDetailPanel } from '../../components/agents/AgentDetailPanel'
import { AgentDeploymentWorkspace } from '../../components/agents/AgentDeploymentWorkspace'
import { AgentFleetTable } from '../../components/agents/AgentFleetTable'
import { AgentGroupRail } from '../../components/agents/AgentGroupRail'
import { AgentPolicyWorkspace } from '../../components/agents/AgentPolicyWorkspace'
import { AgentWorkspaceHeader, type AgentWorkspaceTab } from '../../components/agents/AgentWorkspaceHeader'
import { agentStatus, type AgentStatus } from '../../components/agents/agentStatus'
import { PageHeader } from '../../components/PageHeader'
import { ErrorState, LoadingState } from '../../components/StatePanel'
import { Button } from '../../components/ui/Button'
import { Dialog } from '../../components/ui/Dialog'
import { useApi } from '../../hooks/useApi'

export function AgentsSettingsPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const { data, error, loading, reload, refresh } = useApi(async () => {
    const [agents, groups, policies, controls, enrollmentTokens, packages, connectivity, enrollmentRecovery] = await Promise.all([
      api.agents(), api.agentGroups(), api.agentPolicies(), api.controlCatalog(), api.agentEnrollmentTokens(), api.agentPackages(), api.agentConnectivity(), api.agentEnrollmentRecovery(),
    ])
    return { agents, groups, policies, controls, enrollmentTokens, packages, connectivity, enrollmentRecovery }
  }, [])
  const [selectedGroupId, setSelectedGroupId] = useState(searchParams.get('group') ?? 'all')
  const [activeTab, setActiveTab] = useState<AgentWorkspaceTab>((searchParams.get('tab') as AgentWorkspaceTab) ?? 'hosts')
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState<'all' | AgentStatus>('all')
  const [selectedAgents, setSelectedAgents] = useState<Set<string>>(new Set())
  const [bulkGroupId, setBulkGroupId] = useState('')
  const [confirmBulkRevoke, setConfirmBulkRevoke] = useState(false)
  const [showGroup, setShowGroup] = useState(false)
  const [formError, setFormError] = useState('')
  const [notice, setNotice] = useState('')
  const [saving, setSaving] = useState(false)
  const [detailRevoke, setDetailRevoke] = useState(false)

  const selectedGroup = data?.groups.find(group => group.id === selectedGroupId) ?? null
  const assignedPolicy = selectedGroup ? data?.policies.find(policy => policy.id === selectedGroup.policy_id) ?? null : null

  useEffect(() => {
    const timer = window.setInterval(() => void refresh(), 30_000)
    return () => window.clearInterval(timer)
  }, [refresh])

  useEffect(() => {
    setSelectedAgents(new Set())
    setConfirmBulkRevoke(false)
  }, [selectedGroupId])

  async function submit(action: () => Promise<unknown>, close?: () => void, successMessage?: string) {
    setSaving(true)
    setFormError('')
    setNotice('')
    try {
      await action()
      close?.()
      await refresh()
      if (successMessage) setNotice(successMessage)
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
    setSearchParams(groupId === 'all' ? {} : { group: groupId })
  }

  function changeTab(tab: AgentWorkspaceTab) {
    setActiveTab(tab)
    const next = new URLSearchParams(searchParams)
    if (selectedGroupId === 'all') next.delete('group'); else next.set('group', selectedGroupId)
    if (tab === 'hosts') next.delete('tab'); else next.set('tab', tab)
    next.delete('agent')
    setSearchParams(next)
  }

  function openAgent(agentId: string) {
    const next = new URLSearchParams(searchParams)
    next.set('agent', agentId)
    setSearchParams(next)
  }

  function closeAgent() {
    const next = new URLSearchParams(searchParams)
    next.delete('agent')
    setSearchParams(next)
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

  if (loading) return <LoadingState variant="settings" />
  if (error || !data) return <ErrorState message={error ?? 'Unable to load agents'} retry={reload} />

  const scopedAgents = data.agents.filter(agent => selectedGroupId === 'all' || agent.group_id === selectedGroupId)
  const visibleAgents = scopedAgents.filter(agent => statusFilter === 'all' || agentStatus(agent) === statusFilter)
  const activeCount = scopedAgents.filter(agent => !agent.revoked_at).length
  const attentionCount = scopedAgents.filter(agent => agent.operational_state === 'attention').length
  const awaitingCount = scopedAgents.filter(agent => agent.operational_state === 'awaiting_first_contact').length
  const selectedAgent = data.agents.find(agent => agent.id === searchParams.get('agent')) ?? null
  const selectedAgentNames = data.agents.filter(agent => selectedAgents.has(agent.id)).map(agent => agent.hostname)

  return <div className="page-reveal">
    <PageHeader
      eyebrow="Managed Linux fleet"
      title="Agents"
      detail="Monitor agent connectivity, review accepted report freshness, and manage group-specific policy and deployment."
      action={<button className="button-primary" onClick={() => changeTab('deployment')}><Key size={16} /> Deploy Agent</button>}
    />
    {formError && <div className="mb-5 rounded-xl border border-rose-900/40 bg-rose-950/10 px-4 py-3 text-xs text-rose-700">{formError}</div>}
    {notice && <div className="mb-5 rounded-xl border border-[#b8c5ba] bg-[#edf1eb] px-4 py-3 text-xs text-[#4f6f5c]" role="status">{notice}</div>}

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
          <AgentWorkspaceHeader group={selectedGroup} activeCount={activeCount} attentionCount={attentionCount} awaitingCount={awaitingCount} activeTab={activeTab} onTabChange={changeTab} />

          {activeTab === 'hosts' && <div>
            {selectedAgents.size > 0 && <div className="flex flex-col gap-3 border-b border-[#b8c5ba] bg-[#edf1eb] px-5 py-4 sm:px-7 xl:flex-row xl:items-center">
              <strong className="mr-auto text-xs text-[#4f6f5c]">{selectedAgents.size} selected</strong>
              <button className="button-secondary min-h-9" disabled={saving} onClick={() => void submit(() => api.runAgentAudits([...selectedAgents]), undefined, `${selectedAgents.size} audit ${selectedAgents.size === 1 ? 'request was' : 'requests were'} queued for delivery on the next agent poll.`).then(() => setSelectedAgents(new Set()))}><Play size={14} /> Queue Audit</button>
              <div className="flex gap-2"><select className="select-input min-h-9" aria-label="Bulk destination group" value={bulkGroupId} onChange={event => setBulkGroupId(event.target.value)}><option value="">Move to group…</option>{data.groups.map(group => <option key={group.id} value={group.id}>{group.name}</option>)}</select><button className="button-secondary min-h-9" disabled={saving || !bulkGroupId} onClick={() => void submit(() => api.bulkAssignAgentGroup([...selectedAgents], bulkGroupId)).then(() => { setSelectedAgents(new Set()); setBulkGroupId('') })}>Apply</button></div>
              <Button variant="danger" disabled={saving} onClick={() => setConfirmBulkRevoke(true)}>Revoke selected</Button>
            </div>}
            <AgentFleetTable agents={visibleAgents} groups={data.groups} packageVersion={data.packages[0]?.version} submit={action => submit(action)} selected={selectedAgents} setSelected={setSelectedAgents} search={search} setSearch={setSearch} statusFilter={statusFilter} setStatusFilter={setStatusFilter} openAgent={agent => openAgent(agent.id)} />
          </div>}

          {activeTab === 'deployment' && <AgentDeploymentWorkspace connectivity={data.connectivity} enrollmentTokens={data.enrollmentTokens} enrollmentRecovery={data.enrollmentRecovery} groups={data.groups} packages={data.packages} selectedGroup={selectedGroup} saving={saving} submit={submit} />}

          {activeTab === 'policy' && selectedGroup && assignedPolicy && <AgentPolicyWorkspace assignedPolicy={assignedPolicy} controls={data.controls} policies={data.policies} saving={saving} selectedGroup={selectedGroup} submit={submit} />}
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
      <div className="rounded-lg border border-rose-900/40 bg-rose-950/10 px-4 py-3 text-xs leading-5 text-rose-700">Restoring connectivity requires reinstalling or re-enrolling every affected host with a new one-time token.</div>
      <div className="mt-4 border-y border-stone-200 py-3"><span className="detail-label">Selected Agents Only</span><p className="mt-2 text-xs leading-5 text-stone-700">{selectedAgentNames.join(', ') || 'No Eligible Agents Selected'}</p></div>
      <div className="mt-6 flex justify-end gap-3"><Button onClick={() => setConfirmBulkRevoke(false)} disabled={saving}>Cancel</Button><Button variant="danger" disabled={saving || selectedAgents.size === 0} onClick={() => void submit(() => api.bulkRevokeAgents([...selectedAgents])).then(() => { setSelectedAgents(new Set()); setConfirmBulkRevoke(false) })}>{saving ? 'Revoking agents' : 'Revoke agents'}</Button></div>
    </Dialog>
    {selectedAgent && !detailRevoke && <AgentDetailPanel
      agent={selectedAgent}
      saving={saving}
      close={closeAgent}
      queueAudit={() => void submit(() => api.runAgentAudits([selectedAgent.id]), undefined, `Audit request queued for ${selectedAgent.hostname}; completion will be reported asynchronously.`)}
      revoke={() => setDetailRevoke(true)}
    />}
    <Dialog open={detailRevoke && selectedAgent !== null} onOpenChange={(open) => { if (!open && !saving) setDetailRevoke(false) }} title={`Revoke Access For ${selectedAgent?.hostname ?? 'Agent'}?`} description="The installed service is not removed. Its credentials are revoked immediately and future communication is rejected; existing evidence remains available.">
      <div className="rounded-lg border border-rose-900/40 bg-rose-950/10 px-4 py-3 text-xs leading-5 text-rose-700">Restoring this installation requires a new enrollment credential and re-enrollment from the host.</div>
      <div className="mt-6 flex justify-end gap-3"><Button disabled={saving} onClick={() => setDetailRevoke(false)}>Cancel</Button><Button variant="danger" disabled={saving || !selectedAgent} onClick={() => { if (selectedAgent) void submit(() => api.revokeAgent(selectedAgent.id), () => { setDetailRevoke(false); closeAgent() }, `Access revoked for ${selectedAgent.hostname}. The installed service was not removed.`) }}>{saving ? 'Revoking Access' : 'Revoke Access'}</Button></div>
    </Dialog>
  </div>
}
