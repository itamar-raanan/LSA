import { Key, Play } from '@phosphor-icons/react'
import { FormEvent, useEffect, useState } from 'react'
import { api } from '../../api/client'
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
  const [showGroup, setShowGroup] = useState(false)
  const [formError, setFormError] = useState('')
  const [saving, setSaving] = useState(false)

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

  if (loading) return <LoadingState variant="settings" />
  if (error || !data) return <ErrorState message={error ?? 'Unable to load agents'} retry={reload} />

  const scopedAgents = data.agents.filter(agent => selectedGroupId === 'all' || agent.group_id === selectedGroupId)
  const visibleAgents = scopedAgents.filter(agent => statusFilter === 'all' || agentStatus(agent) === statusFilter)
  const activeCount = scopedAgents.filter(agent => !agent.revoked_at).length

  return <div className="page-reveal">
    <PageHeader
      eyebrow="Managed Linux fleet"
      title="Agents"
      detail="Monitor agent connectivity, review accepted report freshness, and manage group-specific policy and deployment."
      action={<button className="button-primary" onClick={() => setActiveTab('deployment')}><Key size={16} /> Deploy agent</button>}
    />
    {formError && <div className="mb-5 rounded-xl border border-rose-900/40 bg-rose-950/10 px-4 py-3 text-xs text-rose-700">{formError}</div>}

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

          {activeTab === 'deployment' && <AgentDeploymentWorkspace connectivity={data.connectivity} enrollmentTokens={data.enrollmentTokens} groups={data.groups} packages={data.packages} selectedGroup={selectedGroup} saving={saving} submit={submit} />}

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
      <div className="mt-6 flex justify-end gap-3"><Button onClick={() => setConfirmBulkRevoke(false)} disabled={saving}>Cancel</Button><Button variant="danger" disabled={saving || selectedAgents.size === 0} onClick={() => void submit(() => api.bulkRevokeAgents([...selectedAgents])).then(() => { setSelectedAgents(new Set()); setConfirmBulkRevoke(false) })}>{saving ? 'Revoking agents' : 'Revoke agents'}</Button></div>
    </Dialog>
  </div>
}
