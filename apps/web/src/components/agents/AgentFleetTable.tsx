import { Prohibit } from '@phosphor-icons/react'
import { useState } from 'react'
import { api } from '../../api/client'
import { formatDateTime } from '../../lib/dateTime'
import type { AgentGroup, LinuxAgent } from '../../types'
import { type SecurityColumn, SecurityTable } from '../security/SecurityTable'
import { Button } from '../ui/Button'
import { Dialog } from '../ui/Dialog'
import { agentStatus, reportStatus, type AgentStatus } from './agentStatus'

export function AgentFleetTable({ agents, groups, packageVersion, submit, selected, setSelected, search, setSearch, statusFilter, setStatusFilter }: {
  agents: LinuxAgent[]
  groups: AgentGroup[]
  packageVersion?: string
  submit: (action: () => Promise<unknown>) => Promise<void>
  selected: Set<string>
  setSelected: (selected: Set<string>) => void
  search: string
  setSearch: (search: string) => void
  statusFilter: 'all' | AgentStatus
  setStatusFilter: (status: 'all' | AgentStatus) => void
}) {
  const [revoking, setRevoking] = useState<LinuxAgent | null>(null)
  const columns: SecurityColumn<LinuxAgent>[] = [
    { id: 'host', header: 'Host', priority: 'primary', hideable: false, sortValue: (agent) => agent.hostname, exportValue: (agent) => agent.hostname, cell: (agent) => <span className="table-primary">{agent.hostname}<small>Agent {agent.agent_version} · {packageVersion && agent.agent_version !== packageVersion ? `Upgrade ${packageVersion} Available` : agent.capabilities.join(', ') || 'No Capabilities'}</small></span> },
    { id: 'connection', header: 'Connection', priority: 'secondary', sortValue: agentStatus, exportValue: agentStatus, cell: (agent) => <><span className={`status-pill status-pill-${agentStatus(agent)}`}>{agentStatus(agent)}</span><span className="table-subtitle">{agent.platform_trust_status === 'pinned' ? 'Platform Identity Pinned' : 'Platform Trust Missing'}</span></> },
    { id: 'report', header: 'Report Freshness', priority: 'secondary', sortValue: reportStatus, exportValue: reportStatus, cell: (agent) => <><span className={`status-pill status-pill-${reportStatus(agent) === 'fresh' ? 'online' : reportStatus(agent)}`}>{reportStatus(agent)}</span><span className="table-subtitle">{formatDateTime(agent.last_scan_at, 'No Accepted Report')}</span></> },
    { id: 'group', header: 'Group', priority: 'detail', sortValue: (agent) => agent.group_name, exportValue: (agent) => agent.group_name, cell: (agent) => <select aria-label={`Group for ${agent.hostname}`} className="select-input min-h-9" value={agent.group_id} disabled={!!agent.revoked_at} onChange={(event) => void submit(() => api.assignAgentGroup(agent.id, event.target.value))}>{groups.map(group => <option key={group.id} value={group.id}>{group.name}</option>)}</select> },
    { id: 'policy', header: 'Policy', priority: 'detail', sortValue: (agent) => agent.policy_name, exportValue: (agent) => `${agent.policy_name} v${agent.policy_version}`, cell: (agent) => <span className="table-primary">{agent.policy_name}<small>Expected V{agent.policy_version} · Reported V{agent.last_policy_version ?? '—'}</small></span> },
    { id: 'heartbeat', header: 'Last Heartbeat', priority: 'detail', sortValue: (agent) => agent.last_seen_at ?? '', exportValue: (agent) => agent.last_seen_at, cell: (agent) => <span className="table-primary">{formatDateTime(agent.last_seen_at)}<small>{agent.latest_task_status ? `Latest Audit ${agent.latest_task_status}` : 'No Requested Audit'}</small></span> },
    { id: 'actions', header: 'Actions', priority: 'detail', hideable: false, cell: (agent) => <button className="icon-button ml-auto" aria-label={`Revoke ${agent.hostname}`} title="Revoke agent" disabled={!!agent.revoked_at} onClick={() => setRevoking(agent)}><Prohibit size={15} /></button> },
  ]

  return <>
    <SecurityTable rows={agents} columns={columns} ariaLabel="Managed Linux Agents" query={search} onQueryChange={setSearch} searchText={(agent) => `${agent.hostname} ${agent.group_name} ${agent.policy_name} ${agent.agent_version}`} rowLabel={(agent) => agent.hostname} searchPlaceholder="Search Hostname, Group, Policy, Or Version" filename="lsa-agents.csv" embedded emptyTitle="No Agents In This Scope" emptyDetail="Create an enrollment token, install the Linux package, and the host will appear after enrollment." selectedRowIds={selected} onSelectionChange={setSelected} selectionSummary={false} isRowSelectable={(agent) => !agent.revoked_at} toolbarActions={<select className="select-input min-h-9" aria-label="Filter agent status" value={statusFilter} onChange={(event) => setStatusFilter(event.target.value as 'all' | AgentStatus)}><option value="all">All Statuses</option><option value="online">Online</option><option value="stale">Stale</option><option value="offline">Offline</option><option value="never">Never Connected</option><option value="revoked">Revoked</option></select>} />
    <Dialog open={revoking !== null} onOpenChange={(open) => { if (!open) setRevoking(null) }} eyebrow="Agent trust" title={`Revoke ${revoking?.hostname ?? 'agent'}?`} description="The agent identity will be rejected immediately. Existing reports remain available, but this installation cannot reconnect or submit new evidence.">
      <div className="rounded-lg border border-rose-900/40 bg-rose-950/10 px-4 py-3 text-xs leading-5 text-rose-700">Re-enrolling this host later creates a new agent identity and requires a new one-time enrollment token.</div>
      <div className="mt-6 flex justify-end gap-3"><Button onClick={() => setRevoking(null)}>Cancel</Button><Button variant="danger" disabled={!revoking} onClick={() => { if (revoking) void submit(() => api.revokeAgent(revoking.id)).finally(() => setRevoking(null)) }}>Revoke agent</Button></div>
    </Dialog>
  </>
}
