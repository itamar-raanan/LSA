import { Prohibit } from '@phosphor-icons/react'
import { useState } from 'react'
import { api } from '../../api/client'
import { formatDateTime } from '../../lib/dateTime'
import type { AgentGroup, LinuxAgent } from '../../types'
import { type SecurityColumn, SecurityTable } from '../security/SecurityTable'
import { Button } from '../ui/Button'
import { Dialog } from '../ui/Dialog'
import { reportStatus, type AgentStatus } from './agentStatus'

export function AgentFleetTable({ agents, groups, packageVersion, submit, selected, setSelected, search, setSearch, statusFilter, setStatusFilter, openAgent }: {
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
  openAgent?: (agent: LinuxAgent) => void
}) {
  const [revoking, setRevoking] = useState<LinuxAgent | null>(null)
  const columns: SecurityColumn<LinuxAgent>[] = [
    { id: 'host', header: 'Agent', priority: 'primary', hideable: false, sortValue: (agent) => agent.hostname, exportValue: (agent) => agent.hostname, cell: (agent) => <button className="finding-table-link" onClick={() => openAgent?.(agent)}><strong>{agent.hostname}</strong><small>{agent.operating_system} {agent.os_version} · {agent.architecture}</small></button> },
    { id: 'connection', header: 'Operational State', priority: 'secondary', sortValue: (agent) => agent.operational_state, exportValue: (agent) => agent.operational_state, cell: (agent) => <><span className={`status-pill status-pill-${agent.operational_state === 'operational' ? 'online' : agent.operational_state === 'revoked' ? 'revoked' : 'stale'}`}>{agent.operational_state.replaceAll('_', ' ')}</span><span className="table-subtitle">{agent.status_reason}</span></> },
    { id: 'heartbeat', header: 'Last Communication', priority: 'secondary', sortValue: (agent) => agent.last_seen_at ?? '', exportValue: (agent) => agent.last_seen_at, cell: (agent) => <span className="table-primary">{formatDateTime(agent.first_communication_at ? agent.last_seen_at : null, 'Never')}<small>{agent.configuration_state === 'synced' ? 'Policy Synced' : `Policy ${agent.configuration_state.replaceAll('_', ' ')}`}</small></span> },
    { id: 'group', header: 'Group', priority: 'detail', sortValue: (agent) => agent.group_name, exportValue: (agent) => agent.group_name, cell: (agent) => <select aria-label={`Group for ${agent.hostname}`} className="select-input min-h-9" value={agent.group_id} disabled={!!agent.revoked_at} onChange={(event) => void submit(() => api.assignAgentGroup(agent.id, event.target.value))}>{groups.map(group => <option key={group.id} value={group.id}>{group.name}</option>)}</select> },
    { id: 'version', header: 'Version', priority: 'detail', sortValue: (agent) => agent.agent_version, exportValue: (agent) => agent.agent_version, cell: (agent) => <span className="table-primary">{agent.agent_version}<small>{agent.version_state === 'update_available' ? `Update ${agent.desired_agent_version || packageVersion} Available` : agent.version_state === 'current' ? 'Current Release' : 'Version State Unknown'}</small></span> },
    { id: 'report', header: 'Latest Report', priority: 'detail', sortValue: reportStatus, exportValue: reportStatus, cell: (agent) => <span className="table-primary">{formatDateTime(agent.last_scan_at, 'Not Received')}<small>{reportStatus(agent) === 'current' ? 'Current' : reportStatus(agent) === 'stale' ? 'Stale' : 'Awaiting First Report'}</small></span> },
    { id: 'actions', header: 'Actions', priority: 'detail', hideable: false, cell: (agent) => <button className="icon-button ml-auto" aria-label={`Revoke ${agent.hostname}`} title="Revoke agent" disabled={!!agent.revoked_at} onClick={() => setRevoking(agent)}><Prohibit size={15} /></button> },
  ]

  return <>
    <SecurityTable rows={agents} columns={columns} ariaLabel="Managed Linux Agents" query={search} onQueryChange={setSearch} searchText={(agent) => `${agent.hostname} ${agent.fqdn ?? ''} ${agent.ip_addresses.join(' ')} ${agent.group_name} ${agent.policy_name} ${agent.agent_version} ${agent.operational_state}`} rowLabel={(agent) => agent.hostname} searchPlaceholder="Search Agents, IPs, Groups, Or Versions" filename="lsa-agents.csv" embedded emptyTitle="No Agents In This Scope" emptyDetail="Create an enrollment credential, install the Linux package, and verify the first authenticated communication." selectedRowIds={selected} onSelectionChange={setSelected} selectionSummary={false} isRowSelectable={(agent) => !agent.revoked_at} defaultHiddenColumnIds={['group', 'version', 'report']} toolbarActions={<select className="select-input min-h-9" aria-label="Filter agent status" value={statusFilter} onChange={(event) => setStatusFilter(event.target.value as 'all' | AgentStatus)}><option value="all">All Statuses</option><option value="online">Online</option><option value="stale">Delayed</option><option value="offline">Offline</option><option value="never">Awaiting First Contact</option><option value="revoked">Revoked</option></select>} />
    <Dialog open={revoking !== null} onOpenChange={(open) => { if (!open) setRevoking(null) }} eyebrow="Agent trust" title={`Revoke ${revoking?.hostname ?? 'agent'}?`} description="The agent identity will be rejected immediately. Existing reports remain available, but this installation cannot reconnect or submit new evidence.">
      <div className="rounded-lg border border-rose-900/40 bg-rose-950/10 px-4 py-3 text-xs leading-5 text-rose-700">Re-enrolling this host later creates a new agent identity and requires a new one-time enrollment token.</div>
      <div className="mt-6 flex justify-end gap-3"><Button onClick={() => setRevoking(null)}>Cancel</Button><Button variant="danger" disabled={!revoking} onClick={() => { if (revoking) void submit(() => api.revokeAgent(revoking.id)).finally(() => setRevoking(null)) }}>Revoke agent</Button></div>
    </Dialog>
  </>
}
