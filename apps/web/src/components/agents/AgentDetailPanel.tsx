import { ArrowSquareOut, ClockCounterClockwise, Play, Prohibit, X } from '@phosphor-icons/react'
import { Link } from 'react-router-dom'
import { formatDateTime } from '../../lib/dateTime'
import type { LinuxAgent } from '../../types'
import { Button } from '../ui/Button'

function stateLabel(value: string) {
  return value.replaceAll('_', ' ').replace(/\b\w/g, letter => letter.toUpperCase())
}

export function AgentDetailPanel({ agent, saving, close, queueAudit, revoke }: {
  agent: LinuxAgent
  saving: boolean
  close: () => void
  queueAudit: () => void
  revoke: () => void
}) {
  const statusTone = agent.operational_state === 'operational' ? 'online' : agent.operational_state === 'revoked' ? 'revoked' : 'stale'
  return <aside className="agent-detail-panel" role="dialog" aria-modal="false" aria-labelledby="agent-detail-title">
    <header className="agent-detail-header">
      <div className="min-w-0">
        <span className="section-label">Managed Agent</span>
        <h2 id="agent-detail-title">{agent.hostname}</h2>
        <p>{agent.fqdn || agent.ip_addresses[0] || 'No Network Identity Reported'}</p>
      </div>
      <Button variant="ghost" size="icon" aria-label="Close Agent Details" onClick={close}><X size={17} /></Button>
    </header>
    <div className="agent-detail-context">
      <div><span className="detail-label">Operational State</span><strong><span className={`status-pill status-pill-${statusTone}`}>{stateLabel(agent.operational_state)}</span></strong></div>
      <div><span className="detail-label">Last Communication</span><strong>{formatDateTime(agent.first_communication_at ? agent.last_seen_at : null, 'Never')}</strong></div>
      <div><span className="detail-label">Latest Report</span><strong>{formatDateTime(agent.last_scan_at, 'Not Received')}</strong></div>
    </div>
    <div className="agent-detail-body">
      <section className="agent-detail-guidance">
        <h3>{agent.status_reason}</h3>
        {agent.next_action && <p>{agent.next_action}</p>}
      </section>
      <section className="agent-detail-section">
        <h3>System Identity</h3>
        <dl className="agent-detail-list">
          <div><dt>Operating System</dt><dd>{agent.operating_system} {agent.os_version}</dd></div>
          <div><dt>Kernel</dt><dd>{agent.kernel}</dd></div>
          <div><dt>Architecture</dt><dd>{agent.architecture}</dd></div>
          <div><dt>IP Addresses</dt><dd>{agent.ip_addresses.join(', ') || 'Not Reported'}</dd></div>
          <div><dt>Agent ID</dt><dd className="font-mono">{agent.id}</dd></div>
        </dl>
      </section>
      <section className="agent-detail-section">
        <h3>Configuration And Version</h3>
        <dl className="agent-detail-list">
          <div><dt>Group</dt><dd>{agent.group_name}</dd></div>
          <div><dt>Assigned Policy</dt><dd>{agent.policy_name} · Version {agent.policy_version}</dd></div>
          <div><dt>Observed Policy</dt><dd>{agent.last_policy_version ? `Version ${agent.last_policy_version}` : 'Not Acknowledged'}</dd></div>
          <div><dt>Policy State</dt><dd>{stateLabel(agent.configuration_state)}</dd></div>
          <div><dt>Agent Version</dt><dd>{agent.agent_version} {agent.version_state === 'update_available' ? `· Update ${agent.desired_agent_version} Available` : ''}</dd></div>
          <div><dt>Platform Trust</dt><dd>{agent.platform_trust_status === 'pinned' ? 'Pinned' : 'Missing'}</dd></div>
        </dl>
      </section>
      <section className="agent-detail-section">
        <h3>Recent Activity</h3>
        <div className="agent-activity-line"><ClockCounterClockwise size={16} /><div><strong>{agent.latest_task_status ? `Audit ${stateLabel(agent.latest_task_status)}` : 'No Requested Audit'}</strong><span>{formatDateTime(agent.latest_task_completed_at ?? agent.latest_task_created_at, 'No Task History')}{agent.latest_task_id ? ` · ${agent.latest_task_id}` : ''}</span></div></div>
        {agent.latest_task_error && <div className="deployment-blocked mt-3"><span>{agent.latest_task_error}</span></div>}
        <p className="mt-3 text-[10px] leading-5 text-stone-500">Audit requests are asynchronous. Queued work is delivered on the next agent poll and completes only after the agent returns a task result.</p>
      </section>
    </div>
    <footer className="agent-detail-footer">
      <Button asChild><Link to={`/hosts/${agent.host_id}`}><ArrowSquareOut size={15} /> Open Asset</Link></Button>
      <div className="flex gap-2"><Button disabled={saving || !!agent.revoked_at} onClick={queueAudit}><Play size={15} /> Queue Audit</Button><Button variant="danger" disabled={saving || !!agent.revoked_at} onClick={revoke}><Prohibit size={15} /> Revoke Access</Button></div>
    </footer>
  </aside>
}
