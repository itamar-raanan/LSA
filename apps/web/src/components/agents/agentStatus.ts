import type { LinuxAgent } from '../../types'

export type AgentStatus = 'online' | 'stale' | 'offline' | 'never' | 'revoked'
export type ReportStatus = 'current' | 'stale' | 'never'

export function agentStatus(agent: LinuxAgent): AgentStatus {
  return agent.connectivity_state === 'awaiting_first_contact' ? 'never' : agent.connectivity_state
}

export function reportStatus(agent: LinuxAgent): ReportStatus {
  return agent.report_state
}
