import type { LinuxAgent } from '../../types'

export type AgentStatus = 'online' | 'stale' | 'offline' | 'never' | 'revoked'
export type ReportStatus = 'fresh' | 'stale' | 'never'

export function agentStatus(agent: LinuxAgent): AgentStatus {
  if (agent.revoked_at) return 'revoked'
  if (!agent.last_seen_at) return 'never'
  const age = Date.now() - new Date(agent.last_seen_at).getTime()
  if (age <= 5 * 60_000) return 'online'
  if (age <= 24 * 60 * 60_000) return 'stale'
  return 'offline'
}

export function reportStatus(agent: LinuxAgent): ReportStatus {
  if (!agent.last_scan_at) return 'never'
  return Date.now() - new Date(agent.last_scan_at).getTime() <= 24 * 60 * 60_000 ? 'fresh' : 'stale'
}
