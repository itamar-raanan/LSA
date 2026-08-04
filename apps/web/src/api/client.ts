import type {
  ApplicationInventoryItem,
  ApplicationEstateResponse,
  ApplicationHostCorrelation,
  DashboardData,
  Finding,
  Host,
  IngestionToken,
  ReportComparison,
  ReportSummary,
  SigningKey,
  TokenCreated,
  User,
  IdentityProvider,
  ManagedUser,
  ManagedUserCreate,
  ProviderType,
  PublicIdentityProvider,
  TlsCertificate,
  AgentPolicy,
  AgentGroup,
  LinuxAgent,
  ControlCatalogItem,
  AgentEnrollmentTokenCreated,
  AgentEnrollmentToken,
  PolicyMode,
  AgentPackage,
  AgentPolicyVersion,
  AgentTask,
} from '../types'

const API_URL = import.meta.env.VITE_API_URL ?? '/api/v1'
export const SESSION_INVALID_EVENT = 'lsa:session-invalid'

function clearInvalidSession() {
  localStorage.removeItem('lsa_session')
  localStorage.removeItem('lsa_user')
  localStorage.setItem('lsa_auth_notice', 'Your session ended. Sign in again to continue.')
  window.dispatchEvent(new Event(SESSION_INVALID_EVENT))
}

export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message)
  }
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = localStorage.getItem('lsa_session')
  const headers = new Headers(options.headers)
  if (!(options.body instanceof FormData)) headers.set('Content-Type', 'application/json')
  if (token) headers.set('Authorization', `Bearer ${token}`)
  let response: Response
  try {
    response = await fetch(`${API_URL}${path}`, { ...options, headers })
  } catch {
    throw new ApiError('The LSA API is unavailable. Check that the development services are running.', 0)
  }
  if (!response.ok) {
    const body = await response.json().catch(() => ({ detail: 'Request failed' }))
    if (response.status === 401 && token) clearInvalidSession()
    throw new ApiError(body.detail ?? 'Request failed', response.status)
  }
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

export const api = {
  async login(email: string, password: string): Promise<{ access_token: string; user: User }> {
    return request('/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) })
  },
  async radiusLogin(username: string, password: string): Promise<{ access_token: string; user: User }> {
    return request('/auth/radius/login', { method: 'POST', body: JSON.stringify({ username, password }) })
  },
  logout(): Promise<void> {
    return request('/auth/logout', { method: 'POST' })
  },
  publicProviders(): Promise<PublicIdentityProvider[]> {
    return request('/auth/providers')
  },
  async startOidc(providerId: string): Promise<void> {
    const response = await request<{ authorization_url: string }>(`/auth/oidc/${providerId}/start`)
    window.location.assign(response.authorization_url)
  },
  providers(): Promise<IdentityProvider[]> {
    return request('/settings/identity-providers')
  },
  createProvider(payload: { name: string; provider_type: ProviderType; issuer_url?: string; client_id?: string; secret?: string; config: Record<string, unknown>; is_enabled: boolean }): Promise<IdentityProvider> {
    return request('/settings/identity-providers', { method: 'POST', body: JSON.stringify(payload) })
  },
  updateProvider(id: string, payload: { name: string; provider_type: ProviderType; issuer_url?: string; client_id?: string; secret?: string; config: Record<string, unknown>; is_enabled: boolean }): Promise<IdentityProvider> {
    return request(`/settings/identity-providers/${id}`, { method: 'PUT', body: JSON.stringify(payload) })
  },
  deleteProvider(id: string): Promise<void> {
    return request(`/settings/identity-providers/${id}`, { method: 'DELETE' })
  },
  users(): Promise<ManagedUser[]> {
    return request('/settings/users')
  },
  createUser(payload: ManagedUserCreate): Promise<ManagedUser> {
    return request('/settings/users', { method: 'POST', body: JSON.stringify(payload) })
  },
  updateUserRole(id: string, role: string): Promise<ManagedUser> {
    return request(`/settings/users/${id}/role`, { method: 'PATCH', body: JSON.stringify({ role }) })
  },
  updateUserStatus(id: string, is_active: boolean): Promise<ManagedUser> {
    return request(`/settings/users/${id}/status`, { method: 'PATCH', body: JSON.stringify({ is_active }) })
  },
  tlsCertificate(): Promise<TlsCertificate | null> {
    return request('/settings/tls-certificate')
  },
  uploadTlsCertificate(certificate: File, privateKey: File): Promise<TlsCertificate> {
    const body = new FormData()
    body.append('certificate', certificate)
    body.append('private_key', privateKey)
    return request('/settings/tls-certificate', { method: 'POST', body })
  },
  dashboard(): Promise<DashboardData> {
    return request('/dashboard')
  },
  hosts(search = ''): Promise<Host[]> {
    return request(`/hosts${search ? `?search=${encodeURIComponent(search)}` : ''}`)
  },
  host(id: string): Promise<Host> {
    return request(`/hosts/${id}`)
  },
  applications(hostId: string): Promise<ApplicationInventoryItem[]> {
    return request(`/hosts/${hostId}/applications`)
  },
  applicationEstate(search = '', kind = ''): Promise<ApplicationEstateResponse> {
    const params = new URLSearchParams()
    if (search) params.set('search', search)
    if (kind) params.set('kind', kind)
    return request(`/applications${params.size ? `?${params}` : ''}`)
  },
  applicationCorrelation(name: string, kind: string, source: string): Promise<ApplicationHostCorrelation[]> {
    const params = new URLSearchParams({ name, kind, source })
    return request(`/applications/correlation?${params}`)
  },
  deleteHost(id: string): Promise<void> {
    return request(`/hosts/${id}`, { method: 'DELETE' })
  },
  reports(hostId: string): Promise<ReportSummary[]> {
    return request(`/hosts/${hostId}/reports`)
  },
  compareReport(reportId: string): Promise<ReportComparison> {
    return request(`/reports/${reportId}/compare`)
  },
  createHost(payload: {
    hostname: string
    fqdn?: string
    os_family: string
    os_version: string
    tags: Record<string, string>
  }): Promise<Host> {
    return request('/hosts', { method: 'POST', body: JSON.stringify(payload) })
  },
  createToken(payload: { name: string; host_id?: string; expires_at?: string }): Promise<TokenCreated> {
    return request('/ingestion-tokens', { method: 'POST', body: JSON.stringify(payload) })
  },
  tokens(): Promise<IngestionToken[]> {
    return request('/ingestion-tokens')
  },
  revokeToken(tokenId: string): Promise<void> {
    return request(`/ingestion-tokens/${tokenId}`, { method: 'DELETE' })
  },
  createSigningKey(payload: { name: string; public_key: string; host_id?: string; expires_at?: string }): Promise<SigningKey> {
    return request('/signing-keys', { method: 'POST', body: JSON.stringify(payload) })
  },
  signingKeys(): Promise<SigningKey[]> {
    return request('/signing-keys')
  },
  revokeSigningKey(keyId: string): Promise<void> {
    return request(`/signing-keys/${keyId}`, { method: 'DELETE' })
  },
  agentPolicies(): Promise<AgentPolicy[]> {
    return request('/agent-policies')
  },
  createAgentPolicy(payload: { name: string; description: string; default_mode: PolicyMode; control_modes: Record<string, PolicyMode>; settings: Record<string, unknown> }): Promise<AgentPolicy> {
    return request('/agent-policies', { method: 'POST', body: JSON.stringify(payload) })
  },
  updateAgentPolicy(id: string, payload: { description: string; default_mode: PolicyMode; control_modes: Record<string, PolicyMode>; settings: Record<string, unknown> }): Promise<AgentPolicy> {
    return request(`/agent-policies/${id}`, { method: 'PUT', body: JSON.stringify(payload) })
  },
  agentPolicyVersions(id: string): Promise<AgentPolicyVersion[]> {
    return request(`/agent-policies/${id}/versions`)
  },
  restoreAgentPolicy(id: string, version: number): Promise<AgentPolicy> {
    return request(`/agent-policies/${id}/restore`, { method: 'POST', body: JSON.stringify({ version }) })
  },
  agentGroups(): Promise<AgentGroup[]> {
    return request('/agent-groups')
  },
  createAgentGroup(payload: { name: string; description: string; policy_id: string }): Promise<AgentGroup> {
    return request('/agent-groups', { method: 'POST', body: JSON.stringify(payload) })
  },
  updateAgentGroup(id: string, payload: { name: string; description: string; policy_id: string }): Promise<AgentGroup> {
    return request(`/agent-groups/${id}`, { method: 'PUT', body: JSON.stringify(payload) })
  },
  agents(): Promise<LinuxAgent[]> {
    return request('/agents')
  },
  assignAgentGroup(id: string, groupId: string): Promise<LinuxAgent> {
    return request(`/agents/${id}/group`, { method: 'PATCH', body: JSON.stringify({ group_id: groupId }) })
  },
  revokeAgent(id: string): Promise<void> {
    return request(`/agents/${id}`, { method: 'DELETE' })
  },
  runAgentAudits(agentIds: string[]): Promise<AgentTask[]> {
    return request('/agents/actions/run-audit', { method: 'POST', body: JSON.stringify({ agent_ids: agentIds }) })
  },
  bulkAssignAgentGroup(agentIds: string[], groupId: string): Promise<{ affected: number }> {
    return request('/agents/actions/assign-group', { method: 'POST', body: JSON.stringify({ agent_ids: agentIds, group_id: groupId }) })
  },
  bulkRevokeAgents(agentIds: string[]): Promise<{ affected: number }> {
    return request('/agents/actions/revoke', { method: 'POST', body: JSON.stringify({ agent_ids: agentIds }) })
  },
  createAgentEnrollmentToken(payload: { name: string; group_id: string; expires_at: string }): Promise<AgentEnrollmentTokenCreated> {
    return request('/agent-enrollment-tokens', { method: 'POST', body: JSON.stringify(payload) })
  },
  agentEnrollmentTokens(): Promise<AgentEnrollmentToken[]> {
    return request('/agent-enrollment-tokens')
  },
  revokeAgentEnrollmentToken(id: string): Promise<void> {
    return request(`/agent-enrollment-tokens/${id}`, { method: 'DELETE' })
  },
  agentPackages(): Promise<AgentPackage[]> {
    return request('/agent-packages')
  },
  async downloadAgentPackage(packageId: string): Promise<{ blob: Blob; filename: string }> {
    const token = localStorage.getItem('lsa_session')
    const response = await fetch(`${API_URL}/agent-packages/${encodeURIComponent(packageId)}/download`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    })
    if (!response.ok) {
      const payload = await response.json().catch(() => ({ detail: 'Agent package download failed' }))
      throw new ApiError(payload.detail ?? 'Agent package download failed', response.status)
    }
    const disposition = response.headers.get('Content-Disposition') ?? ''
    const filename = disposition.match(/filename="([^"]+)"/)?.[1] ?? `lsa-agent-${packageId}.tar.gz`
    return { blob: await response.blob(), filename }
  },
  controlCatalog(): Promise<ControlCatalogItem[]> {
    return request('/control-catalog')
  },
  async downloadArtifact(reportId: string): Promise<{ blob: Blob; filename: string; checksum: string | null }> {
    const token = localStorage.getItem('lsa_session')
    const response = await fetch(`${API_URL}/reports/${reportId}/artifact`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    })
    if (!response.ok) {
      const payload = await response.json().catch(() => ({ detail: 'Artifact download failed' }))
      throw new ApiError(payload.detail ?? 'Artifact download failed', response.status)
    }
    const disposition = response.headers.get('Content-Disposition') ?? ''
    const filename = disposition.match(/filename="([^"]+)"/)?.[1] ?? `lsa-report-${reportId}.zip`
    return {
      blob: await response.blob(),
      filename,
      checksum: response.headers.get('X-LSA-Artifact-SHA256'),
    }
  },
  findings(filters: { severity?: string; lifecycle?: string; host_id?: string; category?: string } = {}): Promise<Finding[]> {
    const params = new URLSearchParams()
    Object.entries(filters).forEach(([key, value]) => value && params.set(key, value))
    return request(`/findings${params.size ? `?${params}` : ''}`)
  },
  async uploadBundle(file: File, ingestionToken: string): Promise<Record<string, unknown>> {
    const body = new FormData()
    body.append('file', file)
    const response = await fetch(`${API_URL}/ingest/bundles`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${ingestionToken}` },
      body,
    })
    const payload = await response.json().catch(() => ({ detail: 'Upload failed' }))
    if (!response.ok) throw new ApiError(payload.detail ?? 'Upload failed', response.status)
    return payload
  },
}
