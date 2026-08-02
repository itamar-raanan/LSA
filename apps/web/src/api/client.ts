import type {
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
  ProviderType,
  PublicIdentityProvider,
  TlsCertificate,
} from '../types'

const API_URL = import.meta.env.VITE_API_URL ?? '/api/v1'

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
  findings(filters: { severity?: string; lifecycle?: string; host_id?: string } = {}): Promise<Finding[]> {
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
