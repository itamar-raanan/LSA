import type {
  DashboardData,
  Finding,
  Host,
  IngestionToken,
  ReportComparison,
  ReportSummary,
  TokenCreated,
  User,
} from '../types'

const API_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:8000/api/v1'

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
