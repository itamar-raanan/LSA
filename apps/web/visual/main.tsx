import { createRoot } from 'react-dom/client'
import { MemoryRouter } from 'react-router-dom'
import App from '../src/App'
import { AuthContext, type AuthValue } from '../src/auth/context'
import './styles.css'

const surface = new URLSearchParams(window.location.search).get('surface') ?? 'overview'
const routes: Record<string, string> = {
  login: '/login', overview: '/', assets: '/hosts', 'host-card': '/hosts?host=host-1', 'host-detail': '/hosts/host-1', agents: '/agents', 'agents-policy': '/agents', vulnerabilities: '/vulnerabilities', 'vulnerability-investigation': '/vulnerabilities', 'vulnerability-investigation-exposures': '/vulnerabilities', evidence: '/evidence', administration: '/settings/users',
}
const user = surface === 'login' ? null : {
  id: 'user-1', email: 'admin@lsa.local', name: 'Security Administrator', role: 'admin' as const,
}
const auth: AuthValue = {
  user,
  login: async () => undefined,
  radiusLogin: async () => undefined,
  acceptSession: () => undefined,
  logout: () => undefined,
}

createRoot(document.getElementById('root')!).render(
  <AuthContext.Provider value={auth}><MemoryRouter initialEntries={[routes[surface] ?? '/']}><App /></MemoryRouter></AuthContext.Provider>,
)
