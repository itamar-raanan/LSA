import { ArrowRight, Building2, Eye, EyeOff, ShieldCheck } from 'lucide-react'
import { useEffect, useState, type FormEvent } from 'react'
import { Navigate } from 'react-router-dom'
import { api } from '../api/client'
import lsaLogo from '../assets/lsa-logo-transparent.png'
import tuxSamuraiWallpaper from '../assets/tux-samurai-login.png'
import { useAuth } from '../auth/useAuth'
import { Button } from '../components/ui/Button'
import type { PublicIdentityProvider, User } from '../types'

export function LoginPage() {
  const { user, login, radiusLogin, acceptSession } = useAuth()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [showPassword, setShowPassword] = useState(false)
  const [providers, setProviders] = useState<PublicIdentityProvider[]>([])
  const [method, setMethod] = useState<'local' | 'radius'>('local')
  const [sessionNotice] = useState(() => {
    const notice = localStorage.getItem('lsa_auth_notice')
    localStorage.removeItem('lsa_auth_notice')
    return notice
  })

  useEffect(() => {
    const fragment = new URLSearchParams(window.location.hash.slice(1))
    const token = fragment.get('session')
    const encodedUser = fragment.get('user')
    if (token && encodedUser) {
      try {
        const padded = encodedUser + '='.repeat((4 - encodedUser.length % 4) % 4)
        acceptSession(token, JSON.parse(atob(padded.replace(/-/g, '+').replace(/_/g, '/'))) as User)
        window.history.replaceState(null, '', '/login')
      } catch {
        setError('The identity-provider response could not be accepted.')
      }
    }
    void api.publicProviders().then(setProviders).catch(() => setProviders([]))
  }, [acceptSession])

  if (user) return <Navigate to="/" replace />

  async function submit(event: FormEvent) {
    event.preventDefault()
    setSubmitting(true)
    setError('')
    try {
      if (method === 'radius') await radiusLogin(username, password)
      else await login(username, password)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Sign in failed')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <main className="login-page">
      <img className="login-wallpaper" src={tuxSamuraiWallpaper} alt="" aria-hidden="true" />
      <header className="login-brand"><img className="login-logo" src={lsaLogo} alt="Linux Security Auditor" /></header>
      <section className="login-stage" aria-labelledby="login-title">
        <div className="login-form-shell">
          <div className="login-form-intro">
            <span className="login-security-mark"><ShieldCheck size={18} /></span>
            <div><p>LSA Management Console</p><h1 id="login-title">Access the console</h1></div>
          </div>
          <p className="login-form-detail">Sign in with your organization account to review Linux security posture and evidence.</p>
          {sessionNotice && <p className="login-notice" role="status">{sessionNotice}</p>}
          {providers.filter((provider) => provider.provider_type !== 'radius').length > 0 && <div className="login-provider-list">
            {providers.filter((provider) => provider.provider_type !== 'radius').map((provider) => <Button key={provider.id} className="w-full justify-between" onClick={() => void api.startOidc(provider.id)}><span className="flex items-center gap-2"><Building2 size={15} />Continue With {provider.name}</span><ArrowRight size={14} /></Button>)}
          </div>}
          {providers.some((provider) => provider.provider_type === 'radius') && <div className="login-methods" role="group" aria-label="Authentication Method">
            <button type="button" className={method === 'local' ? 'login-method-active' : ''} aria-pressed={method === 'local'} onClick={() => setMethod('local')}>Local Account</button>
            <button type="button" className={method === 'radius' ? 'login-method-active' : ''} aria-pressed={method === 'radius'} onClick={() => setMethod('radius')}>RADIUS</button>
          </div>}
          <form className="login-form" onSubmit={submit}>
            <label className="form-field">
              <span>Username</span>
              <input type="text" value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" required />
            </label>
            <label className="form-field">
              <span>Password</span>
              <span className="login-password-field"><input type={showPassword ? 'text' : 'password'} value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" required /><button type="button" aria-label={showPassword ? 'Hide Password' : 'Show Password'} aria-pressed={showPassword} onClick={() => setShowPassword(value => !value)}>{showPassword ? <EyeOff size={15} /> : <Eye size={15} />}</button></span>
            </label>
            {error && <p className="login-error" role="alert">{error}</p>}
            <Button variant="primary" className="w-full justify-between" disabled={submitting}><span>{submitting ? 'Authenticating' : 'Continue'}</span><ArrowRight size={14} /></Button>
          </form>
          <div className="login-trust-note"><ShieldCheck size={14} /><span>Authorized access only. Authentication activity is recorded in the security audit log.</span></div>
        </div>
      </section>
      <footer className="login-footer"><span>Linux Security Auditor</span><span>Management Access</span></footer>
    </main>
  )
}
