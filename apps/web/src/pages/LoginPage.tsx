import { ArrowRight, Buildings, CheckCircle, ShieldCheck } from '@phosphor-icons/react'
import { useEffect, useState, type FormEvent } from 'react'
import { Navigate } from 'react-router-dom'
import { api } from '../api/client'
import { useAuth } from '../auth/useAuth'
import { BrandMark } from '../components/BrandMark'
import type { PublicIdentityProvider, User } from '../types'

export function LoginPage() {
  const { user, login, radiusLogin, acceptSession } = useAuth()
  const [email, setEmail] = useState('admin@lsa.local')
  const [password, setPassword] = useState('lsa-dev-password')
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [providers, setProviders] = useState<PublicIdentityProvider[]>([])
  const [method, setMethod] = useState<'organization' | 'radius' | 'emergency'>('organization')

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
      if (method === 'radius') await radiusLogin(email, password)
      else await login(email, password)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Sign in failed')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <main className="grid min-h-[100dvh] bg-[#111512] text-stone-100 lg:grid-cols-[1.1fr_0.9fr]">
      <section className="relative hidden overflow-hidden border-r border-stone-800 p-12 lg:flex lg:flex-col">
        <div className="absolute inset-0 opacity-30 [background-image:linear-gradient(rgba(113,124,115,.08)_1px,transparent_1px),linear-gradient(90deg,rgba(113,124,115,.08)_1px,transparent_1px)] [background-size:56px_56px]" />
        <div className="relative"><BrandMark /></div>
        <div className="relative mt-auto max-w-[660px] pb-10">
          <p className="mb-5 font-mono text-[10px] uppercase tracking-[0.2em] text-emerald-400">Estate-wide assurance</p>
          <h1 className="max-w-[12ch] text-5xl font-medium leading-[0.98] tracking-[-0.065em] text-stone-50 xl:text-6xl">Every Linux host. One security picture.</h1>
          <p className="mt-7 max-w-[55ch] text-[15px] leading-7 text-stone-400">Collect signed audit evidence without granting the platform access to your servers. Track exposure, compliance, and change across the entire estate.</p>
          <div className="mt-10 grid grid-cols-2 gap-x-12 gap-y-5 border-t border-stone-800 pt-7 text-xs text-stone-400">
            {['No remote execution', 'Customer-controlled scans', 'Offline-capable bundles', 'Immutable report history'].map((item) => (
              <div key={item} className="flex items-center gap-2"><CheckCircle size={16} className="text-emerald-400" />{item}</div>
            ))}
          </div>
        </div>
      </section>

      <section className="flex items-center justify-center px-5 py-12 sm:px-10">
        <div className="w-full max-w-[420px]">
          <div className="mb-12 lg:hidden"><BrandMark /></div>
          <div className="mb-8 grid size-11 place-items-center rounded-2xl border border-stone-700 bg-stone-900 text-emerald-300 shadow-[inset_0_1px_0_rgba(255,255,255,.05)]"><ShieldCheck size={22} weight="duotone" /></div>
          <h2 className="text-3xl font-medium tracking-[-0.045em]">Access the console</h2>
          <p className="mt-2 text-sm leading-6 text-stone-500">Use your organization account to review the Linux estate.</p>
          {providers.filter((provider) => provider.provider_type !== 'radius').length > 0 && <div className="mt-8 space-y-2">
            {providers.filter((provider) => provider.provider_type !== 'radius').map((provider) => <button key={provider.id} className="button-secondary w-full justify-between" onClick={() => void api.startOidc(provider.id)}><span className="flex items-center gap-2"><Buildings size={16} /> Continue with {provider.name}</span><ArrowRight size={16} /></button>)}
          </div>}
          <div className="mt-7 flex gap-2 border-b border-stone-800 pb-3 text-[10px] uppercase tracking-wider text-stone-600">
            {providers.some((provider) => provider.provider_type === 'radius') && <button className={method === 'radius' ? 'text-emerald-300' : ''} onClick={() => setMethod('radius')}>RADIUS</button>}
            <button className={method === 'emergency' ? 'text-emerald-300' : ''} onClick={() => setMethod('emergency')}>Emergency admin</button>
          </div>
          {method !== 'organization' && <form className="mt-6 space-y-5" onSubmit={submit}>
            <label className="form-field">
              <span>{method === 'radius' ? 'RADIUS username' : 'Email address'}</span>
              <input type={method === 'radius' ? 'text' : 'email'} value={email} onChange={(event) => setEmail(event.target.value)} autoComplete="username" required />
            </label>
            <label className="form-field">
              <span>Password</span>
              <input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" required />
            </label>
            {error && <p className="rounded-xl border border-rose-900/50 bg-rose-950/20 px-3 py-2 text-xs leading-5 text-rose-300">{error}</p>}
            <button className="button-primary w-full justify-between" disabled={submitting}>
              <span>{submitting ? 'Authenticating' : 'Continue'}</span><ArrowRight size={17} />
            </button>
          </form>}
          {!providers.length && method === 'organization' && <p className="mt-7 rounded-xl border border-stone-800 bg-[#151916] px-4 py-3 text-xs leading-5 text-stone-500">No organization identity provider is enabled. Use the emergency administrator to configure OpenID Connect or RADIUS.</p>}
          <p className="mt-7 text-xs leading-5 text-stone-600">The local password is reserved for emergency administration. Regular users are provisioned from OpenID Connect or RADIUS.</p>
        </div>
      </section>
    </main>
  )
}
