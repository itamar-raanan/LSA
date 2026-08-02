import { ArrowRight, CheckCircle, ShieldCheck } from '@phosphor-icons/react'
import { useState, type FormEvent } from 'react'
import { Navigate } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext'
import { BrandMark } from '../components/BrandMark'

export function LoginPage() {
  const { user, login } = useAuth()
  const [email, setEmail] = useState('admin@lsa.local')
  const [password, setPassword] = useState('lsa-dev-password')
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  if (user) return <Navigate to="/" replace />

  async function submit(event: FormEvent) {
    event.preventDefault()
    setSubmitting(true)
    setError('')
    try {
      await login(email, password)
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
          <form className="mt-9 space-y-5" onSubmit={submit}>
            <label className="form-field">
              <span>Email address</span>
              <input type="email" value={email} onChange={(event) => setEmail(event.target.value)} autoComplete="username" required />
            </label>
            <label className="form-field">
              <span>Password</span>
              <input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" required />
            </label>
            {error && <p className="rounded-xl border border-rose-900/50 bg-rose-950/20 px-3 py-2 text-xs leading-5 text-rose-300">{error}</p>}
            <button className="button-primary w-full justify-between" disabled={submitting}>
              <span>{submitting ? 'Authenticating' : 'Continue'}</span><ArrowRight size={17} />
            </button>
          </form>
          <p className="mt-7 text-xs leading-5 text-stone-600">Development credentials are prefilled. Change the bootstrap password before deploying outside a local environment.</p>
        </div>
      </section>
    </main>
  )
}

