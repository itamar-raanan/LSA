import { Buildings, CheckCircle, LockKey, Network, Plus, Trash, WarningCircle } from '@phosphor-icons/react'
import { useState, type FormEvent } from 'react'
import { api } from '../../api/client'
import { PageHeader } from '../../components/PageHeader'
import { EmptyState, ErrorState, LoadingState } from '../../components/StatePanel'
import { useApi } from '../../hooks/useApi'
import type { IdentityProvider, ProviderType } from '../../types'

const providerLabels: Record<ProviderType, string> = { entra: 'Microsoft Entra ID', okta: 'Okta', google: 'Google Workspace', adfs: 'ADFS', openid: 'OpenID Connect', radius: 'RADIUS' }

export function AuthenticationSettingsPage() {
  const { data: providers, error, loading, reload } = useApi(() => api.providers(), [])
  const [adding, setAdding] = useState(false)
  const [type, setType] = useState<ProviderType>('entra')
  const [actionError, setActionError] = useState('')
  const [saving, setSaving] = useState(false)

  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setSaving(true)
    setActionError('')
    const form = new FormData(event.currentTarget)
    const roleMapping = { 'lsa-admins': 'admin', 'lsa-analysts': 'analyst', 'lsa-auditors': 'auditor' }
    const config = type === 'radius'
      ? { host: form.get('host'), port: Number(form.get('port')), user_domain: form.get('domain'), role_attribute: 'Filter-Id', role_mapping: roleMapping, default_role: 'auditor', timeout_seconds: 3, retries: 2 }
      : { scopes: 'openid profile email', email_claim: 'email', name_claim: 'name', groups_claim: 'groups', role_mapping: roleMapping, default_role: 'auditor' }
    try {
      await api.createProvider({ name: String(form.get('name')), provider_type: type, issuer_url: type === 'radius' ? undefined : String(form.get('issuer')), client_id: type === 'radius' ? undefined : String(form.get('clientId')), secret: String(form.get('secret')), config, is_enabled: true })
      setAdding(false)
      await reload()
    } catch (reason) {
      setActionError(reason instanceof Error ? reason.message : 'Provider could not be saved')
    } finally { setSaving(false) }
  }

  async function setEnabled(provider: IdentityProvider, is_enabled: boolean) {
    setActionError('')
    try {
      await api.updateProvider(provider.id, { name: provider.name, provider_type: provider.provider_type, issuer_url: provider.issuer_url ?? undefined, client_id: provider.client_id ?? undefined, config: provider.config, is_enabled })
      await reload()
    } catch (reason) { setActionError(reason instanceof Error ? reason.message : 'Provider update failed') }
  }

  async function remove(provider: IdentityProvider) {
    setActionError('')
    try { await api.deleteProvider(provider.id); await reload() } catch (reason) { setActionError(reason instanceof Error ? reason.message : 'Provider removal failed') }
  }

  return <div className="page-reveal">
    <PageHeader eyebrow="Access control" title="Authentication" detail="Connect organization identity providers and map asserted groups to least-privilege console roles." action={<button className="button-primary" onClick={() => setAdding(!adding)}><Plus size={16} /> Add provider</button>} />
    <section className="panel overflow-hidden">
      <div className="grid gap-4 px-6 py-6 sm:grid-cols-[44px_1fr_auto] sm:items-center md:px-7">
        <span className="grid size-11 place-items-center rounded-xl border border-amber-900/50 bg-amber-950/20 text-amber-300"><LockKey size={21} weight="duotone" /></span>
        <div><p className="text-sm font-medium text-stone-200">Emergency local administrator</p><p className="mt-1 text-xs leading-5 text-stone-600">Break-glass access only. Regular users are JIT-provisioned from OIDC or RADIUS.</p></div>
        <span className="settings-state">Protected fallback</span>
      </div>
    </section>
    {adding && <form className="panel mt-5 grid gap-4 p-6 md:grid-cols-2" onSubmit={create}>
      <label className="form-field"><span>Provider type</span><select className="select-input" value={type} onChange={(event) => setType(event.target.value as ProviderType)}>{Object.entries(providerLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
      <label className="form-field"><span>Display name</span><input name="name" required placeholder={providerLabels[type]} /></label>
      {type === 'radius' ? <>
        <label className="form-field"><span>RADIUS host</span><input name="host" required placeholder="radius.internal.example" /></label>
        <label className="form-field"><span>Authentication port</span><input name="port" type="number" defaultValue="1812" required /></label>
        <label className="form-field"><span>User email domain</span><input name="domain" required placeholder="example.com" /></label>
      </> : <>
        <label className="form-field md:col-span-2"><span>Issuer URL</span><input name="issuer" type="url" required placeholder={type === 'google' ? 'https://accounts.google.com' : 'https://idp.example.com'} /></label>
        <label className="form-field"><span>Client ID</span><input name="clientId" required /></label>
      </>}
      <label className="form-field"><span>{type === 'radius' ? 'Shared secret' : 'Client secret'}</span><input name="secret" type="password" required autoComplete="new-password" /></label>
      <div className="flex items-end gap-2 md:col-span-2"><button className="button-primary" disabled={saving}>{saving ? 'Saving' : 'Save and enable'}</button><button type="button" className="button-secondary" onClick={() => setAdding(false)}>Cancel</button></div>
    </form>}
    {actionError && <p className="mt-4 rounded-xl border border-rose-900/50 bg-rose-950/20 px-4 py-3 text-xs text-rose-300">{actionError}</p>}
    <div className="mt-5">
      {loading ? <LoadingState /> : error ? <ErrorState message={error} retry={reload} /> : !providers?.length ? <EmptyState title="No identity providers" detail="Add Entra ID, Okta, Google Workspace, ADFS, generic OpenID Connect, or RADIUS." /> : <div className="divide-y divide-stone-800 overflow-hidden rounded-[22px] border border-stone-800 bg-[#f7f3eb]">{providers.map((provider) => <section key={provider.id} className="grid gap-5 px-6 py-6 md:grid-cols-[44px_1fr_auto] md:items-center md:px-7">
        <span className="grid size-11 place-items-center rounded-xl border border-stone-800 bg-[#f7f3eb] text-stone-500">{provider.provider_type === 'radius' ? <Network size={21} /> : <Buildings size={21} />}</span>
        <div><p className="text-sm font-medium text-stone-200">{provider.name}</p><p className="mt-2 text-xs text-stone-600">{providerLabels[provider.provider_type]} · {provider.issuer_url ?? String(provider.config.host ?? '')}</p><p className="mt-2 font-mono text-[9px] capitalize tracking-wider text-stone-700">Secret {provider.secret_configured ? 'configured' : 'missing'} · default role auditor</p></div>
        <div className="flex items-center gap-2"><button className="button-secondary min-h-9 px-3" onClick={() => void setEnabled(provider, !provider.is_enabled)}><CheckCircle size={15} />{provider.is_enabled ? 'Disable' : 'Enable'}</button><button className="icon-button" aria-label={`Delete ${provider.name}`} onClick={() => void remove(provider)}><Trash size={15} /></button></div>
      </section>)}</div>}
    </div>
    <div className="mt-5 flex items-start gap-3 rounded-[18px] border border-amber-900/40 bg-amber-950/10 px-5 py-4 text-xs leading-5 text-amber-200/70"><WarningCircle size={18} className="mt-0.5 shrink-0" />Provider secrets are encrypted. OIDC uses discovery, authorization code with PKCE, state, nonce, issuer, audience, expiry, and signing-key validation. RADIUS should remain on a protected internal network.</div>
  </div>
}
