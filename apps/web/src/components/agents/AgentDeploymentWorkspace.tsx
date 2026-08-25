import { Copy, DownloadSimple, Prohibit } from '@phosphor-icons/react'
import { FormEvent, useState } from 'react'
import { api } from '../../api/client'
import { formatDateTime } from '../../lib/dateTime'
import type { AgentConnectivity, AgentEnrollmentToken, AgentGroup, AgentPackage, PlatformCommandTrust } from '../../types'
import { AgentDownloadPanel } from '../AgentDownloadPanel'
import { Button } from '../ui/Button'
import { Dialog } from '../ui/Dialog'

type EnrollmentType = 'one_time' | 'reusable'
type RotationDecision = 'activate' | 'abort'

export function AgentDeploymentWorkspace({ connectivity, enrollmentTokens, groups, packages, selectedGroup, saving, submit }: {
  connectivity: AgentConnectivity
  enrollmentTokens: AgentEnrollmentToken[]
  groups: AgentGroup[]
  packages: AgentPackage[]
  selectedGroup: AgentGroup | null
  saving: boolean
  submit: (action: () => Promise<unknown>, close?: () => void) => Promise<void>
}) {
  const [showDownloads, setShowDownloads] = useState(false)
  const [token, setToken] = useState('')
  const [enrollmentTrust, setEnrollmentTrust] = useState<PlatformCommandTrust | null>(null)
  const [enrollmentType, setEnrollmentType] = useState<EnrollmentType>('one_time')
  const [createdTokenType, setCreatedTokenType] = useState<EnrollmentType>('one_time')
  const [createdTokenMaxUses, setCreatedTokenMaxUses] = useState<number | null>(null)
  const [rotationDecision, setRotationDecision] = useState<RotationDecision | null>(null)

  const activeReusableToken = enrollmentTokens.find(item => item.token_type === 'reusable' && !item.revoked_at && new Date(item.expires_at).getTime() > Date.now() && (item.max_uses === null || item.use_count < item.max_uses))

  function createEnrollment(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const values = new FormData(event.currentTarget)
    void submit(async () => {
      const maxUsesText = String(values.get('max_uses') ?? '').trim()
      const created = await api.createAgentEnrollmentToken({
        name: String(values.get('name')),
        group_id: String(values.get('group_id')),
        expires_at: new Date(Date.now() + Number(values.get('hours')) * 3600000).toISOString(),
        token_type: enrollmentType,
        max_uses: enrollmentType === 'reusable' && maxUsesText ? Number(maxUsesText) : null,
      })
      setToken(created.token)
      setEnrollmentTrust(created.platform_trust)
      setCreatedTokenType(created.token_type)
      setCreatedTokenMaxUses(created.max_uses)
    })
  }

  return <>
    {showDownloads && <AgentDownloadPanel packages={packages} platformUrl={connectivity.public_url} platformTrust={enrollmentTrust ?? connectivity.platform_trust} enrollmentToken={token || undefined} close={() => setShowDownloads(false)} />}
    <div>
      <div className="border-b border-stone-200 px-5 py-5 sm:px-7">
        <p className="section-label">Agent deployment</p>
        <h3 className="mt-2 text-base font-semibold text-stone-800">Enroll Linux hosts</h3>
        <p className="mt-2 max-w-2xl text-xs leading-5 text-stone-500">Use a short-lived token for one host or a controlled reusable tenant token for automated fleet enrollment. Every host enters the selected group and verifies the pinned platform identity.</p>
      </div>
      <div className="grid min-w-0 lg:grid-cols-[minmax(0,1fr)_minmax(320px,.8fr)]">
        <section className="min-w-0 border-b border-stone-200 px-5 py-6 sm:px-7 lg:border-b-0 lg:border-r">
          <div className="flex items-start justify-between gap-4">
            <div><p className="section-label">Connection destination</p><p className="mt-3 text-sm font-medium text-stone-800">Dedicated agent gateway</p><code className="mt-2 block break-all text-[11px] text-stone-500">{connectivity.public_url}</code></div>
            <span className="status-pill status-pill-online">Identity Pinned</span>
          </div>
          <div className="mt-6 grid gap-4 border-t border-stone-200 pt-5 sm:grid-cols-2">
            <div><span className="detail-label">Current release</span><strong className="mt-2 block text-sm font-semibold text-stone-800">{packages[0]?.version ?? 'Unavailable'}</strong><span className="table-subtitle">{packages.length} package formats</span></div>
            <div><span className="detail-label">Operating mode</span><strong className="mt-2 block text-sm font-semibold text-stone-800">Audit only</strong><span className="table-subtitle">Host configuration is not changed</span></div>
          </div>
          <div className="mt-4 border-t border-stone-200 pt-4"><span className="detail-label">Platform identity fingerprint</span><code className="mt-2 block break-all text-[10px] text-stone-500">SHA256:{connectivity.platform_trust.fingerprint}</code></div>
          <div className="mt-5 border-t border-stone-200 pt-5">
            <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
              <div className="min-w-0">
                <span className="detail-label">Signing Key Rotation</span>
                {connectivity.key_rotation ? <>
                  <strong className="mt-2 block text-sm font-semibold text-stone-800">{connectivity.key_rotation.status === 'ready' ? 'Ready To Activate' : 'Waiting For Agent Acknowledgement'}</strong>
                  <p className="mt-1 text-xs leading-5 text-stone-500">{connectivity.key_rotation.acknowledged_agents} of {connectivity.key_rotation.eligible_agents} supported agents acknowledged version {connectivity.key_rotation.next_key.key_version}. {connectivity.key_rotation.blocking_agents > 0 ? `${connectivity.key_rotation.blocking_agents} agent(s) still block activation.` : 'Every managed agent can verify the new identity.'}</p>
                  <code className="mt-3 block break-all text-[10px] text-stone-500">Next SHA256:{connectivity.key_rotation.next_key.fingerprint}</code>
                </> : <>
                  <strong className="mt-2 block text-sm font-semibold text-stone-800">Version {connectivity.platform_trust.key_version} Active</strong>
                  <p className="mt-1 text-xs leading-5 text-stone-500">Stage a replacement without interrupting agents. Activation remains locked until every active agent acknowledges it.</p>
                </>}
              </div>
              {connectivity.key_rotation ? <div className="flex shrink-0 flex-wrap gap-2">
                <Button disabled={saving} onClick={() => setRotationDecision('abort')}>Abort</Button>
                <Button variant="primary" disabled={saving || connectivity.key_rotation.blocking_agents > 0} onClick={() => setRotationDecision('activate')}>Activate</Button>
              </div> : <Button className="shrink-0" disabled={saving} onClick={() => void submit(() => api.stagePlatformCommandKeyRotation())}>Stage New Key</Button>}
            </div>
          </div>
          <Button className="mt-6" disabled={!packages.length} onClick={() => setShowDownloads(true)}><DownloadSimple size={15} /> View packages and commands</Button>
        </section>

        <section className="min-w-0 px-5 py-6 sm:px-7">
          <p className="section-label">Enrollment credential</p>
          {token ? <div className="mt-4">
            <p className="text-xs leading-5 text-stone-500">Copy this token now; it will not be shown again. {createdTokenType === 'one_time' ? 'It becomes invalid after one successful enrollment.' : `It can enroll multiple hosts until expiry${createdTokenMaxUses ? ` or ${createdTokenMaxUses} successful uses` : ''}. Store it in your deployment secret manager.`}</p>
            <code className="mt-4 block min-w-0 overflow-x-auto rounded-lg border border-stone-200 bg-[#f7f3eb] px-4 py-3 text-xs text-[#4f6f5c]">{token}</code>
            <div className="mt-4 flex flex-wrap gap-2"><Button onClick={() => void navigator.clipboard.writeText(token)}><Copy size={15} /> Copy token</Button><Button variant="primary" onClick={() => setShowDownloads(true)}><DownloadSimple size={15} /> Continue to installation</Button></div>
          </div> : <form className="mt-4 grid gap-4" onSubmit={createEnrollment}>
            {activeReusableToken && <div className="rounded-xl border border-[#b8c5ba] bg-[#edf1eb] p-4 text-xs leading-5 text-stone-600"><div className="flex min-w-0 items-start justify-between gap-4"><div className="min-w-0"><strong className="block truncate font-medium text-stone-800">{activeReusableToken.name}</strong><span className="mt-1 block">Reusable tenant token · {activeReusableToken.group_name}</span><span className="mt-1 block">{activeReusableToken.use_count}{activeReusableToken.max_uses === null ? ' uses' : ` of ${activeReusableToken.max_uses} uses`} · Expires {formatDateTime(activeReusableToken.expires_at)}</span></div><Button type="button" disabled={saving} onClick={() => void submit(() => api.revokeAgentEnrollmentToken(activeReusableToken.id))}><Prohibit size={14} /> Revoke</Button></div></div>}
            <label className="form-field">Credential type<select name="token_type" className="select-input w-full" value={enrollmentType} onChange={event => setEnrollmentType(event.target.value as EnrollmentType)}><option value="one_time">One-time token</option><option value="reusable">Reusable tenant token</option></select><small>{enrollmentType === 'one_time' ? 'Best for manual enrollment of one host.' : 'Best for automated provisioning. Only one reusable token can be active per tenant.'}</small></label>
            <label className="form-field">Token name<input name="name" required placeholder="Production enrollment" /></label>
            <label className="form-field">Destination group<select name="group_id" required className="select-input w-full" defaultValue={selectedGroup?.id ?? groups[0]?.id}>{groups.map(group => <option key={group.id} value={group.id}>{group.name}</option>)}</select></label>
            <label className="form-field">Expires after<select name="hours" className="select-input w-full" defaultValue={enrollmentType === 'one_time' ? '24' : '2160'} key={enrollmentType}>{enrollmentType === 'one_time' ? <><option value="1">1 hour</option><option value="24">24 hours</option><option value="168">7 days</option></> : <><option value="720">30 days</option><option value="2160">90 days</option><option value="8760">365 days</option></>}</select></label>
            {enrollmentType === 'reusable' && <label className="form-field">Maximum enrollments <input name="max_uses" type="number" min="2" max="100000" placeholder="Unlimited" /><small>Leave blank for unlimited use until expiration.</small></label>}
            <Button variant="primary" disabled={saving || !groups.length || (enrollmentType === 'reusable' && !!activeReusableToken)}>{saving ? 'Creating token' : enrollmentType === 'reusable' ? 'Create reusable token' : 'Create one-time token'}</Button>
          </form>}
        </section>
      </div>
    </div>
    <Dialog
      open={rotationDecision !== null}
      onOpenChange={(open) => { if (!open && !saving) setRotationDecision(null) }}
      eyebrow="Platform Trust"
      title={rotationDecision === 'activate' ? 'Activate The New Signing Key?' : 'Abort This Key Rotation?'}
      description={rotationDecision === 'activate' ? 'The platform will sign future agent control responses with the acknowledged key. Enrollment tokens tied to the previous identity will be revoked.' : 'Agents will keep the current signing key. Any staged acknowledgements will be cleared safely.'}
    >
      {rotationDecision === 'activate' && <div className="rounded-lg border border-amber-900/30 bg-amber-950/10 px-4 py-3 text-xs leading-5 text-amber-900">Create a new enrollment token after activation. Existing hosts remain connected because they acknowledged the replacement key before this action became available.</div>}
      <div className="mt-6 flex justify-end gap-3"><Button disabled={saving} onClick={() => setRotationDecision(null)}>Cancel</Button><Button variant={rotationDecision === 'activate' ? 'primary' : 'danger'} disabled={saving} onClick={() => void submit(() => rotationDecision === 'activate' ? api.activatePlatformCommandKeyRotation() : api.abortPlatformCommandKeyRotation()).then(() => setRotationDecision(null))}>{saving ? 'Updating Trust' : rotationDecision === 'activate' ? 'Activate Key' : 'Abort Rotation'}</Button></div>
    </Dialog>
  </>
}
