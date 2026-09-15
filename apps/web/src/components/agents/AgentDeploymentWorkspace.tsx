import { ArrowClockwise, CheckCircle, Circle, Copy, DownloadSimple, Prohibit, SpinnerGap, Warning } from '@phosphor-icons/react'
import { FormEvent, useEffect, useState } from 'react'
import { api } from '../../api/client'
import { formatDateTime } from '../../lib/dateTime'
import type { AgentConnectivity, AgentEnrollmentProgress, AgentEnrollmentRecovery, AgentEnrollmentToken, AgentGroup, AgentPackage, PlatformCommandTrust } from '../../types'
import { AgentDownloadPanel } from '../AgentDownloadPanel'
import { Button } from '../ui/Button'
import { Dialog } from '../ui/Dialog'

type EnrollmentType = 'one_time' | 'reusable'
type RotationDecision = 'activate' | 'abort'

export function AgentDeploymentWorkspace({ connectivity, enrollmentTokens, enrollmentRecovery, groups, packages, selectedGroup, saving, submit }: {
  connectivity: AgentConnectivity
  enrollmentTokens: AgentEnrollmentToken[]
  enrollmentRecovery: AgentEnrollmentRecovery[]
  groups: AgentGroup[]
  packages: AgentPackage[]
  selectedGroup: AgentGroup | null
  saving: boolean
  submit: (action: () => Promise<unknown>, close?: () => void) => Promise<void>
}) {
  const [showDownloads, setShowDownloads] = useState(false)
  const [token, setToken] = useState('')
  const [createdTokenId, setCreatedTokenId] = useState('')
  const [progress, setProgress] = useState<AgentEnrollmentProgress | null>(null)
  const [progressError, setProgressError] = useState('')
  const [enrollmentTrust, setEnrollmentTrust] = useState<PlatformCommandTrust | null>(null)
  const [enrollmentType, setEnrollmentType] = useState<EnrollmentType>('one_time')
  const [createdTokenType, setCreatedTokenType] = useState<EnrollmentType>('one_time')
  const [createdTokenMaxUses, setCreatedTokenMaxUses] = useState<number | null>(null)
  const [rotationDecision, setRotationDecision] = useState<RotationDecision | null>(null)
  const [recoveryTarget, setRecoveryTarget] = useState<AgentEnrollmentRecovery | null>(null)

  const activeReusableToken = enrollmentTokens.find(item => item.token_type === 'reusable' && !item.revoked_at && new Date(item.expires_at).getTime() > Date.now() && (item.max_uses === null || item.use_count < item.max_uses))

  useEffect(() => {
    if (!createdTokenId) return
    let active = true
    const load = async () => {
      try {
        const next = await api.agentEnrollmentProgress(createdTokenId)
        if (active) { setProgress(next); setProgressError('') }
      } catch (caught) {
        if (active) setProgressError(caught instanceof Error ? caught.message : 'Verification status could not be loaded')
      }
    }
    void load()
    const timer = window.setInterval(() => void load(), 5_000)
    return () => { active = false; window.clearInterval(timer) }
  }, [createdTokenId])

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
      setCreatedTokenId(created.id)
      setProgress(null)
      setEnrollmentTrust(created.platform_trust)
      setCreatedTokenType(created.token_type)
      setCreatedTokenMaxUses(created.max_uses)
    })
  }

  const deployedAgent = progress?.agents[0]
  const deploymentSteps = [
    { label: 'Instructions Generated', detail: 'Package and enrollment command are ready.', done: !!token },
    { label: 'Agent Enrolled', detail: deployedAgent ? `${deployedAgent.hostname} created an agent identity.` : 'Waiting for the enrollment request.', done: !!deployedAgent },
    { label: 'First Communication', detail: deployedAgent?.first_communication_at ? `Authenticated at ${formatDateTime(deployedAgent.first_communication_at)}.` : 'Waiting for an authenticated request after enrollment.', done: !!deployedAgent?.first_communication_at },
    { label: 'Operational', detail: deployedAgent?.operational_state === 'operational' ? 'Policy is synchronized and a current report is accepted.' : deployedAgent?.next_action ?? 'Waiting for communication, policy sync, and the first accepted report.', done: deployedAgent?.operational_state === 'operational' },
  ]

  return <>
    {showDownloads && <AgentDownloadPanel packages={packages} platformUrl={connectivity.public_url} platformTrust={enrollmentTrust ?? connectivity.platform_trust} enrollmentToken={token || undefined} reusableCredential={createdTokenType === 'reusable'} close={() => setShowDownloads(false)} />}
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
          <details className="mt-5 border-t border-stone-200 pt-5">
            <summary className="cursor-pointer text-xs font-semibold text-stone-700">Advanced Platform Trust</summary>
          <div className="mt-4">
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
          </details>
          <Button className="mt-6" disabled={!packages.length} onClick={() => setShowDownloads(true)}><DownloadSimple size={15} /> Choose Package</Button>
        </section>

        <section className="min-w-0 px-5 py-6 sm:px-7">
          <p className="section-label">Enrollment credential</p>
          {token ? <div className="mt-4">
            <p className="text-xs leading-5 text-stone-500">Copy this token now; it will not be shown again. {createdTokenType === 'one_time' ? 'It becomes invalid after one successful enrollment.' : `It can enroll multiple hosts until expiry${createdTokenMaxUses ? ` or ${createdTokenMaxUses} successful uses` : ''}. Store it in your deployment secret manager.`}</p>
            <code className="mt-4 block min-w-0 overflow-x-auto rounded-lg border border-stone-200 bg-[#f7f3eb] px-4 py-3 text-xs text-[#4f6f5c]">{token}</code>
            <div className="mt-4 flex flex-wrap gap-2"><Button onClick={() => void navigator.clipboard.writeText(token)}><Copy size={15} /> Copy Token</Button><Button variant="primary" onClick={() => setShowDownloads(true)}><DownloadSimple size={15} /> Continue To Installation</Button></div>
            <div className="deployment-verification" aria-label="Deployment Verification">
              <div className="flex items-center justify-between gap-3"><h4>Deployment Verification</h4>{createdTokenId && !progress && !progressError && <SpinnerGap className="animate-spin text-stone-500" size={15} />}</div>
              <p className="mt-1 text-[10px] leading-5 text-stone-500">This tracker reflects server-observed events. Copying a command does not mark the agent as installed.</p>
              <ol>{deploymentSteps.map((step, index) => <li key={step.label} className={step.done ? 'deployment-step-complete' : ''}>{step.done ? <CheckCircle weight="fill" size={17} /> : <Circle size={17} />}<div><strong>{step.label}</strong><span>{step.detail}</span></div>{index < deploymentSteps.length - 1 && <i />}</li>)}</ol>
              {progress && progress.token_state !== 'active' && !deployedAgent && <div className="deployment-blocked"><Warning size={15} /><span>This credential is {progress.token_state}. Create a new credential before retrying enrollment.</span></div>}
              {progressError && <div className="deployment-blocked"><Warning size={15} /><span>{progressError}. Verification will retry automatically.</span></div>}
              {!deployedAgent && <details className="mt-3 text-[10px] leading-5 text-stone-600"><summary className="cursor-pointer font-semibold text-stone-700">If The Agent Does Not Appear</summary><ol className="mt-2 list-decimal space-y-1 pl-4"><li>Confirm the enrollment credential is still active and assigned to the intended group.</li><li>On the host, run <code>systemctl status lsa-agent.service</code>.</li><li>Review <code>journalctl -u lsa-agent.service -n 100 --no-pager</code>.</li><li>Verify DNS, system time, and outbound TCP access to the agent gateway on port 8444.</li></ol></details>}
            </div>
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
      {enrollmentRecovery.length > 0 && <section className="border-t border-stone-200 bg-[#f7f3eb] px-5 py-5 sm:px-7">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div className="min-w-0">
            <div className="flex items-center gap-2 text-sm font-semibold text-stone-800"><Warning size={17} className="shrink-0 text-[#b74f52]" /> Enrollment Recovery Required</div>
            <p className="mt-2 max-w-2xl text-xs leading-5 text-stone-600">LSA found {enrollmentRecovery.length} hidden or incomplete enrollment {enrollmentRecovery.length === 1 ? 'record' : 'records'}. Prepare a host for re-enrollment to restore it to Assets, revoke stale credentials, and preserve its existing reports.</p>
          </div>
        </div>
        <div className="mt-4 divide-y divide-stone-200 border-y border-stone-200">
          {enrollmentRecovery.map(record => <div key={record.agent_id} className="flex flex-col gap-3 py-3 sm:flex-row sm:items-center">
            <div className="min-w-0 flex-1"><strong className="block truncate text-xs font-semibold text-stone-800">{record.hostname}</strong><span className="mt-1 block text-[11px] text-stone-500">{record.reason === 'host_deleted' ? 'Hidden asset record' : record.reason === 'credentials_revoked' ? 'Incomplete agent credentials' : 'Incomplete inventory relationship'} · Agent {record.agent_version}</span></div>
            <Button className="shrink-0" disabled={saving || record.reason === 'inventory_incomplete'} onClick={() => setRecoveryTarget(record)}><ArrowClockwise size={14} /> Prepare Re-enrollment</Button>
          </div>)}
        </div>
      </section>}
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
    <Dialog
      open={recoveryTarget !== null}
      onOpenChange={(open) => { if (!open && !saving) setRecoveryTarget(null) }}
      title={`Prepare ${recoveryTarget?.hostname ?? 'Host'} For Re-enrollment?`}
      description="LSA will restore the hidden asset record and revoke its stale agent credentials. Reports, findings, and audit history remain preserved."
    >
      <div className="rounded-lg border border-[#b8c5ba] bg-[#edf1eb] px-4 py-3 text-xs leading-5 text-stone-700">After this action, create a new enrollment token and run the enrollment command again on the host. Keep the existing files under <code>/etc/lsa-agent</code> and <code>/var/lib/lsa-agent</code>.</div>
      <div className="mt-6 flex justify-end gap-3"><Button disabled={saving} onClick={() => setRecoveryTarget(null)}>Cancel</Button><Button variant="primary" disabled={saving || !recoveryTarget} onClick={() => { if (recoveryTarget) void submit(() => api.prepareAgentReenrollment(recoveryTarget.agent_id)).then(() => setRecoveryTarget(null)) }}>{saving ? 'Preparing Host' : 'Prepare Re-enrollment'}</Button></div>
    </Dialog>
  </>
}
