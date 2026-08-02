import { CheckCircle, Copy, DesktopTower, Key, Plus, ShieldCheck, X } from '@phosphor-icons/react'
import { FormEvent, useMemo, useState } from 'react'
import { api } from '../../api/client'
import { PageHeader } from '../../components/PageHeader'
import { EmptyState, ErrorState, LoadingState } from '../../components/StatePanel'
import { useApi } from '../../hooks/useApi'
import type { AgentPolicy, ControlCatalogItem, PolicyMode } from '../../types'

const modes: PolicyMode[] = ['audit', 'manual', 'remediate', 'disabled']

export function AgentsSettingsPage() {
  const { data, error, loading, reload } = useApi(async () => {
    const [agents, groups, policies, controls, enrollmentTokens] = await Promise.all([
      api.agents(), api.agentGroups(), api.agentPolicies(), api.controlCatalog(), api.agentEnrollmentTokens(),
    ])
    return { agents, groups, policies, controls, enrollmentTokens }
  }, [])
  const [showGroup, setShowGroup] = useState(false)
  const [showPolicy, setShowPolicy] = useState(false)
  const [showEnrollment, setShowEnrollment] = useState(false)
  const [token, setToken] = useState('')
  const [formError, setFormError] = useState('')
  const [saving, setSaving] = useState(false)
  const [selectedPolicy, setSelectedPolicy] = useState<AgentPolicy | null>(null)
  const [controlModes, setControlModes] = useState<Record<string, PolicyMode>>({})
  const categories = useMemo(() => {
    const grouped = new Map<string, ControlCatalogItem[]>()
    for (const control of data?.controls ?? []) {
      const current = grouped.get(control.category) ?? []
      current.push(control)
      grouped.set(control.category, current)
    }
    return [...grouped.entries()]
  }, [data?.controls])

  async function submit(action: () => Promise<unknown>, close?: () => void) {
    setSaving(true); setFormError('')
    try { await action(); close?.(); await reload() }
    catch (caught) { setFormError(caught instanceof Error ? caught.message : 'Unable to save changes') }
    finally { setSaving(false) }
  }

  function createPolicy(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); const values = new FormData(event.currentTarget)
    void submit(() => api.createAgentPolicy({
      name: String(values.get('name')), description: String(values.get('description')),
      default_mode: String(values.get('default_mode')) as PolicyMode, control_modes: {},
      settings: { schedule_minutes: Number(values.get('schedule_minutes')), jitter_seconds: 300, profile: String(values.get('profile')) },
    }), () => setShowPolicy(false))
  }

  function createGroup(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); const values = new FormData(event.currentTarget)
    void submit(() => api.createAgentGroup({ name: String(values.get('name')), description: String(values.get('description')), policy_id: String(values.get('policy_id')) }), () => setShowGroup(false))
  }

  function createEnrollment(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); const values = new FormData(event.currentTarget)
    void submit(async () => {
      const created = await api.createAgentEnrollmentToken({
        name: String(values.get('name')), group_id: String(values.get('group_id')),
        expires_at: new Date(Date.now() + Number(values.get('hours')) * 3600000).toISOString(),
      }); setToken(created.token)
    })
  }

  function configure(policy: AgentPolicy) {
    setSelectedPolicy(policy); setControlModes({ ...policy.control_modes }); setFormError('')
  }

  function savePolicyVersion(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); if (!selectedPolicy) return
    const values = new FormData(event.currentTarget)
    void submit(() => api.updateAgentPolicy(selectedPolicy.id, {
      description: String(values.get('description')),
      default_mode: String(values.get('default_mode')) as PolicyMode,
      control_modes: controlModes,
      settings: { ...selectedPolicy.settings, schedule_minutes: Number(values.get('schedule_minutes')), profile: String(values.get('profile')) },
    }), () => setSelectedPolicy(null))
  }

  if (loading) return <LoadingState />
  if (error || !data) return <ErrorState message={error ?? 'Unable to load agent settings'} retry={reload} />

  return <div className="page-reveal">
    <PageHeader eyebrow="Managed Linux fleet" title="Agents, groups & policies" detail="Enroll outbound-only agents, assign one effective group, and publish immutable audit policy versions." action={<button className="button-primary" onClick={() => { setShowEnrollment(true); setToken('') }}><Key size={16} /> Enrollment token</button>} />
    <div className="mb-6 flex items-start gap-3 rounded-xl border border-emerald-900/40 bg-emerald-950/10 px-4 py-3 text-xs leading-5 text-emerald-200"><ShieldCheck size={17} className="mt-0.5 shrink-0" /><span><strong>Audit-only safety lock is active.</strong> Remediation choices can be staged in policy, but agents cannot change host configuration in this release.</span></div>
    {formError && <div className="mb-6 rounded-xl border border-rose-900/40 bg-rose-950/10 px-4 py-3 text-xs text-rose-300">{formError}</div>}

    {showEnrollment && <section className="panel mb-7 overflow-hidden"><div className="flex items-start justify-between border-b border-stone-800 px-6 py-5"><div><p className="section-label">One-time trust bootstrap</p><h2 className="mt-2 text-base font-semibold">Create enrollment token</h2></div><button className="icon-button" onClick={() => setShowEnrollment(false)} aria-label="Close"><X size={16} /></button></div>{token ? <div className="px-6 py-6"><p className="text-xs text-stone-500">Copy this token now. It is displayed once and becomes invalid after enrollment.</p><div className="mt-4 flex gap-2"><code className="min-w-0 flex-1 overflow-x-auto rounded-xl border border-stone-800 bg-[#101411] px-4 py-3 text-xs text-emerald-300">{token}</code><button className="button-secondary" onClick={() => void navigator.clipboard.writeText(token)}><Copy size={15} /> Copy</button></div></div> : <form className="grid gap-4 px-6 py-6 md:grid-cols-3" onSubmit={createEnrollment}><label className="form-field">Name<input name="name" required placeholder="Production enrollment" /></label><label className="form-field">Group<select name="group_id" required className="select-input">{data.groups.map(group => <option key={group.id} value={group.id}>{group.name}</option>)}</select></label><label className="form-field">Valid for<select name="hours" className="select-input" defaultValue="24"><option value="1">1 hour</option><option value="24">24 hours</option><option value="168">7 days</option></select></label><div className="md:col-span-3 flex justify-end"><button className="button-primary" disabled={saving || !data.groups.length}>Create token</button></div></form>} {!!data.enrollmentTokens.length && <div className="border-t border-stone-800"><div className="px-6 py-3 font-mono text-[9px] uppercase tracking-wider text-stone-600">Recent enrollment tokens</div>{data.enrollmentTokens.slice(0, 5).map(item => <div key={item.id} className="flex items-center justify-between gap-4 border-t border-stone-800 px-6 py-3 text-xs"><span><strong className="font-medium text-stone-300">{item.name}</strong><small className="table-subtitle">{item.group_name} · {item.token_prefix}…</small></span><span className="flex items-center gap-3 text-stone-600">{item.used_at ? 'Consumed' : item.revoked_at ? 'Revoked' : new Date(item.expires_at) < new Date() ? 'Expired' : 'Active'}{!item.used_at && !item.revoked_at && new Date(item.expires_at) >= new Date() && <button className="button-secondary min-h-9" onClick={() => void submit(() => api.revokeAgentEnrollmentToken(item.id))}>Revoke</button>}</span></div>)}</div>}</section>}

    <section className="panel overflow-hidden"><div className="flex items-center justify-between border-b border-stone-800 px-6 py-5"><div><p className="section-label">Agent inventory</p><p className="mt-2 text-xs text-stone-600">{data.agents.filter(agent => !agent.revoked_at).length} active agents</p></div></div>{!data.agents.length ? <EmptyState title="No enrolled agents" detail="Create an enrollment token and run the unified agent on a Linux host." /> : <div className="overflow-x-auto"><table className="data-table min-w-[900px]"><thead><tr><th>Host</th><th>Group</th><th>Policy</th><th>Heartbeat</th><th>Identity</th><th /></tr></thead><tbody>{data.agents.map(agent => <tr key={agent.id}><td><span className="font-medium text-stone-200">{agent.hostname}</span><span className="table-subtitle">agent {agent.agent_version}</span></td><td><select className="select-input min-h-9" value={agent.group_id} disabled={!!agent.revoked_at} onChange={event => void submit(() => api.assignAgentGroup(agent.id, event.target.value))}>{data.groups.map(group => <option key={group.id} value={group.id}>{group.name}</option>)}</select></td><td>{agent.policy_name}<span className="table-subtitle">v{agent.policy_version} · reported v{agent.last_policy_version ?? '—'}</span></td><td>{agent.last_seen_at ? new Date(agent.last_seen_at).toLocaleString() : 'Never'}<span className="table-subtitle">{agent.revoked_at ? 'Revoked' : 'Outbound HTTPS'}</span></td><td><span className="font-mono text-[10px]">{agent.fingerprint.slice(0, 16)}…</span></td><td><button className="button-secondary min-h-9" disabled={!!agent.revoked_at} onClick={() => window.confirm(`Revoke ${agent.hostname}?`) && void submit(() => api.revokeAgent(agent.id))}>Revoke</button></td></tr>)}</tbody></table></div>}</section>

    <div className="mt-8 grid gap-6 xl:grid-cols-2">
      <section className="panel overflow-hidden"><div className="flex items-center justify-between border-b border-stone-800 px-6 py-5"><div><p className="section-label">Groups</p><p className="mt-2 text-xs text-stone-600">One effective policy per agent.</p></div><button className="button-secondary min-h-9" onClick={() => setShowGroup(!showGroup)}><Plus size={14} /> Group</button></div>{showGroup && <form className="grid gap-3 border-b border-stone-800 px-6 py-5" onSubmit={createGroup}><label className="form-field">Name<input name="name" required /></label><label className="form-field">Description<input name="description" /></label><label className="form-field">Policy<select name="policy_id" className="select-input">{data.policies.map(policy => <option key={policy.id} value={policy.id}>{policy.name}</option>)}</select></label><button className="button-primary" disabled={saving}>Create group</button></form>}<div className="divide-y divide-stone-800">{data.groups.map(group => <div key={group.id} className="flex items-center justify-between gap-4 px-6 py-5"><div><p className="text-sm text-stone-200">{group.name}</p><p className="mt-1 text-xs text-stone-600">{group.agent_count} agents · {group.policy_name} v{group.policy_version}</p></div><DesktopTower size={18} className="text-stone-600" /></div>)}</div></section>
      <section className="panel overflow-hidden"><div className="flex items-center justify-between border-b border-stone-800 px-6 py-5"><div><p className="section-label">Policies</p><p className="mt-2 text-xs text-stone-600">Every save publishes a new immutable version.</p></div><button className="button-secondary min-h-9" onClick={() => setShowPolicy(!showPolicy)}><Plus size={14} /> Policy</button></div>{showPolicy && <form className="grid gap-3 border-b border-stone-800 px-6 py-5 md:grid-cols-2" onSubmit={createPolicy}><label className="form-field md:col-span-2">Name<input name="name" required /></label><label className="form-field md:col-span-2">Description<input name="description" /></label><label className="form-field">Default mode<select name="default_mode" className="select-input" defaultValue="audit">{modes.map(mode => <option key={mode}>{mode}</option>)}</select></label><label className="form-field">Schedule<select name="schedule_minutes" className="select-input" defaultValue="60"><option value="15">15 minutes</option><option value="60">Hourly</option><option value="1440">Daily</option></select></label><input type="hidden" name="profile" value="level2_server" /><button className="button-primary md:col-span-2" disabled={saving}>Create policy</button></form>}<div className="divide-y divide-stone-800">{data.policies.map(policy => <button key={policy.id} className="flex w-full items-center justify-between gap-4 px-6 py-5 text-left transition hover:bg-[#191e1a]" onClick={() => configure(policy)}><span><strong className="block text-sm font-medium text-stone-200">{policy.name}</strong><small className="mt-1 block text-xs text-stone-600">v{policy.version} · {policy.default_mode} default · {Object.keys(policy.control_modes).length} overrides</small></span><span className="settings-state">Configure</span></button>)}</div></section>
    </div>

    {selectedPolicy && <section className="panel mt-8 overflow-hidden"><form onSubmit={savePolicyVersion}><div className="flex items-start justify-between border-b border-stone-800 px-6 py-5"><div><p className="section-label">Policy composer</p><h2 className="mt-2 text-base font-semibold text-stone-100">{selectedPolicy.name} · publish v{selectedPolicy.version + 1}</h2></div><button type="button" className="icon-button" onClick={() => setSelectedPolicy(null)}><X size={16} /></button></div><div className="grid gap-4 border-b border-stone-800 px-6 py-5 md:grid-cols-4"><label className="form-field md:col-span-2">Description<input name="description" defaultValue={selectedPolicy.description} /></label><label className="form-field">Default mode<select name="default_mode" className="select-input" defaultValue={selectedPolicy.default_mode}>{modes.map(mode => <option key={mode}>{mode}</option>)}</select></label><label className="form-field">Schedule minutes<input name="schedule_minutes" type="number" min="5" max="10080" defaultValue={Number(selectedPolicy.settings.schedule_minutes ?? 60)} /></label><input type="hidden" name="profile" value={String(selectedPolicy.settings.profile ?? 'level2_server')} /></div>{!categories.length ? <EmptyState title="No observed controls yet" detail="Upload an offline report or complete an agent audit to populate per-control choices." /> : <div className="max-h-[520px] overflow-auto">{categories.map(([category, controls]) => <div key={category}><div className="sticky top-0 border-y border-stone-800 bg-[#121613] px-6 py-3 font-mono text-[9px] uppercase tracking-wider text-stone-500">{category} · {controls.length}</div>{controls.map(control => <div key={control.control_id} className="grid gap-3 border-b border-stone-800/70 px-6 py-3 md:grid-cols-[150px_1fr_150px] md:items-center"><code className="text-[10px] text-stone-500">{control.control_id}</code><span className="text-xs text-stone-300">{control.title}</span><select className="select-input min-h-9" value={controlModes[control.control_id] ?? ''} onChange={event => { const value = event.target.value as PolicyMode | ''; setControlModes(current => { const next = { ...current }; if (value) next[control.control_id] = value; else delete next[control.control_id]; return next }) }}><option value="">Inherit default</option>{modes.map(mode => <option key={mode}>{mode}</option>)}</select></div>)}</div>)}</div>}<div className="flex items-center justify-between gap-4 border-t border-stone-800 px-6 py-5"><span className="flex items-center gap-2 text-xs text-stone-600"><CheckCircle size={16} /> {Object.keys(controlModes).length} explicit control overrides</span><button className="button-primary" disabled={saving}>{saving ? 'Publishing…' : `Publish version ${selectedPolicy.version + 1}`}</button></div></form></section>}
  </div>
}
