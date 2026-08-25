import { FolderSimple, Plus, UsersThree } from '@phosphor-icons/react'
import type { FormEvent } from 'react'
import type { AgentGroup, AgentPolicy, LinuxAgent } from '../../types'

export function AgentGroupRail({ groups, agents, selectedGroupId, selectGroup, showCreate, setShowCreate, createGroup, policies, saving }: {
  groups: AgentGroup[]
  agents: LinuxAgent[]
  selectedGroupId: string
  selectGroup: (groupId: string) => void
  showCreate: boolean
  setShowCreate: (value: boolean) => void
  createGroup: (event: FormEvent<HTMLFormElement>) => void
  policies: AgentPolicy[]
  saving: boolean
}) {
  const activeAgents = agents.filter(agent => !agent.revoked_at)
  return <aside className="min-w-0 overflow-hidden border-b border-stone-200 bg-[#f7f3eb] lg:min-h-[690px] lg:border-b-0 lg:border-r" aria-label="Agent groups">
    <div className="flex items-center justify-between border-b border-stone-200 px-4 py-4">
      <div><p className="section-label">Fleet scope</p><p className="mt-1 text-xs text-stone-500">{groups.length} groups</p></div>
      <button className="icon-button" onClick={() => setShowCreate(!showCreate)} aria-label="Create group"><Plus size={15} /></button>
    </div>
    {showCreate && <form className="grid min-w-0 gap-3 border-b border-stone-200 bg-[#f7f3eb] p-4" onSubmit={createGroup}>
      <label className="form-field">Group name<input name="name" required placeholder="Database servers" /></label>
      <label className="form-field">Description<input name="description" placeholder="Production database fleet" /></label>
      <label className="form-field">Initial policy<select name="policy_id" className="select-input w-full" required>{policies.map(policy => <option key={policy.id} value={policy.id}>{policy.name}</option>)}</select></label>
      <button className="button-primary min-h-9" disabled={saving || !policies.length}>Create group</button>
    </form>}
    <nav className="flex gap-2 overflow-x-auto p-3 lg:block lg:space-y-1" aria-label="Fleet groups">
      <button className={`group-scope-item min-w-48 lg:min-w-0 ${selectedGroupId === 'all' ? 'group-scope-item-active' : ''}`} onClick={() => selectGroup('all')}>
        <span className="group-scope-icon"><UsersThree size={17} /></span><span className="min-w-0 flex-1 text-left"><strong>All Agents</strong><small>Every Managed Linux Agent</small></span><span className="font-mono text-[10px] text-stone-500">{activeAgents.length}</span>
      </button>
      <div className="hidden px-3 pb-2 pt-5 lg:block"><span className="section-label">Groups</span></div>
      {groups.map(group => { const count = activeAgents.filter(agent => agent.group_id === group.id).length; return <button key={group.id} className={`group-scope-item min-w-48 lg:min-w-0 ${selectedGroupId === group.id ? 'group-scope-item-active' : ''}`} onClick={() => selectGroup(group.id)}><span className="group-scope-icon"><FolderSimple size={17} /></span><span className="min-w-0 flex-1 text-left"><strong>{group.name}</strong><small>{group.policy_name} · v{group.policy_version}</small></span><span className="font-mono text-[10px] text-stone-500">{count}</span></button> })}
    </nav>
  </aside>
}
