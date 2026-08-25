import { DesktopTower, DownloadSimple, FolderSimple, SlidersHorizontal, UsersThree } from '@phosphor-icons/react'
import type { AgentGroup } from '../../types'
import { TabButton, TabList } from '../ui/Tabs'

export type AgentWorkspaceTab = 'hosts' | 'policy' | 'deployment'

export function AgentWorkspaceHeader({ group, activeCount, activeTab, onTabChange }: {
  group: AgentGroup | null
  activeCount: number
  activeTab: AgentWorkspaceTab
  onTabChange: (tab: AgentWorkspaceTab) => void
}) {
  return <header className="border-b border-stone-200 px-5 pt-5 sm:px-7 sm:pt-6">
    <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
      <div>
        <div className="flex items-center gap-2 text-stone-500">{group ? <FolderSimple size={16} /> : <UsersThree size={16} />}<span className="section-label">{group ? 'Agent group' : 'Fleet inventory'}</span></div>
        <h2 className="mt-2 text-xl font-semibold tracking-[-0.025em] text-stone-800">{group?.name ?? 'All Agents'}</h2>
        <p className="mt-1 text-xs leading-5 text-stone-500">{group?.description || (group ? `${group.policy_name} is applied to this group.` : 'Every agent across all policy groups.')}</p>
      </div>
      <div className="flex items-center gap-6 border-l border-stone-200 pl-5">
        <div><strong className="block font-mono text-lg font-medium text-stone-800">{activeCount}</strong><span className="text-[10px] text-stone-600">active hosts</span></div>
        {group && <div><strong className="block font-mono text-lg font-medium text-stone-800">v{group.policy_version}</strong><span className="text-[10px] text-stone-600">policy version</span></div>}
      </div>
    </div>
    <TabList label="Group Workspace" className="mb-0 mt-6">
      <TabButton active={activeTab === 'hosts'} onClick={() => onTabChange('hosts')}><DesktopTower size={15} /> Hosts</TabButton>
      {group && <TabButton active={activeTab === 'policy'} onClick={() => onTabChange('policy')}><SlidersHorizontal size={15} /> Policy</TabButton>}
      <TabButton active={activeTab === 'deployment'} onClick={() => onTabChange('deployment')}><DownloadSimple size={15} /> Deployment</TabButton>
    </TabList>
  </header>
}
