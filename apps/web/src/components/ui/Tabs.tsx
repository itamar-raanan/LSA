import type { ButtonHTMLAttributes, ReactNode } from 'react'
import { Link, type LinkProps } from 'react-router-dom'
import { cn } from '../../lib/utils'

export function TabList({ children, label, className }: { children: ReactNode; label: string; className?: string }) {
  return <nav className={cn('ui-tab-list', className)} aria-label={label}>{children}</nav>
}

export function TabButton({ active, className, children, ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { active?: boolean }) {
  return <button type="button" className={cn('ui-tab', active && 'ui-tab-active', className)} aria-current={active ? 'page' : undefined} {...props}>{children}</button>
}

export function TabLink({ active, className, children, ...props }: LinkProps & { active?: boolean }) {
  return <Link className={cn('ui-tab', active && 'ui-tab-active', className)} aria-current={active ? 'page' : undefined} {...props}>{children}</Link>
}
