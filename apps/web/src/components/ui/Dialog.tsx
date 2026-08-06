import * as DialogPrimitive from '@radix-ui/react-dialog'
import { X } from 'lucide-react'
import type { ReactNode } from 'react'
import { cn } from '../../lib/utils'
import { Button } from './Button'

interface DialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  eyebrow?: string
  title: string
  description?: string
  children: ReactNode
  size?: 'md' | 'lg'
}

export function Dialog({ open, onOpenChange, eyebrow, title, description, children, size = 'md' }: DialogProps) {
  return (
    <DialogPrimitive.Root open={open} onOpenChange={onOpenChange}>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className="ui-dialog-overlay" />
        <DialogPrimitive.Content className={cn('ui-dialog-content', size === 'lg' && 'ui-dialog-content-lg')}>
          <header className="ui-dialog-header">
            <div className="min-w-0">
              {eyebrow && <p className="section-label">{eyebrow}</p>}
              <DialogPrimitive.Title className="ui-dialog-title">{title}</DialogPrimitive.Title>
              {description && <DialogPrimitive.Description className="ui-dialog-description">{description}</DialogPrimitive.Description>}
            </div>
            <DialogPrimitive.Close asChild>
              <Button variant="ghost" size="icon" aria-label={`Close ${title}`}><X size={17} /></Button>
            </DialogPrimitive.Close>
          </header>
          <div className="ui-dialog-body">{children}</div>
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  )
}
