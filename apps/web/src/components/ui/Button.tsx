import { Slot } from '@radix-ui/react-slot'
import { cva, type VariantProps } from 'class-variance-authority'
import type { ButtonHTMLAttributes } from 'react'
import { cn } from '../../lib/utils'

const buttonVariants = cva(
  'soc-button inline-flex items-center justify-center gap-2 whitespace-nowrap font-semibold outline-none disabled:pointer-events-none disabled:opacity-45',
  {
    variants: {
      variant: {
        primary: 'soc-button-primary',
        secondary: 'soc-button-secondary',
        ghost: 'soc-button-ghost',
        danger: 'soc-button-danger',
        success: 'soc-button-success',
      },
      size: {
        sm: 'h-[34px] px-3 text-[11px]',
        md: 'h-[34px] px-3.5 text-[11px]',
        lg: 'h-[34px] px-4 text-[11px]',
        iconSm: 'size-[34px] p-0',
        icon: 'size-[34px] p-0',
      },
    },
    defaultVariants: { variant: 'secondary', size: 'md' },
  },
)

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & VariantProps<typeof buttonVariants> & { asChild?: boolean }

export function Button({ className, variant, size, asChild, ...props }: ButtonProps) {
  const Component = asChild ? Slot : 'button'
  return <Component className={cn(buttonVariants({ variant, size }), className)} {...props} />
}
