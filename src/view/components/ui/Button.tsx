import React from 'react'
import { clsx } from 'clsx'
import { LucideIcon } from 'lucide-react'

/**
 * Button variant types
 */
export type ButtonVariant = 'default' | 'destructive' | 'outline' | 'secondary' | 'ghost' | 'link'

/**
 * Button size types
 */
export type ButtonSize = 'default' | 'sm' | 'lg' | 'icon'

/**
 * Button component props
 */
export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant
  size?: ButtonSize
  icon?: LucideIcon
  iconPosition?: 'left' | 'right'
  loading?: boolean
  children?: React.ReactNode
}

/**
 * Button component with multiple variants and sizes
 */
export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ 
    className, 
    variant = 'default', 
    size = 'default', 
    icon: Icon,
    iconPosition = 'left',
    loading = false,
    disabled,
    children, 
    ...props 
  }, ref) => {
    const baseClasses = [
      'inline-flex items-center justify-center rounded-md text-sm font-medium',
      'ring-offset-background transition-colors',
      'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2',
      'disabled:pointer-events-none disabled:opacity-50',
    ]

    const variantClasses = {
      default: 'bg-primary text-primary-foreground hover:bg-primary/90',
      destructive: 'bg-destructive text-destructive-foreground hover:bg-destructive/90',
      outline: 'border border-input bg-background hover:bg-accent hover:text-accent-foreground',
      secondary: 'bg-secondary text-secondary-foreground hover:bg-secondary/80',
      ghost: 'hover:bg-accent hover:text-accent-foreground',
      link: 'text-primary underline-offset-4 hover:underline',
    }

    const sizeClasses = {
      default: 'h-10 px-4 py-2',
      sm: 'h-9 rounded-md px-3',
      lg: 'h-11 rounded-md px-8',
      icon: 'h-10 w-10',
    }

    const iconClasses = {
      left: 'mr-2 h-4 w-4',
      right: 'ml-2 h-4 w-4',
    }

    return (
      <button
        className={clsx(
          baseClasses,
          variantClasses[variant],
          sizeClasses[size],
          className
        )}
        ref={ref}
        disabled={disabled || loading}
        {...props}
      >
        {loading && (
          <div className="mr-2 h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" />
        )}
        {Icon && iconPosition === 'left' && !loading && (
          <Icon className={iconClasses.left} />
        )}
        {children}
        {Icon && iconPosition === 'right' && !loading && (
          <Icon className={iconClasses.right} />
        )}
      </button>
    )
  }
)

Button.displayName = 'Button'
