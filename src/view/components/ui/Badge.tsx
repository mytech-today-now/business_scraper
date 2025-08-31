import React from 'react'
import { clsx } from 'clsx'
import { X } from 'lucide-react'

/**
 * Badge variant types
 */
export type BadgeVariant =
  | 'default'
  | 'primary'
  | 'secondary'
  | 'success'
  | 'warning'
  | 'error'
  | 'outline'

/**
 * Badge size types
 */
export type BadgeSize = 'sm' | 'md' | 'lg'

/**
 * Badge component props
 */
export interface BadgeProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: BadgeVariant
  size?: BadgeSize
  children: React.ReactNode
  removable?: boolean
  onRemove?: () => void
}

/**
 * Badge component for labels, tags, and status indicators
 */
export const Badge = React.forwardRef<HTMLDivElement, BadgeProps>(
  (
    {
      className,
      variant = 'default',
      size = 'md',
      children,
      removable = false,
      onRemove,
      ...props
    },
    ref
  ) => {
    const baseClasses = [
      'inline-flex items-center gap-1 rounded-full font-medium',
      'transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2',
    ]

    const variantClasses = {
      default: 'bg-primary text-primary-foreground hover:bg-primary/80',
      primary:
        'bg-blue-100 text-blue-800 hover:bg-blue-200 dark:bg-blue-900 dark:text-blue-200 dark:hover:bg-blue-800',
      secondary: 'bg-secondary text-secondary-foreground hover:bg-secondary/80',
      success:
        'bg-green-100 text-green-800 hover:bg-green-200 dark:bg-green-900 dark:text-green-200 dark:hover:bg-green-800',
      warning:
        'bg-yellow-100 text-yellow-800 hover:bg-yellow-200 dark:bg-yellow-900 dark:text-yellow-200 dark:hover:bg-yellow-800',
      error:
        'bg-red-100 text-red-800 hover:bg-red-200 dark:bg-red-900 dark:text-red-200 dark:hover:bg-red-800',
      outline: 'border border-input bg-background hover:bg-accent hover:text-accent-foreground',
    }

    const sizeClasses = {
      sm: 'px-2 py-0.5 text-xs',
      md: 'px-2.5 py-0.5 text-sm',
      lg: 'px-3 py-1 text-sm',
    }

    const removeSizeClasses = {
      sm: 'h-3 w-3',
      md: 'h-3.5 w-3.5',
      lg: 'h-4 w-4',
    }

    return (
      <div
        ref={ref}
        className={clsx(baseClasses, variantClasses[variant], sizeClasses[size], className)}
        {...props}
      >
        <span className="truncate">{children}</span>
        {removable && onRemove && (
          <button
            onClick={e => {
              e.stopPropagation()
              onRemove()
            }}
            className="ml-1 rounded-full hover:bg-black/10 dark:hover:bg-white/10 transition-colors"
            aria-label="Remove badge"
          >
            <X className={clsx('flex-shrink-0', removeSizeClasses[size])} />
          </button>
        )}
      </div>
    )
  }
)

Badge.displayName = 'Badge'

/**
 * Status badge component for specific status indicators
 */
export interface StatusBadgeProps extends Omit<BadgeProps, 'variant'> {
  status: 'active' | 'inactive' | 'pending' | 'completed' | 'failed' | 'cancelled'
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, children, ...props }) => {
  const statusVariantMap = {
    active: 'success' as BadgeVariant,
    inactive: 'secondary' as BadgeVariant,
    pending: 'warning' as BadgeVariant,
    completed: 'success' as BadgeVariant,
    failed: 'error' as BadgeVariant,
    cancelled: 'secondary' as BadgeVariant,
  }

  const statusLabels = {
    active: 'Active',
    inactive: 'Inactive',
    pending: 'Pending',
    completed: 'Completed',
    failed: 'Failed',
    cancelled: 'Cancelled',
  }

  return (
    <Badge variant={statusVariantMap[status]} {...props}>
      {children || statusLabels[status]}
    </Badge>
  )
}

StatusBadge.displayName = 'StatusBadge'

/**
 * Count badge component for numerical indicators
 */
export interface CountBadgeProps extends Omit<BadgeProps, 'children'> {
  count: number
  max?: number
  showZero?: boolean
}

export const CountBadge: React.FC<CountBadgeProps> = ({
  count,
  max = 99,
  showZero = false,
  ...props
}) => {
  if (count === 0 && !showZero) {
    return null
  }

  const displayCount = count > max ? `${max}+` : count.toString()

  return <Badge {...props}>{displayCount}</Badge>
}

CountBadge.displayName = 'CountBadge'

/**
 * Dot badge component for simple indicators
 */
export interface DotBadgeProps extends Omit<BadgeProps, 'children' | 'size'> {
  size?: 'sm' | 'md' | 'lg'
}

export const DotBadge: React.FC<DotBadgeProps> = ({ size = 'md', className, ...props }) => {
  const dotSizeClasses = {
    sm: 'h-2 w-2',
    md: 'h-3 w-3',
    lg: 'h-4 w-4',
  }

  return <div className={clsx('rounded-full', dotSizeClasses[size], className)} {...props} />
}

DotBadge.displayName = 'DotBadge'
