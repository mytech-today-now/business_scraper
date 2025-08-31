import React from 'react'
import { clsx } from 'clsx'

/**
 * Spinner size types
 */
export type SpinnerSize = 'xs' | 'sm' | 'md' | 'lg' | 'xl'

/**
 * Spinner variant types
 */
export type SpinnerVariant = 'default' | 'primary' | 'secondary' | 'success' | 'warning' | 'error'

/**
 * Spinner component props
 */
export interface SpinnerProps extends React.HTMLAttributes<HTMLDivElement> {
  size?: SpinnerSize
  variant?: SpinnerVariant
  label?: string
  showLabel?: boolean
}

/**
 * Spinner component for loading states
 */
export const Spinner = React.forwardRef<HTMLDivElement, SpinnerProps>(
  (
    {
      className,
      size = 'md',
      variant = 'default',
      label = 'Loading...',
      showLabel = false,
      ...props
    },
    ref
  ) => {
    const sizeClasses = {
      xs: 'h-3 w-3',
      sm: 'h-4 w-4',
      md: 'h-6 w-6',
      lg: 'h-8 w-8',
      xl: 'h-12 w-12',
    }

    const variantClasses = {
      default: 'border-gray-200 border-t-gray-600 dark:border-gray-700 dark:border-t-gray-300',
      primary: 'border-blue-200 border-t-blue-600 dark:border-blue-800 dark:border-t-blue-400',
      secondary: 'border-gray-200 border-t-gray-500 dark:border-gray-700 dark:border-t-gray-400',
      success: 'border-green-200 border-t-green-600 dark:border-green-800 dark:border-t-green-400',
      warning:
        'border-yellow-200 border-t-yellow-600 dark:border-yellow-800 dark:border-t-yellow-400',
      error: 'border-red-200 border-t-red-600 dark:border-red-800 dark:border-t-red-400',
    }

    const labelSizeClasses = {
      xs: 'text-xs',
      sm: 'text-sm',
      md: 'text-sm',
      lg: 'text-base',
      xl: 'text-lg',
    }

    return (
      <div
        ref={ref}
        className={clsx('inline-flex items-center gap-2', className)}
        role="status"
        aria-label={label}
        {...props}
      >
        <div
          className={clsx(
            'animate-spin rounded-full border-2 border-solid border-current border-t-transparent',
            sizeClasses[size],
            variantClasses[variant]
          )}
        />
        {showLabel && (
          <span className={clsx('text-muted-foreground', labelSizeClasses[size])}>{label}</span>
        )}
        <span className="sr-only">{label}</span>
      </div>
    )
  }
)

Spinner.displayName = 'Spinner'

/**
 * Full page spinner overlay component
 */
export interface SpinnerOverlayProps {
  isVisible: boolean
  label?: string
  backdrop?: boolean
  size?: SpinnerSize
  variant?: SpinnerVariant
}

export const SpinnerOverlay: React.FC<SpinnerOverlayProps> = ({
  isVisible,
  label = 'Loading...',
  backdrop = true,
  size = 'lg',
  variant = 'primary',
}) => {
  if (!isVisible) return null

  return (
    <div
      className={clsx(
        'fixed inset-0 z-50 flex items-center justify-center',
        backdrop && 'bg-background/80 backdrop-blur-sm'
      )}
      role="dialog"
      aria-modal="true"
      aria-label={label}
    >
      <div className="flex flex-col items-center gap-4 p-6 rounded-lg bg-card border shadow-lg">
        <Spinner size={size} variant={variant} />
        <p className="text-sm text-muted-foreground font-medium">{label}</p>
      </div>
    </div>
  )
}

SpinnerOverlay.displayName = 'SpinnerOverlay'

/**
 * Inline spinner for buttons and small spaces
 */
export interface InlineSpinnerProps extends Omit<SpinnerProps, 'showLabel'> {
  className?: string
}

export const InlineSpinner: React.FC<InlineSpinnerProps> = ({
  size = 'sm',
  variant = 'default',
  className,
  ...props
}) => {
  return (
    <Spinner size={size} variant={variant} className={clsx('inline-block', className)} {...props} />
  )
}

InlineSpinner.displayName = 'InlineSpinner'
