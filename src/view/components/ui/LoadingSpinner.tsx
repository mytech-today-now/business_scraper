import React from 'react'
import { clsx } from 'clsx'

/**
 * Loading spinner component props
 */
export interface LoadingSpinnerProps {
  size?: 'sm' | 'md' | 'lg' | 'xl'
  variant?: 'default' | 'primary' | 'secondary' | 'success' | 'warning' | 'error'
  className?: string
  label?: string
  showLabel?: boolean
}

/**
 * Loading spinner component with multiple sizes and variants
 */
export const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({
  size = 'md',
  variant = 'default',
  className,
  label = 'Loading...',
  showLabel = false,
}) => {
  const sizeClasses = {
    sm: 'h-4 w-4',
    md: 'h-6 w-6',
    lg: 'h-8 w-8',
    xl: 'h-12 w-12',
  }

  const variantClasses = {
    default: 'border-gray-300 border-t-gray-600',
    primary: 'border-blue-200 border-t-blue-600',
    secondary: 'border-gray-200 border-t-gray-500',
    success: 'border-green-200 border-t-green-600',
    warning: 'border-yellow-200 border-t-yellow-600',
    error: 'border-red-200 border-t-red-600',
  }

  const labelSizeClasses = {
    sm: 'text-xs',
    md: 'text-sm',
    lg: 'text-base',
    xl: 'text-lg',
  }

  return (
    <div className={clsx('flex items-center justify-center', className)}>
      <div className="flex flex-col items-center space-y-2">
        <div
          className={clsx(
            'animate-spin rounded-full border-2',
            sizeClasses[size],
            variantClasses[variant]
          )}
          role="status"
          aria-label={label}
        />
        {showLabel && (
          <span
            className={clsx(
              'text-muted-foreground',
              labelSizeClasses[size]
            )}
          >
            {label}
          </span>
        )}
      </div>
    </div>
  )
}

LoadingSpinner.displayName = 'LoadingSpinner'

/**
 * Loading overlay component props
 */
export interface LoadingOverlayProps {
  isLoading: boolean
  children: React.ReactNode
  loadingText?: string
  className?: string
  overlayClassName?: string
  spinnerSize?: LoadingSpinnerProps['size']
  spinnerVariant?: LoadingSpinnerProps['variant']
}

/**
 * Loading overlay component that shows a spinner over content
 */
export const LoadingOverlay: React.FC<LoadingOverlayProps> = ({
  isLoading,
  children,
  loadingText = 'Loading...',
  className,
  overlayClassName,
  spinnerSize = 'lg',
  spinnerVariant = 'primary',
}) => {
  return (
    <div className={clsx('relative', className)}>
      {children}
      {isLoading && (
        <div
          className={clsx(
            'absolute inset-0 bg-background/80 backdrop-blur-sm',
            'flex items-center justify-center z-50',
            overlayClassName
          )}
        >
          <LoadingSpinner
            size={spinnerSize}
            variant={spinnerVariant}
            label={loadingText}
            showLabel={true}
          />
        </div>
      )}
    </div>
  )
}

LoadingOverlay.displayName = 'LoadingOverlay'

/**
 * Loading skeleton component props
 */
export interface LoadingSkeletonProps {
  className?: string
  width?: string | number
  height?: string | number
  variant?: 'text' | 'rectangular' | 'circular'
  animation?: 'pulse' | 'wave' | 'none'
}

/**
 * Loading skeleton component for placeholder content
 */
export const LoadingSkeleton: React.FC<LoadingSkeletonProps> = ({
  className,
  width,
  height,
  variant = 'rectangular',
  animation = 'pulse',
}) => {
  const variantClasses = {
    text: 'rounded',
    rectangular: 'rounded-md',
    circular: 'rounded-full',
  }

  const animationClasses = {
    pulse: 'animate-pulse',
    wave: 'animate-pulse', // Could be enhanced with custom wave animation
    none: '',
  }

  const style: React.CSSProperties = {}
  if (width) style.width = typeof width === 'number' ? `${width}px` : width
  if (height) style.height = typeof height === 'number' ? `${height}px` : height

  return (
    <div
      className={clsx(
        'bg-muted',
        variantClasses[variant],
        animationClasses[animation],
        className
      )}
      style={style}
      role="status"
      aria-label="Loading content"
    />
  )
}

LoadingSkeleton.displayName = 'LoadingSkeleton'

/**
 * Loading dots component for inline loading states
 */
export interface LoadingDotsProps {
  className?: string
  dotClassName?: string
  size?: 'sm' | 'md' | 'lg'
}

export const LoadingDots: React.FC<LoadingDotsProps> = ({
  className,
  dotClassName,
  size = 'md',
}) => {
  const sizeClasses = {
    sm: 'h-1 w-1',
    md: 'h-2 w-2',
    lg: 'h-3 w-3',
  }

  return (
    <div className={clsx('flex space-x-1', className)} role="status" aria-label="Loading">
      {[0, 1, 2].map((index) => (
        <div
          key={index}
          className={clsx(
            'bg-current rounded-full animate-pulse',
            sizeClasses[size],
            dotClassName
          )}
          style={{
            animationDelay: `${index * 0.2}s`,
            animationDuration: '1s',
          }}
        />
      ))}
    </div>
  )
}

LoadingDots.displayName = 'LoadingDots'

/**
 * Loading button component that shows loading state
 */
export interface LoadingButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  isLoading?: boolean
  loadingText?: string
  children: React.ReactNode
  variant?: 'default' | 'primary' | 'secondary' | 'outline' | 'ghost'
  size?: 'sm' | 'md' | 'lg'
}

export const LoadingButton = React.forwardRef<HTMLButtonElement, LoadingButtonProps>(
  (
    {
      isLoading = false,
      loadingText,
      children,
      className,
      disabled,
      variant = 'default',
      size = 'md',
      ...props
    },
    ref
  ) => {
    const baseClasses = [
      'inline-flex items-center justify-center rounded-md font-medium',
      'transition-colors focus-visible:outline-none focus-visible:ring-2',
      'focus-visible:ring-ring focus-visible:ring-offset-2',
      'disabled:pointer-events-none disabled:opacity-50',
    ]

    const variantClasses = {
      default: 'bg-primary text-primary-foreground hover:bg-primary/90',
      primary: 'bg-blue-600 text-white hover:bg-blue-700',
      secondary: 'bg-secondary text-secondary-foreground hover:bg-secondary/80',
      outline: 'border border-input bg-background hover:bg-accent hover:text-accent-foreground',
      ghost: 'hover:bg-accent hover:text-accent-foreground',
    }

    const sizeClasses = {
      sm: 'h-8 px-3 text-xs',
      md: 'h-10 px-4 py-2 text-sm',
      lg: 'h-11 px-8 text-base',
    }

    return (
      <button
        ref={ref}
        className={clsx(
          baseClasses,
          variantClasses[variant],
          sizeClasses[size],
          className
        )}
        disabled={disabled || isLoading}
        {...props}
      >
        {isLoading && (
          <LoadingSpinner
            size={size === 'sm' ? 'sm' : 'md'}
            variant="default"
            className="mr-2"
          />
        )}
        {isLoading ? loadingText || 'Loading...' : children}
      </button>
    )
  }
)

LoadingButton.displayName = 'LoadingButton'
