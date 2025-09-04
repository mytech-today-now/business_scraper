import React from 'react'
import { clsx } from 'clsx'
import { createCSPSafeStyle } from '@/lib/cspUtils'

/**
 * Progress bar variant types
 */
export type ProgressVariant = 'default' | 'success' | 'warning' | 'error' | 'info'

/**
 * Progress bar size types
 */
export type ProgressSize = 'sm' | 'md' | 'lg'

/**
 * Progress bar component props
 */
export interface ProgressBarProps extends React.HTMLAttributes<HTMLDivElement> {
  value: number
  max?: number
  variant?: ProgressVariant
  size?: ProgressSize
  showLabel?: boolean
  label?: string
  animated?: boolean
  striped?: boolean
}

/**
 * Progress bar component for displaying progress and usage indicators
 */
export const ProgressBar = React.forwardRef<HTMLDivElement, ProgressBarProps>(
  (
    {
      className,
      value,
      max = 100,
      variant = 'default',
      size = 'md',
      showLabel = false,
      label,
      animated = false,
      striped = false,
      ...props
    },
    ref
  ) => {
    // Ensure value is within bounds
    const normalizedValue = Math.max(0, Math.min(value, max))
    const percentage = (normalizedValue / max) * 100

    const baseClasses = ['relative overflow-hidden rounded-full bg-secondary']

    const sizeClasses = {
      sm: 'h-1',
      md: 'h-2',
      lg: 'h-3',
    }

    const variantClasses = {
      default: 'bg-primary',
      success: 'bg-green-500',
      warning: 'bg-yellow-500',
      error: 'bg-red-500',
      info: 'bg-blue-500',
    }

    const stripedClasses = striped
      ? 'bg-gradient-to-r from-transparent via-white/20 to-transparent bg-[length:1rem_1rem]'
      : ''
    const animatedClasses = animated ? 'animate-pulse' : ''

    return (
      <div className="w-full">
        {showLabel && (
          <div className="flex justify-between items-center mb-1">
            <span className="text-sm font-medium text-gray-700 dark:text-gray-300">{label}</span>
            <span className="text-sm text-gray-500 dark:text-gray-400">
              {Math.round(percentage)}%
            </span>
          </div>
        )}
        <div
          ref={ref}
          className={clsx(baseClasses, sizeClasses[size], className)}
          role="progressbar"
          aria-valuenow={normalizedValue}
          aria-valuemin={0}
          aria-valuemax={max}
          aria-label={label}
          {...props}
        >
          <div
            className={clsx(
              'h-full transition-all duration-300 ease-in-out',
              variantClasses[variant],
              stripedClasses,
              animatedClasses
            )}
            style={createCSPSafeStyle({ width: `${percentage}%` })}
          />
        </div>
      </div>
    )
  }
)

ProgressBar.displayName = 'ProgressBar'

/**
 * Circular progress component props
 */
export interface CircularProgressProps extends React.HTMLAttributes<HTMLDivElement> {
  value: number
  max?: number
  size?: number
  strokeWidth?: number
  variant?: ProgressVariant
  showLabel?: boolean
  label?: string
}

/**
 * Circular progress component
 */
export const CircularProgress = React.forwardRef<HTMLDivElement, CircularProgressProps>(
  (
    {
      className,
      value,
      max = 100,
      size = 40,
      strokeWidth = 4,
      variant = 'default',
      showLabel = false,
      label,
      ...props
    },
    ref
  ) => {
    const normalizedValue = Math.max(0, Math.min(value, max))
    const percentage = (normalizedValue / max) * 100

    const radius = (size - strokeWidth) / 2
    const circumference = radius * 2 * Math.PI
    const strokeDasharray = circumference
    const strokeDashoffset = circumference - (percentage / 100) * circumference

    const variantColors = {
      default: 'stroke-primary',
      success: 'stroke-green-500',
      warning: 'stroke-yellow-500',
      error: 'stroke-red-500',
      info: 'stroke-blue-500',
    }

    return (
      <div
        ref={ref}
        className={clsx('relative inline-flex items-center justify-center', className)}
        {...props}
      >
        <svg width={size} height={size} className="transform -rotate-90">
          {/* Background circle */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke="currentColor"
            strokeWidth={strokeWidth}
            fill="none"
            className="text-gray-200 dark:text-gray-700"
          />
          {/* Progress circle */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            strokeWidth={strokeWidth}
            fill="none"
            strokeDasharray={strokeDasharray}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            className={clsx('transition-all duration-300 ease-in-out', variantColors[variant])}
          />
        </svg>
        {showLabel && (
          <div className="absolute inset-0 flex items-center justify-center">
            <span className="text-xs font-medium">{label || `${Math.round(percentage)}%`}</span>
          </div>
        )}
      </div>
    )
  }
)

CircularProgress.displayName = 'CircularProgress'

/**
 * Multi-step progress component props
 */
export interface MultiStepProgressProps extends React.HTMLAttributes<HTMLDivElement> {
  steps: Array<{
    label: string
    completed: boolean
    current?: boolean
  }>
  variant?: ProgressVariant
}

/**
 * Multi-step progress component
 */
export const MultiStepProgress = React.forwardRef<HTMLDivElement, MultiStepProgressProps>(
  ({ className, steps, variant = 'default', ...props }, ref) => {
    const variantClasses = {
      default: 'bg-primary border-primary text-primary-foreground',
      success: 'bg-green-500 border-green-500 text-white',
      warning: 'bg-yellow-500 border-yellow-500 text-white',
      error: 'bg-red-500 border-red-500 text-white',
      info: 'bg-blue-500 border-blue-500 text-white',
    }

    return (
      <div ref={ref} className={clsx('flex items-center', className)} {...props}>
        {steps.map((step, index) => (
          <React.Fragment key={index}>
            <div className="flex flex-col items-center">
              <div
                className={clsx(
                  'flex items-center justify-center w-8 h-8 rounded-full border-2 text-sm font-medium',
                  step.completed || step.current
                    ? variantClasses[variant]
                    : 'bg-gray-200 border-gray-200 text-gray-500 dark:bg-gray-700 dark:border-gray-700 dark:text-gray-400'
                )}
              >
                {step.completed ? (
                  <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                    <path
                      fillRule="evenodd"
                      d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z"
                      clipRule="evenodd"
                    />
                  </svg>
                ) : (
                  <span>{index + 1}</span>
                )}
              </div>
              <span className="mt-2 text-xs text-center text-gray-600 dark:text-gray-400">
                {step.label}
              </span>
            </div>
            {index < steps.length - 1 && (
              <div
                className={clsx(
                  'flex-1 h-0.5 mx-4',
                  step.completed
                    ? variantClasses[variant].split(' ')[0]
                    : 'bg-gray-200 dark:bg-gray-700'
                )}
              />
            )}
          </React.Fragment>
        ))}
      </div>
    )
  }
)

MultiStepProgress.displayName = 'MultiStepProgress'

/**
 * Usage quota progress component specifically for user dashboard
 */
export interface UsageProgressProps extends React.HTMLAttributes<HTMLDivElement> {
  used: number
  limit: number
  label: string
  variant?: ProgressVariant
}

export const UsageProgress: React.FC<UsageProgressProps> = ({
  used,
  limit,
  label,
  variant = 'default',
  className,
  ...props
}) => {
  const isUnlimited = limit === -1
  const percentage = isUnlimited ? 0 : Math.min((used / limit) * 100, 100)

  // Auto-select variant based on usage
  let autoVariant = variant
  if (variant === 'default' && !isUnlimited) {
    if (percentage >= 90) autoVariant = 'error'
    else if (percentage >= 75) autoVariant = 'warning'
    else autoVariant = 'success'
  }

  const formatUsage = (used: number, limit: number) => {
    if (limit === -1) return `${used} / Unlimited`
    return `${used} / ${limit}`
  }

  return (
    <div className={clsx('space-y-2', className)} {...props}>
      <div className="flex justify-between items-center">
        <span className="text-sm font-medium text-gray-700 dark:text-gray-300">{label}</span>
        <span className="text-sm text-gray-500 dark:text-gray-400">{formatUsage(used, limit)}</span>
      </div>
      <ProgressBar
        value={isUnlimited ? 0 : used}
        max={isUnlimited ? 100 : limit}
        variant={autoVariant}
        size="sm"
      />
      {!isUnlimited && percentage >= 90 && (
        <p className="text-xs text-red-600 dark:text-red-400">
          {percentage >= 100 ? 'Quota exceeded' : 'Approaching quota limit'}
        </p>
      )}
    </div>
  )
}

UsageProgress.displayName = 'UsageProgress'
