import React from 'react'
import { clsx } from 'clsx'
import { AlertCircle, CheckCircle, Info, XCircle } from 'lucide-react'

/**
 * Alert variant types
 */
export type AlertVariant = 'default' | 'success' | 'warning' | 'error' | 'info'

/**
 * Alert component props
 */
export interface AlertProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: AlertVariant
  title?: string
  children: React.ReactNode
  onClose?: () => void
  dismissible?: boolean
}

/**
 * Alert component for displaying notifications and messages
 */
export const Alert = React.forwardRef<HTMLDivElement, AlertProps>(
  (
    { className, variant = 'default', title, children, onClose, dismissible = false, ...props },
    ref
  ) => {
    const baseClasses = ['relative w-full rounded-lg border p-4', 'flex items-start gap-3']

    const variantClasses = {
      default: 'bg-background text-foreground border-border',
      success:
        'bg-green-50 text-green-800 border-green-200 dark:bg-green-950 dark:text-green-200 dark:border-green-800',
      warning:
        'bg-yellow-50 text-yellow-800 border-yellow-200 dark:bg-yellow-950 dark:text-yellow-200 dark:border-yellow-800',
      error:
        'bg-red-50 text-red-800 border-red-200 dark:bg-red-950 dark:text-red-200 dark:border-red-800',
      info: 'bg-blue-50 text-blue-800 border-blue-200 dark:bg-blue-950 dark:text-blue-200 dark:border-blue-800',
    }

    const iconMap = {
      default: Info,
      success: CheckCircle,
      warning: AlertCircle,
      error: XCircle,
      info: Info,
    }

    const Icon = iconMap[variant]

    return (
      <div
        ref={ref}
        role="alert"
        className={clsx(baseClasses, variantClasses[variant], className)}
        {...props}
      >
        <Icon className="h-5 w-5 flex-shrink-0 mt-0.5" />
        <div className="flex-1 min-w-0">
          {title && <h5 className="mb-1 font-medium leading-none tracking-tight">{title}</h5>}
          <div className="text-sm [&_p]:leading-relaxed">{children}</div>
        </div>
        {dismissible && onClose && (
          <button
            onClick={onClose}
            className="flex-shrink-0 ml-auto -mx-1.5 -my-1.5 rounded-lg p-1.5 hover:bg-black/5 dark:hover:bg-white/5 transition-colors"
            aria-label="Close alert"
          >
            <XCircle className="h-4 w-4" />
          </button>
        )}
      </div>
    )
  }
)

Alert.displayName = 'Alert'

/**
 * Alert title component
 */
export interface AlertTitleProps extends React.HTMLAttributes<HTMLHeadingElement> {
  children: React.ReactNode
}

export const AlertTitle = React.forwardRef<HTMLParagraphElement, AlertTitleProps>(
  ({ className, children, ...props }, ref) => (
    <h5
      ref={ref}
      className={clsx('mb-1 font-medium leading-none tracking-tight', className)}
      {...props}
    >
      {children}
    </h5>
  )
)

AlertTitle.displayName = 'AlertTitle'

/**
 * Alert description component
 */
export interface AlertDescriptionProps extends React.HTMLAttributes<HTMLParagraphElement> {
  children: React.ReactNode
}

export const AlertDescription = React.forwardRef<HTMLParagraphElement, AlertDescriptionProps>(
  ({ className, children, ...props }, ref) => (
    <div ref={ref} className={clsx('text-sm [&_p]:leading-relaxed', className)} {...props}>
      {children}
    </div>
  )
)

AlertDescription.displayName = 'AlertDescription'
