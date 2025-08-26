import React from 'react'
import { clsx } from 'clsx'
import { ValidationState } from '../../../hooks/useValidation'

/**
 * Validation state type for visual feedback
 */
export type ValidationStateType = 'error' | 'warning' | 'success' | 'default'

/**
 * Input component props
 */
export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  error?: string
  label?: string
  helperText?: string
  validationState?: ValidationState
  showValidationIcon?: boolean
  'aria-describedby'?: string
}

/**
 * Get validation state type from validation state
 */
function getValidationStateType(validationState?: ValidationState, error?: string): ValidationStateType {
  if (error || validationState?.error) return 'error'
  if (validationState?.warning) return 'warning'
  if (validationState?.success) return 'success'
  return 'default'
}

/**
 * Get validation icon based on state
 */
function getValidationIcon(stateType: ValidationStateType): JSX.Element | null {
  switch (stateType) {
    case 'success':
      return (
        <svg
          className="w-4 h-4 text-green-500"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          aria-hidden="true"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
        </svg>
      )
    case 'error':
      return (
        <svg
          className="w-4 h-4 text-red-500"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          aria-hidden="true"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
        </svg>
      )
    case 'warning':
      return (
        <svg
          className="w-4 h-4 text-yellow-500"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          aria-hidden="true"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
        </svg>
      )
    default:
      return null
  }
}

/**
 * Input component with label, error handling, and real-time validation
 */
export const Input = React.forwardRef<HTMLInputElement, InputProps>(
  ({
    className,
    type = 'text',
    error,
    label,
    helperText,
    id,
    validationState,
    showValidationIcon = true,
    'aria-describedby': ariaDescribedBy,
    ...props
  }, ref) => {
    const inputId = id || `input-${Math.random().toString(36).substr(2, 9)}`
    const errorId = `${inputId}-error`
    const helperTextId = `${inputId}-helper`

    const stateType = getValidationStateType(validationState, error)
    const validationIcon = showValidationIcon ? getValidationIcon(stateType) : null

    // Determine the message to display
    const displayError = error || validationState?.error
    const displayWarning = validationState?.warning
    const displaySuccess = validationState?.success
    const displayHelper = helperText && !displayError && !displayWarning && !displaySuccess

    // Build aria-describedby
    const describedByIds = []
    if (ariaDescribedBy) describedByIds.push(ariaDescribedBy)
    if (displayError) describedByIds.push(errorId)
    else if (displayHelper) describedByIds.push(helperTextId)

    return (
      <div className="space-y-2">
        {label && (
          <label
            htmlFor={inputId}
            className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70"
          >
            {label}
          </label>
        )}
        <div className="relative">
          <input
            type={type}
            id={inputId}
            className={clsx(
              'flex h-10 w-full rounded-md border bg-background px-3 py-2 text-sm',
              'ring-offset-background file:border-0 file:bg-transparent file:text-sm file:font-medium',
              'placeholder:text-muted-foreground',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2',
              'disabled:cursor-not-allowed disabled:opacity-50',
              // Validation state styling
              stateType === 'error' && 'border-red-500 focus-visible:ring-red-500',
              stateType === 'warning' && 'border-yellow-500 focus-visible:ring-yellow-500',
              stateType === 'success' && 'border-green-500 focus-visible:ring-green-500',
              stateType === 'default' && 'border-input focus-visible:ring-ring',
              // Add padding for icon if present
              validationIcon && 'pr-10',
              className
            )}
            aria-invalid={stateType === 'error'}
            aria-describedby={describedByIds.length > 0 ? describedByIds.join(' ') : undefined}
            ref={ref}
            {...props}
          />
          {validationIcon && (
            <div className="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none">
              {validationIcon}
            </div>
          )}
        </div>

        {/* Error message */}
        {displayError && (
          <p
            id={errorId}
            className="text-sm text-red-600 dark:text-red-400"
            role="alert"
            aria-live="polite"
          >
            {displayError}
          </p>
        )}

        {/* Warning message */}
        {displayWarning && !displayError && (
          <p
            className="text-sm text-yellow-600 dark:text-yellow-400"
            role="alert"
            aria-live="polite"
          >
            {displayWarning}
          </p>
        )}

        {/* Success message */}
        {displaySuccess && !displayError && !displayWarning && (
          <p
            className="text-sm text-green-600 dark:text-green-400"
            aria-live="polite"
          >
            {displaySuccess}
          </p>
        )}

        {/* Helper text */}
        {displayHelper && (
          <p
            id={helperTextId}
            className="text-sm text-muted-foreground"
          >
            {helperText}
          </p>
        )}
      </div>
    )
  }
)

Input.displayName = 'Input'
