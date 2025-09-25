import React from 'react'
import { clsx } from 'clsx'
import { ValidationState } from '../../../hooks/useValidation'

/**
 * Validation state type for visual feedback
 */
export type ValidationStateType = 'error' | 'warning' | 'success' | 'default'

/**
 * Input component props with enhanced accessibility and validation
 */
export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  error?: string
  label?: string
  helperText?: string
  validationState?: ValidationState
  showValidationIcon?: boolean
  'aria-describedby'?: string
  icon?: React.ComponentType<{ className?: string }>
  iconPosition?: 'left' | 'right'
  loading?: boolean
  clearable?: boolean
  onClear?: () => void
}

/**
 * Get validation state type from validation state
 */
function getValidationStateType(
  validationState?: ValidationState,
  error?: string
): ValidationStateType {
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
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M6 18L18 6M6 6l12 12"
          />
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
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"
          />
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
  (
    {
      className,
      type = 'text',
      error,
      label,
      helperText,
      id,
      validationState,
      showValidationIcon = true,
      icon: Icon,
      iconPosition = 'left',
      loading = false,
      clearable = false,
      onClear,
      'aria-describedby': ariaDescribedBy,
      ...props
    },
    ref
  ) => {
    const inputId = id || React.useId()
    const errorId = `${inputId}-error`
    const helperTextId = `${inputId}-helper`
    const [isFocused, setIsFocused] = React.useState(false)

    const stateType = getValidationStateType(validationState, error)
    const validationIcon = showValidationIcon ? getValidationIcon(stateType) : null

    // Determine the message to display
    const displayError = error || validationState?.error
    const displayWarning = validationState?.warning
    const displaySuccess = validationState?.success
    const displayHelper = helperText && !displayError && !displayWarning && !displaySuccess
    const hasValue = props.value !== undefined && props.value !== ''

    // Build aria-describedby
    const describedByIds = []
    if (ariaDescribedBy) describedByIds.push(ariaDescribedBy)
    if (displayError) describedByIds.push(errorId)
    else if (displayHelper) describedByIds.push(helperTextId)

    // Calculate padding based on icons
    const leftPadding = Icon && iconPosition === 'left' ? 'pl-10' : 'px-3'
    const rightPadding = React.useMemo(() => {
      let padding = 'pr-3'
      if (showValidationIcon && stateType !== 'default') padding = 'pr-10'
      if (clearable && hasValue) padding = 'pr-10'
      if (loading) padding = 'pr-10'
      if ((showValidationIcon && stateType !== 'default') && (clearable && hasValue)) padding = 'pr-16'
      return padding
    }, [showValidationIcon, stateType, clearable, hasValue, loading])

    const handleFocus = (e: React.FocusEvent<HTMLInputElement>) => {
      setIsFocused(true)
      props.onFocus?.(e)
    }

    const handleBlur = (e: React.FocusEvent<HTMLInputElement>) => {
      setIsFocused(false)
      props.onBlur?.(e)
    }

    const handleClear = () => {
      onClear?.()
      // Focus the input after clearing
      if (ref && 'current' in ref && ref.current) {
        ref.current.focus()
      }
    }

    return (
      <div className="space-y-2">
        {label && (
          <label
            htmlFor={inputId}
            className={clsx(
              'text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70',
              stateType === 'error' && 'text-red-600',
              stateType === 'success' && 'text-green-600'
            )}
          >
            {label}
            {props.required && <span className="text-red-500 ml-1">*</span>}
            {loading && (
              <span className="ml-2 text-xs text-blue-600">
                <span className="animate-pulse">●</span> Validating...
              </span>
            )}
          </label>
        )}

        <div className="relative">
          {/* Left icon */}
          {Icon && iconPosition === 'left' && (
            <div className="absolute inset-y-0 left-0 flex items-center pl-3 pointer-events-none">
              <Icon className={clsx('h-4 w-4', isFocused ? 'text-ring' : 'text-muted-foreground')} />
            </div>
          )}

          <input
            type={type}
            id={inputId}
            className={clsx(
              'flex h-10 w-full rounded-md border bg-background py-2 text-sm',
              'ring-offset-background file:border-0 file:bg-transparent file:text-sm file:font-medium',
              'placeholder:text-muted-foreground',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2',
              'disabled:cursor-not-allowed disabled:opacity-50',
              'transition-colors duration-200',
              // Dynamic padding
              leftPadding,
              rightPadding,
              // Validation state styling
              stateType === 'error' && 'border-red-500 focus-visible:ring-red-500',
              stateType === 'warning' && 'border-yellow-500 focus-visible:ring-yellow-500',
              stateType === 'success' && 'border-green-500 focus-visible:ring-green-500',
              stateType === 'default' && 'border-input focus-visible:ring-ring',
              className
            )}
            aria-invalid={stateType === 'error'}
            aria-describedby={describedByIds.length > 0 ? describedByIds.join(' ') : undefined}
            onFocus={handleFocus}
            onBlur={handleBlur}
            ref={ref}
            {...props}
          />

          {/* Right side icons container */}
          <div className="absolute inset-y-0 right-0 flex items-center pr-3 space-x-1">
            {/* Loading spinner */}
            {loading && (
              <div className="animate-spin h-4 w-4 border-2 border-blue-600 border-t-transparent rounded-full" />
            )}

            {/* Clear button */}
            {clearable && hasValue && !loading && (
              <button
                type="button"
                onClick={handleClear}
                className="h-4 w-4 text-muted-foreground hover:text-foreground transition-colors"
                aria-label="Clear input"
                tabIndex={-1}
              >
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            )}

            {/* Validation icon */}
            {validationIcon && !loading && (
              <div className="pointer-events-none">
                {validationIcon}
              </div>
            )}

            {/* Right icon */}
            {Icon && iconPosition === 'right' && !loading && (
              <Icon className={clsx('h-4 w-4', isFocused ? 'text-ring' : 'text-muted-foreground')} />
            )}
          </div>
        </div>

        {/* Error message */}
        {displayError && (
          <p
            id={errorId}
            className="text-sm text-red-600 dark:text-red-400 flex items-center gap-1"
            role="alert"
            aria-live="polite"
          >
            <svg className="h-4 w-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            {displayError}
          </p>
        )}

        {/* Warning message */}
        {displayWarning && !displayError && (
          <p
            className="text-sm text-yellow-600 dark:text-yellow-400 flex items-center gap-1"
            role="alert"
            aria-live="polite"
          >
            <svg className="h-4 w-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
            </svg>
            {displayWarning}
          </p>
        )}

        {/* Success message */}
        {displaySuccess && !displayError && !displayWarning && (
          <p className="text-sm text-green-600 dark:text-green-400 flex items-center gap-1" aria-live="polite">
            <svg className="h-4 w-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
            </svg>
            {displaySuccess}
          </p>
        )}

        {/* Helper text */}
        {displayHelper && (
          <p id={helperTextId} className="text-sm text-muted-foreground">
            {helperText}
          </p>
        )}
      </div>
    )
  }
)

Input.displayName = 'Input'
