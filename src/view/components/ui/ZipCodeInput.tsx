/**
 * Enhanced ZIP Code Input Component
 *
 * Handles various address formats and extracts ZIP codes gracefully
 * with proper error handling and user feedback.
 */

import React from 'react'
import { clsx } from 'clsx'
import { useZipCodeInput, UseZipCodeInputOptions } from '@/hooks/useZipCodeInput'
import { Input, InputProps } from './Input'

export interface ZipCodeInputProps extends Omit<InputProps, 'value' | 'onChange' | 'error'> {
  value?: string
  onChange?: (zipCode: string) => void
  onValidZipCode?: (zipCode: string) => void
  onInvalidInput?: (error: string) => void
  showExtractedWarning?: boolean
  debounceMs?: number
}

/**
 * Enhanced ZIP Code Input Component
 */
export const ZipCodeInput = React.forwardRef<HTMLInputElement, ZipCodeInputProps>(
  (
    {
      value: externalValue,
      onChange,
      onValidZipCode,
      onInvalidInput,
      showExtractedWarning = true,
      debounceMs = 500,
      label = 'ZIP Code',
      placeholder = 'e.g., 90210 or 123 Main St, Beverly Hills, CA 90210',
      helperText = 'Enter ZIP code or full address',
      className,
      ...props
    },
    ref
  ) => {
    const hookOptions: UseZipCodeInputOptions = {
      initialValue: externalValue || '',
      onValidZipCode: (zipCode: string) => {
        onChange?.(zipCode)
        onValidZipCode?.(zipCode)
      },
      onInvalidInput,
      debounceMs,
    }

    const { state, handlers, displayValue, isValid, error, warning, isProcessing } =
      useZipCodeInput(hookOptions)

    // Sync external value changes
    React.useEffect(() => {
      if (externalValue !== undefined && externalValue !== displayValue) {
        handlers.handleChange(externalValue)
      }
    }, [externalValue])

    // Determine what message to show
    const getDisplayMessage = () => {
      if (error) {
        return error
      }

      if (warning && showExtractedWarning) {
        return warning
      }

      if (isProcessing) {
        return 'Processing address...'
      }

      return helperText
    }

    // Determine message type for styling
    const getMessageType = (): 'error' | 'warning' | 'info' | 'success' => {
      if (error) return 'error'
      if (warning && showExtractedWarning) return 'warning'
      if (isValid && state.parseResult?.wasExtracted) return 'success'
      return 'info'
    }

    const messageType = getMessageType()
    const displayMessage = getDisplayMessage()

    return (
      <div className="space-y-2">
        {label && (
          <label
            htmlFor={props.id}
            className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70"
          >
            {label}
            {isProcessing && (
              <span className="ml-2 text-xs text-blue-600">
                <span className="animate-pulse">●</span> Processing...
              </span>
            )}
          </label>
        )}

        <div className="relative">
          <input
            ref={ref}
            type="text"
            value={displayValue}
            onChange={e => handlers.handleChange(e.target.value)}
            onBlur={handlers.handleBlur}
            onFocus={handlers.handleFocus}
            placeholder={placeholder}
            className={clsx(
              'flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm',
              'ring-offset-background file:border-0 file:bg-transparent file:text-sm file:font-medium',
              'placeholder:text-muted-foreground',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2',
              'disabled:cursor-not-allowed disabled:opacity-50',
              error && 'border-destructive focus-visible:ring-destructive',
              warning && !error && 'border-yellow-300 focus-visible:ring-yellow-500',
              isValid && !error && !warning && 'border-green-300 focus-visible:ring-green-500',
              isProcessing && 'border-blue-300',
              className
            )}
            {...props}
          />

          {/* Status indicator */}
          <div className="absolute inset-y-0 right-0 flex items-center pr-3">
            {isProcessing && (
              <div className="animate-spin h-4 w-4 border-2 border-blue-600 border-t-transparent rounded-full" />
            )}
            {!isProcessing && isValid && (
              <div className="h-4 w-4 text-green-600">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M5 13l4 4L19 7"
                  />
                </svg>
              </div>
            )}
            {!isProcessing && error && (
              <div className="h-4 w-4 text-red-600">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M6 18L18 6M6 6l12 12"
                  />
                </svg>
              </div>
            )}
            {!isProcessing && warning && !error && (
              <div className="h-4 w-4 text-yellow-600">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"
                  />
                </svg>
              </div>
            )}
          </div>
        </div>

        {/* Message display */}
        {displayMessage && (
          <p
            className={clsx(
              'text-sm',
              messageType === 'error' && 'text-destructive',
              messageType === 'warning' && 'text-yellow-600',
              messageType === 'success' && 'text-green-600',
              messageType === 'info' && 'text-muted-foreground'
            )}
          >
            {displayMessage}
          </p>
        )}

        {/* Debug info (only in development) */}
        {process.env.NODE_ENV === 'development' && state.parseResult && (
          <details className="text-xs text-gray-500">
            <summary className="cursor-pointer">Debug Info</summary>
            <div className="mt-1 p-2 bg-gray-50 rounded text-xs">
              <div>Extracted from: {state.parseResult.extractedFrom}</div>
              <div>Confidence: {state.parseResult.confidence}</div>
              <div>Was extracted: {state.parseResult.wasExtracted ? 'Yes' : 'No'}</div>
              {state.parseResult.zipCode && <div>ZIP Code: {state.parseResult.zipCode}</div>}
            </div>
          </details>
        )}
      </div>
    )
  }
)

ZipCodeInput.displayName = 'ZipCodeInput'
