/**
 * ZIP Code Input Hook
 *
 * Custom hook for handling ZIP code input with address parsing,
 * error handling, and user feedback.
 */

import { useState, useCallback, useEffect } from 'react'
import { AddressInputHandler, AddressParseResult } from '@/utils/addressInputHandler'
import { logger } from '@/utils/logger'

export interface ZipCodeInputState {
  value: string
  displayValue: string
  isValid: boolean
  parseResult: AddressParseResult | null
  error: string | null
  warning: string | null
  isProcessing: boolean
}

export interface ZipCodeInputHandlers {
  handleChange: (value: string) => void
  handleBlur: () => void
  handleFocus: () => void
  clearError: () => void
  reset: () => void
}

export interface UseZipCodeInputOptions {
  initialValue?: string
  onValidZipCode?: (zipCode: string) => void
  onInvalidInput?: (error: string) => void
  debounceMs?: number
}

/**
 * Custom hook for ZIP code input handling
 */
export function useZipCodeInput(options: UseZipCodeInputOptions = {}) {
  const { initialValue = '', onValidZipCode, onInvalidInput, debounceMs = 1000 } = options

  const [state, setState] = useState<ZipCodeInputState>({
    value: '',
    displayValue: initialValue,
    isValid: false,
    parseResult: null,
    error: null,
    warning: null,
    isProcessing: false,
  })

  const [debounceTimer, setDebounceTimer] = useState<NodeJS.Timeout | null>(null)

  /**
   * Process the input and extract ZIP code
   */
  const processInput = useCallback(
    (input: string) => {
      setState(prev => ({ ...prev, isProcessing: true }))

      try {
        const parseResult = AddressInputHandler.parseAddressInput(input)

        const newState: Partial<ZipCodeInputState> = {
          parseResult,
          isProcessing: false,
          error: null,
          warning: null,
        }

        if (parseResult.error) {
          // Don't treat incomplete input as an error - just a typing state
          if (parseResult.error === 'Incomplete input - continue typing') {
            newState.error = null
            newState.warning = 'Continue typing...'
            newState.isValid = false
            newState.value = ''
            // Don't call error callback for incomplete input
          } else {
            newState.error = parseResult.error
            newState.isValid = false
            newState.value = ''

            // Call error callback for actual errors
            if (onInvalidInput) {
              onInvalidInput(parseResult.error)
            }

            logger.warn('ZipCodeInput', `Invalid input: ${parseResult.error}`)
          }
        } else if (parseResult.zipCode) {
          newState.value = parseResult.zipCode
          newState.isValid = true

          // Show warning if ZIP was extracted from address
          if (parseResult.wasExtracted && parseResult.warning) {
            newState.warning = parseResult.warning
          }

          // Call success callback
          if (onValidZipCode) {
            onValidZipCode(parseResult.zipCode)
          }

          logger.info('ZipCodeInput', `Valid ZIP code: ${parseResult.zipCode}`)
        } else {
          newState.error = 'Please enter a valid ZIP code'
          newState.isValid = false
          newState.value = ''

          if (onInvalidInput) {
            onInvalidInput('Please enter a valid ZIP code')
          }
        }

        setState(prev => ({ ...prev, ...newState }))
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred'

        setState(prev => ({
          ...prev,
          error: `Error processing input: ${errorMessage}`,
          isValid: false,
          value: '',
          isProcessing: false,
        }))

        if (onInvalidInput) {
          onInvalidInput(errorMessage)
        }

        logger.error('ZipCodeInput', 'Error processing input', error)
      }
    },
    [onValidZipCode, onInvalidInput]
  )

  /**
   * Handle input change with debouncing
   */
  const handleChange = useCallback(
    (value: string) => {
      setState(prev => ({
        ...prev,
        displayValue: value,
        error: null,
        warning: null,
      }))

      // Clear existing timer
      if (debounceTimer) {
        clearTimeout(debounceTimer)
      }

      // Set new timer for debounced processing
      const timer = setTimeout(() => {
        if (value.trim().length > 0) {
          processInput(value)
        } else {
          setState(prev => ({
            ...prev,
            value: '',
            isValid: false,
            parseResult: null,
            error: null,
            warning: null,
            isProcessing: false,
          }))
        }
      }, debounceMs)

      setDebounceTimer(timer)
    },
    [debounceTimer, debounceMs, processInput]
  )

  /**
   * Handle input blur (immediate processing)
   */
  const handleBlur = useCallback(() => {
    // Clear debounce timer and process immediately
    if (debounceTimer) {
      clearTimeout(debounceTimer)
      setDebounceTimer(null)
    }

    if (state.displayValue.trim().length > 0) {
      processInput(state.displayValue)
    }
  }, [debounceTimer, state.displayValue, processInput])

  /**
   * Handle input focus
   */
  const handleFocus = useCallback(() => {
    setState(prev => ({
      ...prev,
      error: null,
      warning: null,
    }))
  }, [])

  /**
   * Clear error state
   */
  const clearError = useCallback(() => {
    setState(prev => ({
      ...prev,
      error: null,
      warning: null,
    }))
  }, [])

  /**
   * Reset to initial state
   */
  const reset = useCallback(() => {
    if (debounceTimer) {
      clearTimeout(debounceTimer)
      setDebounceTimer(null)
    }

    setState({
      value: '',
      displayValue: initialValue,
      isValid: false,
      parseResult: null,
      error: null,
      warning: null,
      isProcessing: false,
    })
  }, [debounceTimer, initialValue])

  /**
   * Initialize with initial value if provided
   */
  useEffect(() => {
    if (initialValue && initialValue.trim().length > 0) {
      handleChange(initialValue)
    }
  }, []) // Only run on mount

  /**
   * Cleanup timer on unmount
   */
  useEffect(() => {
    return () => {
      if (debounceTimer) {
        clearTimeout(debounceTimer)
      }
    }
  }, [debounceTimer])

  const handlers: ZipCodeInputHandlers = {
    handleChange,
    handleBlur,
    handleFocus,
    clearError,
    reset,
  }

  return {
    state,
    handlers,
    // Convenience getters
    zipCode: state.value,
    isValid: state.isValid,
    error: state.error,
    warning: state.warning,
    isProcessing: state.isProcessing,
    displayValue: state.displayValue,
  }
}
