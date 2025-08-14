'use client'

import { useState, useCallback, useRef } from 'react'
import { logger } from '@/utils/logger'

export interface ErrorState {
  error: Error | null
  isError: boolean
  errorId: string | null
  retryCount: number
}

export interface AsyncOperationState<T = any> {
  data: T | null
  loading: boolean
  error: Error | null
  isError: boolean
  errorId: string | null
  retryCount: number
}

export interface UseErrorHandlingOptions {
  maxRetries?: number
  retryDelay?: number
  onError?: (error: Error, errorId: string) => void
  logErrors?: boolean
  component?: string
}

/**
 * Hook for standardized error handling in React components
 */
export function useErrorHandling(options: UseErrorHandlingOptions = {}) {
  const {
    maxRetries = 3,
    retryDelay = 1000,
    onError,
    logErrors = true,
    component = 'Component'
  } = options

  const [errorState, setErrorState] = useState<ErrorState>({
    error: null,
    isError: false,
    errorId: null,
    retryCount: 0
  })

  const retryTimeoutRef = useRef<NodeJS.Timeout>()

  const generateErrorId = useCallback(() => {
    return `err_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  }, [])

  const logError = useCallback((error: Error, errorId: string, context?: any) => {
    if (logErrors) {
      logger.error(component, `Error ${errorId}`, {
        errorId,
        error: {
          name: error.name,
          message: error.message,
          stack: error.stack
        },
        retryCount: errorState.retryCount,
        context
      })
    }
  }, [component, logErrors, errorState.retryCount])

  const handleError = useCallback((error: Error, context?: any) => {
    const errorId = generateErrorId()
    
    logError(error, errorId, context)
    
    setErrorState(prev => ({
      error,
      isError: true,
      errorId,
      retryCount: prev.retryCount
    }))

    onError?.(error, errorId)
  }, [generateErrorId, logError, onError])

  const clearError = useCallback(() => {
    if (retryTimeoutRef.current) {
      clearTimeout(retryTimeoutRef.current)
    }
    
    setErrorState({
      error: null,
      isError: false,
      errorId: null,
      retryCount: 0
    })
  }, [])

  const retry = useCallback((retryFn?: () => void | Promise<void>) => {
    if (errorState.retryCount >= maxRetries) {
      logger.warn(component, 'Maximum retry attempts reached')
      return false
    }

    setErrorState(prev => ({
      ...prev,
      retryCount: prev.retryCount + 1,
      isError: false,
      error: null
    }))

    if (retryFn) {
      const delay = retryDelay * (errorState.retryCount + 1)
      retryTimeoutRef.current = setTimeout(async () => {
        try {
          await retryFn()
        } catch (error) {
          handleError(error instanceof Error ? error : new Error(String(error)))
        }
      }, delay)
    }

    return true
  }, [errorState.retryCount, maxRetries, component, retryDelay, handleError])

  const canRetry = errorState.retryCount < maxRetries

  return {
    ...errorState,
    handleError,
    clearError,
    retry,
    canRetry,
    maxRetries
  }
}

/**
 * Hook for handling async operations with standardized error handling
 */
export function useAsyncOperation<T = any>(options: UseErrorHandlingOptions = {}) {
  const {
    maxRetries = 3,
    retryDelay = 1000,
    onError,
    logErrors = true,
    component = 'AsyncOperation'
  } = options

  const [state, setState] = useState<AsyncOperationState<T>>({
    data: null,
    loading: false,
    error: null,
    isError: false,
    errorId: null,
    retryCount: 0
  })

  const retryTimeoutRef = useRef<NodeJS.Timeout>()

  const generateErrorId = useCallback(() => {
    return `err_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  }, [])

  const logError = useCallback((error: Error, errorId: string, context?: any) => {
    if (logErrors) {
      logger.error(component, `Async operation error ${errorId}`, {
        errorId,
        error: {
          name: error.name,
          message: error.message,
          stack: error.stack
        },
        retryCount: state.retryCount,
        context
      })
    }
  }, [component, logErrors, state.retryCount])

  const execute = useCallback(async (
    asyncFn: () => Promise<T>,
    context?: any
  ): Promise<T | null> => {
    setState(prev => ({
      ...prev,
      loading: true,
      error: null,
      isError: false
    }))

    try {
      const result = await asyncFn()
      setState(prev => ({
        ...prev,
        data: result,
        loading: false,
        error: null,
        isError: false,
        errorId: null
      }))
      return result
    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error))
      const errorId = generateErrorId()
      
      logError(err, errorId, context)
      
      setState(prev => ({
        ...prev,
        loading: false,
        error: err,
        isError: true,
        errorId
      }))

      onError?.(err, errorId)
      return null
    }
  }, [generateErrorId, logError, onError])

  const retry = useCallback(async (
    asyncFn: () => Promise<T>,
    context?: any
  ): Promise<T | null> => {
    if (state.retryCount >= maxRetries) {
      logger.warn(component, 'Maximum retry attempts reached for async operation')
      return null
    }

    setState(prev => ({
      ...prev,
      retryCount: prev.retryCount + 1
    }))

    const delay = retryDelay * (state.retryCount + 1)
    
    return new Promise((resolve) => {
      retryTimeoutRef.current = setTimeout(async () => {
        const result = await execute(asyncFn, context)
        resolve(result)
      }, delay)
    })
  }, [state.retryCount, maxRetries, component, retryDelay, execute])

  const reset = useCallback(() => {
    if (retryTimeoutRef.current) {
      clearTimeout(retryTimeoutRef.current)
    }
    
    setState({
      data: null,
      loading: false,
      error: null,
      isError: false,
      errorId: null,
      retryCount: 0
    })
  }, [])

  const canRetry = state.retryCount < maxRetries

  return {
    ...state,
    execute,
    retry,
    reset,
    canRetry,
    maxRetries
  }
}

/**
 * Hook for handling form submission errors
 */
export function useFormErrorHandling(options: UseErrorHandlingOptions = {}) {
  const errorHandling = useErrorHandling({
    ...options,
    component: options.component || 'Form'
  })

  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})

  const setFieldError = useCallback((field: string, error: string) => {
    setFieldErrors(prev => ({
      ...prev,
      [field]: error
    }))
  }, [])

  const clearFieldError = useCallback((field: string) => {
    setFieldErrors(prev => {
      const newErrors = { ...prev }
      delete newErrors[field]
      return newErrors
    })
  }, [])

  const clearAllFieldErrors = useCallback(() => {
    setFieldErrors({})
  }, [])

  const handleSubmissionError = useCallback((error: Error | any) => {
    // Handle validation errors with field-specific messages
    if (error?.response?.data?.errors) {
      const errors = error.response.data.errors
      if (typeof errors === 'object') {
        setFieldErrors(errors)
        return
      }
    }

    // Handle general form errors
    errorHandling.handleError(
      error instanceof Error ? error : new Error(String(error))
    )
  }, [errorHandling])

  const clearAllErrors = useCallback(() => {
    errorHandling.clearError()
    clearAllFieldErrors()
  }, [errorHandling, clearAllFieldErrors])

  return {
    ...errorHandling,
    fieldErrors,
    setFieldError,
    clearFieldError,
    clearAllFieldErrors,
    handleSubmissionError,
    clearAllErrors
  }
}

/**
 * Utility function to wrap async functions with error handling
 */
export function withErrorHandling<T extends any[], R>(
  fn: (...args: T) => Promise<R>,
  options: UseErrorHandlingOptions = {}
) {
  const {
    onError,
    logErrors = true,
    component = 'AsyncFunction'
  } = options

  return async (...args: T): Promise<R | null> => {
    try {
      return await fn(...args)
    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error))
      const errorId = `err_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
      
      if (logErrors) {
        logger.error(component, `Function error ${errorId}`, {
          errorId,
          error: {
            name: err.name,
            message: err.message,
            stack: err.stack
          },
          args: args.length > 0 ? 'provided' : 'none'
        })
      }

      onError?.(err, errorId)
      return null
    }
  }
}
