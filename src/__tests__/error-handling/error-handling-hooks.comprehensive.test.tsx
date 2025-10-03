/**
 * Error Handling Hooks - Comprehensive Test Suite
 * Tests React hooks for error handling, async operations, and error recovery
 */

import React from 'react'
import { renderHook, act, render, screen, fireEvent, waitFor } from '@testing-library/react'
import {
  useErrorHandling,
  useAsyncOperation,
  withErrorHandling,
  UseErrorHandlingOptions,
} from '@/hooks/useErrorHandling'
import { logger } from '@/utils/logger'

// Mock dependencies
jest.mock('@/utils/logger')
const mockLogger = logger as jest.Mocked<typeof logger>

describe('Error Handling Hooks - Comprehensive Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    jest.spyOn(console, 'error').mockImplementation(() => {})
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  describe('useErrorHandling Hook', () => {
    it('should initialize with no error state', () => {
      const { result } = renderHook(() => useErrorHandling())

      expect(result.current.isError).toBe(false)
      expect(result.current.error).toBeNull()
      expect(result.current.errorId).toBeNull()
      expect(result.current.retryCount).toBe(0)
    })

    it('should handle errors and update state', () => {
      const { result } = renderHook(() => useErrorHandling())
      const testError = new Error('Test error')

      act(() => {
        result.current.handleError(testError)
      })

      expect(result.current.isError).toBe(true)
      expect(result.current.error).toBe(testError)
      expect(result.current.errorId).toBeTruthy()
    })

    it('should log errors when logErrors is enabled', () => {
      const { result } = renderHook(() => 
        useErrorHandling({ component: 'TestComponent', logErrors: true })
      )
      const testError = new Error('Logged error')

      act(() => {
        result.current.handleError(testError)
      })

      expect(mockLogger.error).toHaveBeenCalledWith(
        'TestComponent',
        expect.stringContaining('Error'),
        expect.objectContaining({
          errorId: expect.any(String),
          error: {
            name: 'Error',
            message: 'Logged error',
            stack: expect.any(String),
          },
          retryCount: 0,
        })
      )
    })

    it('should call custom error handler when provided', () => {
      const customErrorHandler = jest.fn()
      const { result } = renderHook(() => 
        useErrorHandling({ onError: customErrorHandler })
      )
      const testError = new Error('Custom handler test')

      act(() => {
        result.current.handleError(testError)
      })

      expect(customErrorHandler).toHaveBeenCalledWith(
        testError,
        expect.any(String)
      )
    })

    it('should clear error state', () => {
      const { result } = renderHook(() => useErrorHandling())
      const testError = new Error('Test error')

      act(() => {
        result.current.handleError(testError)
      })

      expect(result.current.isError).toBe(true)

      act(() => {
        result.current.clearError()
      })

      expect(result.current.isError).toBe(false)
      expect(result.current.error).toBeNull()
      expect(result.current.errorId).toBeNull()
    })

    it('should retry operations and increment retry count', () => {
      const { result } = renderHook(() => useErrorHandling())
      const testError = new Error('Retryable error')

      act(() => {
        result.current.handleError(testError)
      })

      expect(result.current.retryCount).toBe(0)

      act(() => {
        result.current.retry()
      })

      expect(result.current.retryCount).toBe(1)
      expect(result.current.isError).toBe(false)
    })

    it('should limit retry attempts', () => {
      const { result } = renderHook(() => 
        useErrorHandling({ maxRetries: 2 })
      )
      const testError = new Error('Persistent error')

      // Simulate multiple retries
      for (let i = 0; i < 5; i++) {
        act(() => {
          result.current.handleError(testError)
          result.current.retry()
        })
      }

      expect(result.current.retryCount).toBeLessThanOrEqual(2)
    })

    it('should handle error context', () => {
      const { result } = renderHook(() => useErrorHandling())
      const testError = new Error('Context error')
      const context = { operation: 'test', userId: '123' }

      act(() => {
        result.current.handleError(testError, context)
      })

      expect(mockLogger.error).toHaveBeenCalledWith(
        expect.any(String),
        expect.any(String),
        expect.objectContaining({
          context,
        })
      )
    })
  })

  describe('Error State Management', () => {
    it('should track error retry count', () => {
      const { result } = renderHook(() => useErrorHandling({ maxRetries: 3 }))
      const testError = new Error('Retryable error')

      act(() => {
        result.current.handleError(testError)
      })

      expect(result.current.retryCount).toBe(0)

      act(() => {
        result.current.retry()
      })

      expect(result.current.retryCount).toBe(1)
      expect(result.current.isError).toBe(false)
    })

    it('should handle error context properly', () => {
      const { result } = renderHook(() => useErrorHandling({ logErrors: true }))
      const testError = new Error('Context error')
      const context = { operation: 'test', userId: '123' }

      act(() => {
        result.current.handleError(testError, context)
      })

      expect(mockLogger.error).toHaveBeenCalledWith(
        expect.any(String),
        expect.any(String),
        expect.objectContaining({
          context,
        })
      )
    })

    it('should reset error state correctly', () => {
      const { result } = renderHook(() => useErrorHandling())
      const testError = new Error('Reset test')

      act(() => {
        result.current.handleError(testError)
      })

      expect(result.current.isError).toBe(true)

      act(() => {
        result.current.clearError()
      })

      expect(result.current.isError).toBe(false)
      expect(result.current.error).toBeNull()
      expect(result.current.errorId).toBeNull()
    })
  })

  describe('withErrorHandling Higher-Order Function', () => {
    it('should wrap async functions with error handling', async () => {
      const mockFn = jest.fn().mockResolvedValue('wrapped success')
      const wrappedFn = withErrorHandling(mockFn, { component: 'WrappedFunction' })

      const result = await wrappedFn('arg1', 'arg2')

      expect(result).toBe('wrapped success')
      expect(mockFn).toHaveBeenCalledWith('arg1', 'arg2')
    })

    it('should handle errors in wrapped functions', async () => {
      const testError = new Error('Wrapped error')
      const mockFn = jest.fn().mockRejectedValue(testError)
      const customErrorHandler = jest.fn()
      
      const wrappedFn = withErrorHandling(mockFn, {
        component: 'WrappedFunction',
        onError: customErrorHandler,
      })

      const result = await wrappedFn()

      expect(result).toBeNull()
      expect(customErrorHandler).toHaveBeenCalledWith(testError, expect.any(String))
    })

    it('should log errors in wrapped functions', async () => {
      const testError = new Error('Wrapped logging error')
      const mockFn = jest.fn().mockRejectedValue(testError)
      
      const wrappedFn = withErrorHandling(mockFn, {
        component: 'LoggingTest',
        logErrors: true,
      })

      await wrappedFn()

      expect(mockLogger.error).toHaveBeenCalledWith(
        'LoggingTest',
        expect.stringContaining('Function error'),
        expect.objectContaining({
          errorId: expect.any(String),
          error: {
            name: 'Error',
            message: 'Wrapped logging error',
            stack: expect.any(String),
          },
        })
      )
    })

    it('should handle non-Error exceptions in wrapped functions', async () => {
      const mockFn = jest.fn().mockRejectedValue('String error')
      const wrappedFn = withErrorHandling(mockFn)

      const result = await wrappedFn()

      expect(result).toBeNull()
      expect(mockLogger.error).toHaveBeenCalledWith(
        expect.any(String),
        expect.any(String),
        expect.objectContaining({
          error: {
            name: 'Error',
            message: 'String error',
            stack: expect.any(String),
          },
        })
      )
    })
  })

  describe('Integration with React Components', () => {
    it('should integrate error handling with React components', async () => {
      const TestComponent = () => {
        const { isError, error, handleError, clearError } = useErrorHandling()
        const [count, setCount] = React.useState(0)

        const triggerError = () => {
          if (count > 2) {
            handleError(new Error('Count too high'))
          } else {
            setCount(c => c + 1)
          }
        }

        if (isError) {
          return (
            <div>
              <div data-testid="error-message">{error?.message}</div>
              <button onClick={clearError} data-testid="clear-error">Clear Error</button>
            </div>
          )
        }

        return (
          <div>
            <div data-testid="count">{count}</div>
            <button onClick={triggerError} data-testid="increment">Increment</button>
          </div>
        )
      }

      render(<TestComponent />)

      // Normal operation
      expect(screen.getByTestId('count')).toHaveTextContent('0')

      fireEvent.click(screen.getByTestId('increment'))
      expect(screen.getByTestId('count')).toHaveTextContent('1')

      // Trigger error
      fireEvent.click(screen.getByTestId('increment'))
      fireEvent.click(screen.getByTestId('increment'))
      fireEvent.click(screen.getByTestId('increment'))

      expect(screen.getByTestId('error-message')).toHaveTextContent('Count too high')

      // Clear error
      fireEvent.click(screen.getByTestId('clear-error'))
      expect(screen.getByTestId('count')).toHaveTextContent('3')
    })

    it('should handle error recovery in components', async () => {
      const TestRecoveryComponent = () => {
        const { isError, error, retryCount, handleError, clearError, retry } = useErrorHandling()
        const [attemptCount, setAttemptCount] = React.useState(0)

        const attemptOperation = () => {
          const newCount = attemptCount + 1
          setAttemptCount(newCount)

          if (newCount < 3) {
            handleError(new Error(`Attempt ${newCount} failed`))
          } else {
            clearError()
          }
        }

        if (isError) {
          return (
            <div>
              <div data-testid="error">{error?.message}</div>
              <div data-testid="retry-count">Retries: {retryCount}</div>
              <button onClick={retry} data-testid="retry">Retry</button>
              <button onClick={clearError} data-testid="clear">Clear</button>
            </div>
          )
        }

        return (
          <div>
            <div data-testid="attempts">Attempts: {attemptCount}</div>
            <button onClick={attemptOperation} data-testid="attempt">Attempt Operation</button>
          </div>
        )
      }

      render(<TestRecoveryComponent />)

      // Test error and retry
      fireEvent.click(screen.getByTestId('attempt'))
      expect(screen.getByTestId('error')).toHaveTextContent('Attempt 1 failed')

      fireEvent.click(screen.getByTestId('retry'))
      expect(screen.getByTestId('retry-count')).toHaveTextContent('Retries: 1')

      // Clear and try again
      fireEvent.click(screen.getByTestId('clear'))
      expect(screen.getByTestId('attempts')).toHaveTextContent('Attempts: 1')
    })
  })

  describe('Error Recovery Patterns', () => {
    it('should implement retry with exponential backoff', async () => {
      let attemptCount = 0
      const { result } = renderHook(() => useAsyncOperation())
      
      const flakyOperation = jest.fn().mockImplementation(async () => {
        attemptCount++
        if (attemptCount < 3) {
          throw new Error(`Attempt ${attemptCount} failed`)
        }
        return 'Success after retries'
      })

      // Implement retry logic
      const executeWithRetry = async (maxRetries = 3, delay = 100) => {
        for (let i = 0; i <= maxRetries; i++) {
          try {
            return await result.current.execute(flakyOperation)
          } catch (error) {
            if (i === maxRetries) throw error
            await new Promise(resolve => setTimeout(resolve, delay * Math.pow(2, i)))
          }
        }
      }

      let finalResult: any
      await act(async () => {
        finalResult = await executeWithRetry()
      })

      expect(finalResult).toBe('Success after retries')
      expect(flakyOperation).toHaveBeenCalledTimes(3)
    })

    it('should implement circuit breaker pattern', async () => {
      let failureCount = 0
      let circuitOpen = false
      const { result } = renderHook(() => useAsyncOperation())

      const circuitBreakerOperation = jest.fn().mockImplementation(async () => {
        if (circuitOpen) {
          throw new Error('Circuit breaker is open')
        }
        
        failureCount++
        if (failureCount < 5) {
          throw new Error('Service failure')
        }
        
        // Reset on success
        failureCount = 0
        return 'Service recovered'
      })

      // Simulate circuit breaker logic
      const executeWithCircuitBreaker = async () => {
        try {
          const result = await result.current.execute(circuitBreakerOperation)
          failureCount = 0 // Reset on success
          return result
        } catch (error) {
          if (failureCount >= 3) {
            circuitOpen = true
            setTimeout(() => { circuitOpen = false }, 1000) // Reset after timeout
          }
          throw error
        }
      }

      // Test multiple failures
      for (let i = 0; i < 4; i++) {
        await act(async () => {
          try {
            await executeWithCircuitBreaker()
          } catch (error) {
            // Expected failures
          }
        })
      }

      expect(circuitOpen).toBe(true)
    })
  })

  describe('Error Boundary Integration', () => {
    it('should work with error boundaries for unhandled errors', () => {
      const TestComponent = () => {
        const { handleError } = useErrorHandling()

        const throwUnhandledError = () => {
          // Simulate an unhandled error that should be caught by error boundary
          throw new Error('Unhandled component error')
        }

        return (
          <button onClick={throwUnhandledError} data-testid="throw-error">
            Throw Error
          </button>
        )
      }

      expect(() => {
        render(<TestComponent />)
        fireEvent.click(screen.getByTestId('throw-error'))
      }).toThrow('Unhandled component error')
    })
  })
})
