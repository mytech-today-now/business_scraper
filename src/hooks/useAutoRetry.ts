/**
 * AutoRetry Hook for Test Suite Enhancement
 * Provides automatic retry mechanism for flaky tests without user intervention
 */

import { useCallback, useRef } from 'react'
import { testLogger } from '@/utils/TestLogger'

export interface RetryConfig {
  maxRetries: number
  retryDelay: number
  backoffMultiplier: number
  retryCondition?: (error: Error) => boolean
  onRetry?: (attempt: number, error: Error) => void
  onMaxRetriesReached?: (error: Error) => void
}

export interface RetryResult<T> {
  result: T | null
  error: Error | null
  attempts: number
  success: boolean
}

const DEFAULT_RETRY_CONFIG: RetryConfig = {
  maxRetries: 2,
  retryDelay: 1000,
  backoffMultiplier: 1.5,
  retryCondition: (error: Error) => {
    // Retry for common flaky test conditions
    const retryableErrors = [
      'timeout',
      'network',
      'ECONNRESET',
      'ENOTFOUND',
      'ETIMEDOUT',
      'flaky',
      'intermittent',
      'race condition',
      'async',
      'promise',
    ]

    const errorMessage = error.message.toLowerCase()
    return retryableErrors.some(pattern => errorMessage.includes(pattern))
  },
}

/**
 * Hook for automatic test retry functionality
 */
export function useAutoRetry<T>(config: Partial<RetryConfig> = {}) {
  const retryConfig = { ...DEFAULT_RETRY_CONFIG, ...config }
  const retryAttempts = useRef<Map<string, number>>(new Map())

  /**
   * Execute a function with automatic retry logic
   */
  const executeWithRetry = useCallback(
    async (
      testFunction: () => Promise<T> | T,
      testId: string,
      suiteName?: string
    ): Promise<RetryResult<T>> => {
      let lastError: Error | null = null
      let result: T | null = null
      let attempts = 0

      // Reset retry count for this test
      retryAttempts.current.set(testId, 0)

      while (attempts <= retryConfig.maxRetries) {
        try {
          attempts++
          result = await Promise.resolve(testFunction())

          // Success - reset retry count and return
          retryAttempts.current.delete(testId)
          return {
            result,
            error: null,
            attempts,
            success: true,
          }
        } catch (error) {
          lastError = error as Error

          // Check if we should retry this error
          if (
            attempts <= retryConfig.maxRetries &&
            retryConfig.retryCondition &&
            retryConfig.retryCondition(lastError)
          ) {
            // Log retry attempt
            if (suiteName) {
              testLogger.logError(suiteName, testId, lastError, {
                category: 'flaky',
                severity: 'medium',
                retryCount: attempts - 1,
              })
            }

            // Call retry callback if provided
            if (retryConfig.onRetry) {
              retryConfig.onRetry(attempts, lastError)
            }

            // Wait before retry with exponential backoff
            if (attempts <= retryConfig.maxRetries) {
              const delay =
                retryConfig.retryDelay * Math.pow(retryConfig.backoffMultiplier, attempts - 1)
              await new Promise(resolve => setTimeout(resolve, delay))
            }
          } else {
            // Don't retry this error type
            break
          }
        }
      }

      // All retries exhausted
      retryAttempts.current.set(testId, attempts - 1)

      if (retryConfig.onMaxRetriesReached && lastError) {
        retryConfig.onMaxRetriesReached(lastError)
      }

      // Log final failure
      if (suiteName && lastError) {
        testLogger.logError(suiteName, testId, lastError, {
          category: 'flaky',
          severity: 'high',
          retryCount: attempts - 1,
        })
      }

      return {
        result: null,
        error: lastError,
        attempts,
        success: false,
      }
    },
    [retryConfig]
  )

  /**
   * Get retry statistics for a specific test
   */
  const getRetryStats = useCallback((testId: string) => {
    return {
      retryCount: retryAttempts.current.get(testId) || 0,
      hasRetried: retryAttempts.current.has(testId),
    }
  }, [])

  /**
   * Clear retry history
   */
  const clearRetryHistory = useCallback(() => {
    retryAttempts.current.clear()
  }, [])

  /**
   * Get all retry statistics
   */
  const getAllRetryStats = useCallback(() => {
    const stats = Array.from(retryAttempts.current.entries())
    return {
      totalTests: stats.length,
      totalRetries: stats.reduce((sum, [, retries]) => sum + retries, 0),
      averageRetries:
        stats.length > 0 ? stats.reduce((sum, [, retries]) => sum + retries, 0) / stats.length : 0,
      testsWithRetries: stats.filter(([, retries]) => retries > 0).length,
    }
  }, [])

  return {
    executeWithRetry,
    getRetryStats,
    clearRetryHistory,
    getAllRetryStats,
    config: retryConfig,
  }
}

/**
 * Utility function for wrapping Jest test functions with retry logic
 */
export function withAutoRetry<T>(
  testFunction: () => Promise<T> | T,
  testName: string,
  suiteName: string,
  config: Partial<RetryConfig> = {}
): () => Promise<T> {
  return async () => {
    const { executeWithRetry } = useAutoRetry(config)
    const result = await executeWithRetry(testFunction, testName, suiteName)

    if (!result.success && result.error) {
      throw result.error
    }

    return result.result as T
  }
}

/**
 * Jest test wrapper with automatic retry
 */
export function retryableTest(
  name: string,
  testFunction: () => Promise<void> | void,
  timeout?: number,
  retryConfig: Partial<RetryConfig> = {}
): void {
  const wrappedTest = async () => {
    const { executeWithRetry } = useAutoRetry(retryConfig)
    const result = await executeWithRetry(
      testFunction,
      name,
      expect.getState().currentTestName || 'unknown'
    )

    if (!result.success && result.error) {
      throw result.error
    }
  }

  if (timeout) {
    test(name, wrappedTest, timeout)
  } else {
    test(name, wrappedTest)
  }
}

/**
 * Describe block with retry configuration for all tests
 */
export function retryableDescribe(
  name: string,
  testSuite: () => void,
  retryConfig: Partial<RetryConfig> = {}
): void {
  describe(name, () => {
    // Set up retry configuration for this suite
    beforeEach(() => {
      // Store retry config in global state for tests to access
      ;(global as any).__retryConfig = retryConfig
    })

    afterEach(() => {
      // Clean up retry config
      delete (global as any).__retryConfig
    })

    testSuite()
  })
}

/**
 * Helper to check if a test should be retried based on error patterns
 */
export function shouldRetryError(error: Error): boolean {
  const retryablePatterns = [
    /timeout/i,
    /network/i,
    /ECONNRESET/i,
    /ENOTFOUND/i,
    /ETIMEDOUT/i,
    /flaky/i,
    /intermittent/i,
    /race condition/i,
    /async/i,
    /promise/i,
    /websocket/i,
    /connection/i,
    /temporary/i,
  ]

  return retryablePatterns.some(pattern => pattern.test(error.message))
}

/**
 * Create a retry-enabled version of any async function
 */
export function createRetryableFunction<T extends (...args: any[]) => Promise<any>>(
  fn: T,
  config: Partial<RetryConfig> = {}
): T {
  return (async (...args: Parameters<T>) => {
    const { executeWithRetry } = useAutoRetry(config)
    const result = await executeWithRetry(
      () => fn(...args),
      fn.name || 'anonymous',
      'retryable-function'
    )

    if (!result.success && result.error) {
      throw result.error
    }

    return result.result
  }) as T
}

export default useAutoRetry
