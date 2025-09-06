/**
 * React Hook for CSRF Protection
 * Provides CSRF token management for forms and API requests
 */

import React, { useState, useEffect, useCallback } from 'react'
import { logger } from '@/utils/logger'

export interface CSRFToken {
  token: string
  expiresAt: number
}

export interface CSRFHookResult {
  csrfToken: string | null
  isLoading: boolean
  error: string | null
  refreshToken: () => Promise<void>
  getHeaders: () => Record<string, string>
  isTokenValid: () => boolean
  tokenId?: string | null
  isTemporary?: boolean
}

/**
 * Custom hook for CSRF protection
 */
export function useCSRFProtection(): CSRFHookResult {
  const [csrfToken, setCSRFToken] = useState<string | null>(null)
  const [tokenId, setTokenId] = useState<string | null>(null)
  const [isTemporary, setIsTemporary] = useState<boolean>(false)
  const [expiresAt, setExpiresAt] = useState<number>(0)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [retryCount, setRetryCount] = useState<number>(0)
  const [lastFetchAttempt, setLastFetchAttempt] = useState<number>(0)

  /**
   * Fetch CSRF token from the server
   * First tries the public endpoint, then falls back to the auth endpoint
   * Includes retry logic for better reliability
   */
  const fetchCSRFToken = useCallback(async (retryAttempt: number = 0): Promise<void> => {
    const maxRetries = 3
    const retryDelay = Math.min(1000 * Math.pow(2, retryAttempt), 5000) // Exponential backoff, max 5s
    const now = Date.now()

    // Prevent rapid successive calls (minimum 1 second between attempts)
    if (now - lastFetchAttempt < 1000 && retryAttempt === 0) {
      return
    }

    try {
      setIsLoading(true)
      setLastFetchAttempt(now)

      if (retryAttempt === 0) {
        setError(null)
        setRetryCount(0)
      } else {
        setRetryCount(retryAttempt)
      }

      // First, try to get a temporary CSRF token from the public endpoint
      let response = await fetch('/api/csrf', {
        method: 'GET',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
        },
      })

      if (!response.ok) {
        throw new Error(`Failed to fetch CSRF token: ${response.status}`)
      }

      const data = await response.json()

      if (data.csrfToken) {
        setCSRFToken(data.csrfToken)
        setTokenId(data.tokenId || null)
        setIsTemporary(data.temporary || false)
        setExpiresAt(data.expiresAt ? new Date(data.expiresAt).getTime() : Date.now() + 3600000)

        // Also check for token in response headers
        const headerToken = response.headers.get('X-CSRF-Token')
        const headerTokenId = response.headers.get('X-CSRF-Token-ID')
        const headerExpires = response.headers.get('X-CSRF-Expires')

        if (headerToken) {
          setCSRFToken(headerToken)
        }

        if (headerTokenId) {
          setTokenId(headerTokenId)
        }

        if (headerExpires) {
          setExpiresAt(parseInt(headerExpires, 10))
        }

        logger.info('CSRF', 'CSRF token fetched successfully from /api/csrf')
      } else {
        throw new Error('No CSRF token in response')
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to fetch CSRF token'
      const isNetworkError = errorMessage.includes('Failed to fetch') || errorMessage.includes('NetworkError')
      const is401Error = errorMessage.includes('401')

      // Don't retry on 401 errors after the middleware fix - they should not happen
      // Only retry on network errors or 5xx server errors
      const shouldRetry = retryAttempt < maxRetries && (isNetworkError || (!is401Error && !errorMessage.includes('400')))

      if (shouldRetry) {
        logger.warn('CSRF', `CSRF token fetch failed (attempt ${retryAttempt + 1}/${maxRetries + 1}), retrying in ${retryDelay}ms`, err)

        setTimeout(() => {
          fetchCSRFToken(retryAttempt + 1)
        }, retryDelay)

        return // Don't set error or stop loading yet
      }

      // All retries exhausted or non-retryable error
      const finalError = is401Error
        ? 'Authentication error - please refresh the page'
        : `${errorMessage}${retryAttempt > 0 ? ` (after ${retryAttempt + 1} attempts)` : ''}`

      setError(finalError)
      logger.error('CSRF', `Failed to fetch CSRF token: ${finalError}`, err)
      setIsLoading(false)
    }

    // Only set loading to false on success (error case handles it above)
    if (!error) {
      setIsLoading(false)
    }
  }, [lastFetchAttempt])

  /**
   * Check if current token is valid and not expired
   */
  const isTokenValid = useCallback((): boolean => {
    if (!csrfToken || !expiresAt) {
      return false
    }

    // Check if token expires within the next 5 minutes
    const fiveMinutesFromNow = Date.now() + 5 * 60 * 1000
    return expiresAt > fiveMinutesFromNow
  }, [csrfToken, expiresAt])

  /**
   * Refresh token if needed
   */
  const refreshToken = useCallback(async (): Promise<void> => {
    if (!isTokenValid()) {
      await fetchCSRFToken()
    }
  }, [isTokenValid, fetchCSRFToken])

  /**
   * Get headers for API requests
   */
  const getHeaders = useCallback((): Record<string, string> => {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    }

    if (csrfToken) {
      headers['X-CSRF-Token'] = csrfToken

      // Include token ID for temporary tokens
      if (tokenId && isTemporary) {
        headers['X-CSRF-Token-ID'] = tokenId
      }
    }

    return headers
  }, [csrfToken, tokenId, isTemporary])

  /**
   * Auto-refresh token when it's about to expire
   */
  useEffect(() => {
    if (!isTokenValid() && !isLoading) {
      fetchCSRFToken()
    }
  }, [isTokenValid, isLoading, fetchCSRFToken])

  /**
   * Set up automatic token refresh
   */
  useEffect(() => {
    const interval = setInterval(
      () => {
        if (!isTokenValid()) {
          fetchCSRFToken()
        }
      },
      5 * 60 * 1000
    ) // Check every 5 minutes

    return () => clearInterval(interval)
  }, [isTokenValid, fetchCSRFToken])

  /**
   * Initial token fetch
   */
  useEffect(() => {
    fetchCSRFToken()
  }, [fetchCSRFToken])

  return {
    csrfToken,
    isLoading,
    error,
    refreshToken,
    getHeaders,
    isTokenValid,
    tokenId,
    isTemporary,
  }
}

/**
 * Hook for form CSRF protection
 */
export function useFormCSRFProtection(): {
  csrfToken: string | null
  isLoading: boolean
  error: string | null
  getCSRFInput: () => { name: string; type: 'hidden'; value: string } | null
  validateForm: () => Promise<boolean>
  submitForm: (
    url: string,
    formData: FormData | Record<string, any>,
    options?: RequestInit
  ) => Promise<Response>
  isTokenValid: () => boolean
} {
  const { csrfToken, isLoading, error, refreshToken, isTokenValid, getHeaders } = useCSRFProtection()

  /**
   * Get CSRF input field for forms
   */
  const getCSRFInput = useCallback(() => {
    if (!csrfToken) {
      return null
    }

    return {
      name: 'csrf_token',
      type: 'hidden' as const,
      value: csrfToken,
    }
  }, [csrfToken])

  /**
   * Validate form before submission
   */
  const validateForm = useCallback(async (): Promise<boolean> => {
    if (!isTokenValid()) {
      try {
        await refreshToken()
        return isTokenValid()
      } catch (err) {
        logger.error('CSRF', 'Failed to refresh token for form validation', err)
        return false
      }
    }
    return true
  }, [isTokenValid, refreshToken])

  /**
   * Submit form with CSRF protection
   */
  const submitForm = useCallback(
    async (
      url: string,
      formData: FormData | Record<string, any>,
      options: RequestInit = {}
    ): Promise<Response> => {
      // Validate token first
      const isValid = await validateForm()
      if (!isValid) {
        throw new Error('CSRF token validation failed')
      }

      // Prepare headers using the getHeaders method (includes token ID for temporary tokens)
      const csrfHeaders = getHeaders()
      const headers = new Headers(options.headers)

      // Add CSRF headers
      Object.entries(csrfHeaders).forEach(([key, value]) => {
        if (key !== 'Content-Type' || !headers.has('Content-Type')) {
          headers.set(key, value)
        }
      })

      // Prepare body
      let body: string | FormData
      if (formData instanceof FormData) {
        // Add CSRF token to FormData
        if (csrfToken) {
          formData.set('csrf_token', csrfToken)
        }
        body = formData
      } else {
        // Add CSRF token to JSON data
        const dataWithCSRF = { ...formData }
        if (csrfToken) {
          dataWithCSRF.csrf_token = csrfToken
        }
        body = JSON.stringify(dataWithCSRF)
        headers.set('Content-Type', 'application/json')
      }

      // Make request
      const response = await fetch(url, {
        ...options,
        method: options.method || 'POST',
        headers,
        body,
        credentials: 'include',
      })

      // Check if we need to refresh token based on response
      if (response.status === 403) {
        const responseData = await response
          .clone()
          .json()
          .catch(() => ({}))
        if (responseData.needsRefresh) {
          await refreshToken()
        }
      }

      return response
    },
    [csrfToken, validateForm, refreshToken]
  )

  return {
    csrfToken,
    isLoading,
    error,
    getCSRFInput,
    validateForm,
    submitForm,
    isTokenValid,
  }
}

/**
 * Higher-order component for CSRF protection
 */
export function withCSRFProtection<T extends object>(
  Component: React.ComponentType<T>
): React.ComponentType<T & { csrfToken?: string }> {
  return function CSRFProtectedComponent(props: T & { csrfToken?: string }) {
    const { csrfToken } = useCSRFProtection()

    return React.createElement(Component, { ...props, csrfToken: csrfToken || props.csrfToken })
  }
}
