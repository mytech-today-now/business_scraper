/**
 * React Hook for CSRF Protection
 * Provides CSRF token management for forms and API requests
 */

import { useState, useEffect, useCallback } from 'react'
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
}

/**
 * Custom hook for CSRF protection
 */
export function useCSRFProtection(): CSRFHookResult {
  const [csrfToken, setCSRFToken] = useState<string | null>(null)
  const [expiresAt, setExpiresAt] = useState<number>(0)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  /**
   * Fetch CSRF token from the server
   */
  const fetchCSRFToken = useCallback(async (): Promise<void> => {
    try {
      setIsLoading(true)
      setError(null)

      const response = await fetch('/api/auth', {
        method: 'GET',
        credentials: 'include',
        headers: {
          'Accept': 'application/json',
        },
      })

      if (!response.ok) {
        throw new Error(`Failed to fetch CSRF token: ${response.status}`)
      }

      const data = await response.json()
      
      if (data.csrfToken) {
        setCSRFToken(data.csrfToken)
        setExpiresAt(data.expiresAt ? new Date(data.expiresAt).getTime() : Date.now() + 3600000)
        
        // Also check for token in response headers
        const headerToken = response.headers.get('X-CSRF-Token')
        const headerExpires = response.headers.get('X-CSRF-Expires')
        
        if (headerToken) {
          setCSRFToken(headerToken)
        }
        
        if (headerExpires) {
          setExpiresAt(parseInt(headerExpires, 10))
        }

        logger.info('CSRF', 'CSRF token fetched successfully')
      } else {
        throw new Error('No CSRF token in response')
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to fetch CSRF token'
      setError(errorMessage)
      logger.error('CSRF', 'Failed to fetch CSRF token', err)
    } finally {
      setIsLoading(false)
    }
  }, [])

  /**
   * Check if current token is valid and not expired
   */
  const isTokenValid = useCallback((): boolean => {
    if (!csrfToken || !expiresAt) {
      return false
    }

    // Check if token expires within the next 5 minutes
    const fiveMinutesFromNow = Date.now() + (5 * 60 * 1000)
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
    }

    return headers
  }, [csrfToken])

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
    const interval = setInterval(() => {
      if (!isTokenValid()) {
        fetchCSRFToken()
      }
    }, 5 * 60 * 1000) // Check every 5 minutes

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
  }
}

/**
 * Hook for form CSRF protection
 */
export function useFormCSRFProtection() {
  const { csrfToken, isLoading, error, refreshToken, isTokenValid } = useCSRFProtection()

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
  const submitForm = useCallback(async (
    url: string,
    formData: FormData | Record<string, any>,
    options: RequestInit = {}
  ): Promise<Response> => {
    // Validate token first
    const isValid = await validateForm()
    if (!isValid) {
      throw new Error('CSRF token validation failed')
    }

    // Prepare headers
    const headers = new Headers(options.headers)
    if (csrfToken) {
      headers.set('X-CSRF-Token', csrfToken)
    }

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
      const responseData = await response.clone().json().catch(() => ({}))
      if (responseData.needsRefresh) {
        await refreshToken()
      }
    }

    return response
  }, [csrfToken, validateForm, refreshToken])

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
    
    return <Component {...props} csrfToken={csrfToken || props.csrfToken} />
  }
}
