/**
 * Lightweight CSRF Protection Hook for Login Page
 * Optimized for performance with minimal dependencies
 */

import { useState, useEffect, useCallback, useRef } from 'react'

export interface LightweightCSRFResult {
  csrfToken: string | null
  isLoading: boolean
  error: string | null
  submitForm: (
    url: string,
    formData: Record<string, any>,
    options?: RequestInit
  ) => Promise<Response>
  isTokenValid: () => boolean
}

/**
 * Lightweight CSRF protection hook optimized for login page performance
 */
export function useLightweightCSRF(): LightweightCSRFResult {
  const [csrfToken, setCSRFToken] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [expiresAt, setExpiresAt] = useState<number>(0)
  const lastFetchAttemptRef = useRef<number>(0)
  const retryTimeoutRef = useRef<NodeJS.Timeout | null>(null)

  /**
   * Fetch CSRF token with optimized retry logic
   */
  const fetchCSRFToken = useCallback(async (retryAttempt: number = 0): Promise<void> => {
    const maxRetries = 2 // Reduced from 3 for faster failure
    const retryDelay = Math.min(1000 * Math.pow(1.5, retryAttempt), 3000) // Faster backoff
    const now = Date.now()

    // Prevent rapid successive calls
    if (now - lastFetchAttemptRef.current < 500 && retryAttempt === 0) {
      return
    }

    try {
      setIsLoading(true)
      lastFetchAttemptRef.current = now

      if (retryAttempt === 0) {
        setError(null)
      }

      console.log(`[CSRF] Fetching token (attempt ${retryAttempt + 1})`)

      // Simple fetch without heavy error logging
      const response = await fetch('/api/csrf', {
        method: 'GET',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
        },
      })

      console.log(`[CSRF] Response status: ${response.status}`)

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`)
      }

      const data = await response.json()
      console.log('[CSRF] Response data:', data)

      if (data.csrfToken) {
        setCSRFToken(data.csrfToken)
        setExpiresAt(data.expiresAt ? new Date(data.expiresAt).getTime() : Date.now() + 3600000)
        setError(null)
        console.log('[CSRF] Token loaded successfully')
      } else {
        throw new Error('No CSRF token in response')
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to fetch CSRF token'
      console.error('[CSRF] Error:', errorMessage)

      if (retryAttempt < maxRetries) {
        console.log(`[CSRF] Retrying in ${retryDelay}ms (attempt ${retryAttempt + 1}/${maxRetries})`)

        // Clear any existing timeout
        if (retryTimeoutRef.current) {
          clearTimeout(retryTimeoutRef.current)
        }

        retryTimeoutRef.current = setTimeout(() => {
          fetchCSRFToken(retryAttempt + 1)
        }, retryDelay)
      } else {
        setError(errorMessage.includes('401')
          ? 'Security token initialization failed. Please refresh the page.'
          : 'Failed to load security token. Please try again.'
        )
      }
    } finally {
      setIsLoading(false)
    }
  }, []) // Empty dependency array to make function stable

  /**
   * Check if token is valid and not expired
   */
  const isTokenValid = useCallback((): boolean => {
    if (!csrfToken) return false
    if (expiresAt > 0 && Date.now() > expiresAt) return false
    return true
  }, [csrfToken, expiresAt])

  /**
   * Submit form with CSRF protection
   */
  const submitForm = useCallback(async (
    url: string,
    formData: Record<string, any>,
    options: RequestInit = {}
  ): Promise<Response> => {
    // Validate token before submission
    if (!isTokenValid()) {
      throw new Error('Invalid or expired security token')
    }

    // Prepare headers
    const headers = new Headers(options.headers)
    headers.set('Content-Type', 'application/json')

    // Add CSRF token to form data
    const dataWithCSRF = { ...formData }
    if (csrfToken) {
      dataWithCSRF.csrf_token = csrfToken
    }

    // Make request
    const response = await fetch(url, {
      ...options,
      method: options.method || 'POST',
      headers,
      body: JSON.stringify(dataWithCSRF),
      credentials: 'include',
    })

    return response
  }, [csrfToken, isTokenValid])

  // Initialize CSRF token on mount
  useEffect(() => {
    fetchCSRFToken()

    // Cleanup timeout on unmount
    return () => {
      if (retryTimeoutRef.current) {
        clearTimeout(retryTimeoutRef.current)
      }
    }
  }, []) // Remove fetchCSRFToken from dependencies to prevent infinite loop

  return {
    csrfToken,
    isLoading,
    error,
    submitForm,
    isTokenValid,
  }
}

/**
 * Hook for form CSRF protection with lightweight implementation
 */
export function useLightweightFormCSRF(): LightweightCSRFResult & {
  getCSRFInput: () => { name: string; type: 'hidden'; value: string } | null
} {
  const csrfResult = useLightweightCSRF()

  /**
   * Get CSRF input field for forms
   */
  const getCSRFInput = useCallback(() => {
    if (!csrfResult.csrfToken) {
      return null
    }

    return {
      name: 'csrf_token',
      type: 'hidden' as const,
      value: csrfResult.csrfToken,
    }
  }, [csrfResult.csrfToken])

  return {
    ...csrfResult,
    getCSRFInput,
  }
}
