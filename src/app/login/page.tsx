'use client'

/**
 * Login page for single-user authentication
 */

import { useState, useEffect, Suspense } from 'react'
import { useRouter } from 'next/navigation'
import dynamic from 'next/dynamic'
import Image from 'next/image'
import { Button } from '@/view/components/ui/Button'
import { Input } from '@/view/components/ui/Input'
import { Card } from '@/view/components/ui/Card'

// Use lightweight CSRF protection for better performance
import { useLightweightFormCSRF } from '@/hooks/useLightweightCSRF'

// Lazy load debug utilities only when needed
const debugUtils = {
  shouldPreventAutoReload: () => false, // Default safe value
  shouldUseEnhancedErrorLogging: () => false,
  safeReload: (reason?: string) => {
    if (typeof window !== 'undefined') {
      console.log(`Reloading page: ${reason || 'Unknown reason'}`)
      window.location.reload()
    }
  },
  getPersistedErrors: () => [],
  clearPersistedErrors: () => {}
}

// Simple logger for login page to avoid heavy imports
const simpleLogger = {
  info: (component: string, message: string, data?: any) => {
    console.log(`[${component}] ${message}`, data || '')
  },
  warn: (component: string, message: string, data?: any) => {
    console.warn(`[${component}] ${message}`, data || '')
  },
  error: (component: string, message: string, data?: any) => {
    console.error(`[${component}] ${message}`, data || '')
  }
}

export default function LoginPage() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState('')
  const [retryAfter, setRetryAfter] = useState(0)
  const [debugInfo, setDebugInfo] = useState<any>(null)
  const router = useRouter()

  // Lightweight CSRF Protection for better performance
  const {
    csrfToken,
    submitForm,
    isLoading: csrfLoading,
    error: csrfError,
    getCSRFInput,
  } = useLightweightFormCSRF()

  // Check for persisted errors on component mount (simplified)
  useEffect(() => {
    if (debugUtils.shouldUseEnhancedErrorLogging()) {
      const persistedErrors = debugUtils.getPersistedErrors()
      if (persistedErrors.length > 0) {
        setDebugInfo({
          persistedErrors: persistedErrors.slice(0, 5), // Show last 5 errors
        })
      }
    }
  }, [])

  const checkAuthStatus = async () => {
    try {
      const response = await fetch('/api/auth', {
        method: 'GET',
        credentials: 'include',
      })

      if (response.ok) {
        const data = await response.json()
        if (data.authenticated) {
          // Already authenticated, redirect to main app
          // Use window.location.href for more reliable redirect
          window.location.href = '/'
        }
        // If not authenticated, stay on login page
      }
    } catch (_error) {
      // Error checking auth status, stay on login page
      simpleLogger.info('Login', 'Error checking authentication status')
    }
  }

  // Check if already authenticated
  useEffect(() => {
    checkAuthStatus()
  }, []) // Remove checkAuthStatus from dependencies to avoid the hoisting issue

  // Countdown timer for retry after rate limiting
  useEffect(() => {
    if (retryAfter > 0) {
      const timer = setInterval(() => {
        setRetryAfter(prev => {
          if (prev <= 1) {
            setError('')
            return 0
          }
          return prev - 1
        })
      }, 1000)

      return () => clearInterval(timer)
    }
    // Return undefined for the else case
    return undefined
  }, [retryAfter])

  const handleSubmit = async (e: React.FormEvent): Promise<void> => {
    e.preventDefault()

    // Debug logging
    simpleLogger.info('Login', 'Form submission started', {
      username: username.trim(),
      hasPassword: !!password,
      csrfToken: !!csrfToken,
      csrfLoading,
      retryAfter,
      isLoading
    })

    if (retryAfter > 0) {
      simpleLogger.warn('Login', 'Form submission blocked due to retry timeout', { retryAfter })
      return
    }

    // Check if button should be disabled
    const shouldBeDisabled = isLoading || csrfLoading || retryAfter > 0 || !username.trim() || !password || !csrfToken
    if (shouldBeDisabled) {
      simpleLogger.warn('Login', 'Form submission blocked due to disabled conditions', {
        isLoading,
        csrfLoading,
        retryAfter,
        hasUsername: !!username.trim(),
        hasPassword: !!password,
        hasCsrfToken: !!csrfToken
      })
      setError('Form is not ready for submission. Please ensure all fields are filled and try again.')
      return
    }

    setIsLoading(true)
    setError('')

    try {
      simpleLogger.info('Login', 'Attempting CSRF-protected form submission')

      // Use CSRF-protected form submission
      const response = await submitForm('/api/auth', {
        username: username.trim(),
        password,
      })

      simpleLogger.info('Login', 'Form submission response received', {
        status: response.status,
        ok: response.ok
      })

      const data = await response.json()

      if (response.ok) {
        simpleLogger.info('Login', 'Login successful')

        // Add a longer delay to ensure session cookie is properly set
        await new Promise(resolve => setTimeout(resolve, 500))

        // Verify session is working before redirecting
        try {
          const sessionCheck = await fetch('/api/auth', {
            method: 'GET',
            credentials: 'include',
          })

          if (sessionCheck.ok) {
            const sessionData = await sessionCheck.json()
            if (sessionData.authenticated) {
              simpleLogger.info('Login', 'Session verified, redirecting to dashboard')
              // Use window.location.href for more reliable redirect that bypasses Next.js router
              window.location.href = '/'
            } else {
              simpleLogger.warn('Login', 'Session not authenticated after login')
              setError('Login succeeded but session verification failed. Please try again.')
            }
          } else {
            simpleLogger.warn('Login', 'Session verification request failed')
            setError('Login succeeded but session verification failed. Please try again.')
          }
        } catch (sessionError) {
          simpleLogger.error('Login', 'Session verification error', sessionError)
          setError('Login succeeded but session verification failed. Please try again.')
        }
      } else {
        if (response.status === 429) {
          // Rate limited
          setRetryAfter(data.retryAfter || 60)
          setError(`Too many failed attempts. Please wait ${data.retryAfter || 60} seconds.`)
        } else if (response.status === 403 && data.needsRefresh) {
          // CSRF token needs refresh
          setError('Security token expired. Please try again.')
        } else {
          setError(data.error || 'Login failed')
        }
      }
    } catch (error) {
      simpleLogger.error('Login', 'Login request failed', error)
      if (error instanceof Error && error.message.includes('CSRF')) {
        setError('Security validation failed. Please refresh the page and try again.')
      } else {
        setError('Network error. Please try again.')
      }
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        <div>
          <div className="flex items-center justify-center gap-3 mb-2">
            <Image
              src="/favicon.ico"
              alt="Business Scraper Logo"
              width={40}
              height={40}
              className="object-contain"
              priority
              sizes="40px"
              quality={90}
            />
            <h2 className="text-3xl font-extrabold text-gray-900">Business Scraper</h2>
          </div>
          <p className="mt-2 text-center text-sm text-gray-600">
            Sign in to access the application
          </p>
        </div>

        <Card className="p-8">
          <form className="space-y-6" onSubmit={handleSubmit}>
            <div>
              <label htmlFor="username" className="sr-only">
                Username
              </label>
              <Input
                id="username"
                name="username"
                type="text"
                autoComplete="username"
                required
                placeholder="Username"
                value={username}
                onChange={e => setUsername(e.target.value)}
                disabled={isLoading || retryAfter > 0}
                className="relative block w-full"
              />
            </div>

            <div>
              <label htmlFor="password" className="sr-only">
                Password
              </label>
              <Input
                id="password"
                name="password"
                type="password"
                autoComplete="current-password"
                required
                placeholder="Password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                disabled={isLoading || retryAfter > 0}
                className="relative block w-full"
              />
            </div>

            {/* Show error messages only if not loading and there's a real error */}
            {error && !csrfLoading && (
              <div className="rounded-md bg-red-50 p-4">
                <div className="text-sm text-red-700">
                  {error}
                  {retryAfter > 0 && (
                    <div className="mt-1 font-medium">Retry in {retryAfter} seconds</div>
                  )}
                </div>
              </div>
            )}

            {/* Debug information in development */}
            {process.env.NODE_ENV === 'development' && (
              <div className="rounded-md bg-blue-50 p-4 mb-4">
                <div className="text-xs text-blue-700">
                  <div><strong>Debug Info:</strong></div>
                  <div>CSRF Token: {csrfToken ? 'Present' : 'Missing'}</div>
                  <div>CSRF Loading: {csrfLoading ? 'Yes' : 'No'}</div>
                  <div>CSRF Error: {csrfError || 'None'}</div>
                  <div>Username: {username ? 'Present' : 'Empty'}</div>
                  <div>Password: {password ? 'Present' : 'Empty'}</div>
                  <div>Retry After: {retryAfter}</div>
                  <div>Is Loading: {isLoading ? 'Yes' : 'No'}</div>
                  <div>Button Disabled: {(isLoading || csrfLoading || retryAfter > 0 || !username.trim() || !password || !csrfToken) ? 'Yes' : 'No'}</div>
                </div>
              </div>
            )}

            {/* Show CSRF error with better messaging */}
            {csrfError && !csrfLoading && (
              <div className="rounded-md bg-red-50 p-4">
                <div className="text-sm text-red-700">
                  {csrfError.includes('401')
                    ? 'Security token initialization failed. Please refresh the page.'
                    : csrfError
                  }
                  {(csrfError.includes('after') || csrfError.includes('Authentication error')) && (
                    <div className="mt-1">
                      <button
                        onClick={() => debugUtils.safeReload('CSRF error recovery')}
                        className="text-red-800 underline hover:text-red-900"
                      >
                        {debugUtils.shouldPreventAutoReload() ? 'Reload Prevented (Debug Mode)' : 'Refresh page'}
                      </button>
                      {debugUtils.shouldPreventAutoReload() && (
                        <div className="mt-2 text-xs text-red-600">
                          Debug mode is active. Auto-reload prevented for debugging.
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Show loading message only during initial load or when explicitly loading */}
            {csrfLoading && !csrfToken && (
              <div className="rounded-md bg-blue-50 p-4">
                <div className="text-sm text-blue-700">Loading security token...</div>
                {debugUtils.shouldUseEnhancedErrorLogging() && (
                  <div className="mt-2 text-xs text-blue-600">
                    Debug mode active - Enhanced error logging enabled
                  </div>
                )}
              </div>
            )}

            {/* Debug Information Panel */}
            {debugUtils.shouldUseEnhancedErrorLogging() && debugInfo && (
              <div className="rounded-md bg-yellow-50 p-4 border border-yellow-200">
                <div className="text-sm text-yellow-800">
                  <div className="font-semibold mb-2">🐛 Debug Information</div>

                  {debugInfo.persistedErrors && debugInfo.persistedErrors.length > 0 && (
                    <div className="mb-3">
                      <div className="font-medium text-xs mb-1">Recent Errors:</div>
                      {debugInfo.persistedErrors.map((error: any, index: number) => (
                        <div key={index} className="text-xs bg-yellow-100 p-2 rounded mb-1">
                          <div className="font-mono">{error.id}</div>
                          <div>{error.message}</div>
                          <div className="text-yellow-600">{new Date(error.timestamp).toLocaleString()}</div>
                        </div>
                      ))}
                    </div>
                  )}

                  {debugInfo.errorPatterns && debugInfo.errorPatterns.length > 0 && (
                    <div className="mb-3">
                      <div className="font-medium text-xs mb-1">Error Patterns:</div>
                      {debugInfo.errorPatterns.map((pattern: any, index: number) => (
                        <div key={index} className="text-xs">
                          {pattern.type}: {pattern.count} occurrences
                        </div>
                      ))}
                    </div>
                  )}

                  <div className="flex gap-2 mt-3">
                    <button
                      onClick={() => debugUtils.clearPersistedErrors()}
                      className="text-xs bg-yellow-200 hover:bg-yellow-300 px-2 py-1 rounded"
                    >
                      Clear Debug Data
                    </button>
                    <button
                      onClick={() => setDebugInfo(null)}
                      className="text-xs bg-yellow-200 hover:bg-yellow-300 px-2 py-1 rounded"
                    >
                      Hide Debug Panel
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* CSRF Token Input */}
            {(() => {
              const csrfInput = getCSRFInput()
              return csrfInput ? (
                <input
                  type="hidden"
                  name={csrfInput.name}
                  value={csrfInput.value}
                />
              ) : null
            })()}

            <div>
              <Button
                type="submit"
                disabled={
                  isLoading ||
                  csrfLoading ||
                  retryAfter > 0 ||
                  !username.trim() ||
                  !password ||
                  !csrfToken
                }
                className="group relative w-full flex justify-center"
              >
                {isLoading ? (
                  <span className="flex items-center">
                    <svg
                      className="animate-spin -ml-1 mr-3 h-5 w-5 text-white"
                      xmlns="http://www.w3.org/2000/svg"
                      fill="none"
                      viewBox="0 0 24 24"
                    >
                      <circle
                        className="opacity-25"
                        cx="12"
                        cy="12"
                        r="10"
                        stroke="currentColor"
                        strokeWidth="4"
                      ></circle>
                      <path
                        className="opacity-75"
                        fill="currentColor"
                        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                      ></path>
                    </svg>
                    Signing in...
                  </span>
                ) : retryAfter > 0 ? (
                  `Wait ${retryAfter}s`
                ) : (
                  'Sign in'
                )}
              </Button>
            </div>
          </form>
        </Card>

        <div className="text-center">
          <p className="text-xs text-gray-500">
            This is a single-user application. Contact your administrator for access.
          </p>
        </div>
      </div>
    </div>
  )
}
