'use client'

/**
 * Login page for single-user authentication
 */

import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { Button } from '@/view/components/ui/Button'
import { Input } from '@/view/components/ui/Input'
import { Card } from '@/view/components/ui/Card'
import { logger } from '@/utils/logger'

export default function LoginPage() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState('')
  const [retryAfter, setRetryAfter] = useState(0)
  const router = useRouter()

  // Check if already authenticated
  useEffect(() => {
    checkAuthStatus()
  }, [])

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

  const checkAuthStatus = async () => {
    try {
      const response = await fetch('/api/auth', {
        method: 'GET',
        credentials: 'include'
      })

      if (response.ok) {
        // Already authenticated, redirect to main app
        router.push('/')
      }
    } catch (error) {
      // Not authenticated, stay on login page
      logger.info('Login', 'User not authenticated')
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    
    if (retryAfter > 0) {
      return
    }

    setIsLoading(true)
    setError('')

    try {
      const response = await fetch('/api/auth', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          username: username.trim(),
          password
        })
      })

      const data = await response.json()

      if (response.ok) {
        logger.info('Login', 'Login successful')
        router.push('/')
      } else {
        if (response.status === 429) {
          // Rate limited
          setRetryAfter(data.retryAfter || 60)
          setError(`Too many failed attempts. Please wait ${data.retryAfter || 60} seconds.`)
        } else {
          setError(data.error || 'Login failed')
        }
      }
    } catch (error) {
      logger.error('Login', 'Login request failed', error)
      setError('Network error. Please try again.')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        <div>
          <div className="flex items-center justify-center gap-3 mb-2">
            <img
              src="/favicon.ico"
              alt="Business Scraper Logo"
              className="h-10 w-10 object-contain"
            />
            <h2 className="text-3xl font-extrabold text-gray-900">
              Business Scraper
            </h2>
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
                onChange={(e) => setUsername(e.target.value)}
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
                onChange={(e) => setPassword(e.target.value)}
                disabled={isLoading || retryAfter > 0}
                className="relative block w-full"
              />
            </div>

            {error && (
              <div className="rounded-md bg-red-50 p-4">
                <div className="text-sm text-red-700">
                  {error}
                  {retryAfter > 0 && (
                    <div className="mt-1 font-medium">
                      Retry in {retryAfter} seconds
                    </div>
                  )}
                </div>
              </div>
            )}

            <div>
              <Button
                type="submit"
                disabled={isLoading || retryAfter > 0 || !username.trim() || !password}
                className="group relative w-full flex justify-center"
              >
                {isLoading ? (
                  <span className="flex items-center">
                    <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
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
