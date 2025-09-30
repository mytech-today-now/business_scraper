/**
 * CSRF Token Fix Validation Tests
 * Tests for the login screen CSRF token flashing issue fix
 */

import { renderHook, act, waitFor } from '@testing-library/react'
import { useCSRFProtection, useFormCSRFProtection } from '@/hooks/useCSRFProtection'
import { logger } from '@/utils/logger'
import { mockFetchResponses } from './utils/commonMocks'
import { createMockResponse } from './utils/mockTypeHelpers'

// Mock fetch
global.fetch = jest.fn()
const mockFetch = fetch as jest.MockedFunction<typeof fetch>

// Mock logger
jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  },
}))

// Mock enhanced error logger
jest.mock('@/utils/enhancedErrorLogger', () => ({
  securityTokenErrorLogger: {
    logCSRFError: jest.fn(),
    logNetworkError: jest.fn(),
  },
  fetchWithErrorLogging: jest.fn(),
}))

import { fetchWithErrorLogging } from '@/utils/enhancedErrorLogger'
const mockFetchWithErrorLogging = fetchWithErrorLogging as jest.MockedFunction<typeof fetchWithErrorLogging>

describe('CSRF Token Fix Validation', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    mockFetch.mockClear()
    mockFetchWithErrorLogging.mockClear()
  })

  describe('useCSRFProtection Hook', () => {
    it('should use /api/csrf endpoint instead of /api/auth', async () => {
      // Mock successful response
      mockFetch.mockResolvedValueOnce(createMockResponse({
        csrfToken: 'test-token',
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
        temporary: false,
      }, {
        headers: {
          'X-CSRF-Token': 'test-token',
          'X-CSRF-Expires': String(Date.now() + 3600000),
        }
      }))

      const { result } = renderHook(() => useCSRFProtection())

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      // Verify the correct endpoint was called
      expect(mockFetch).toHaveBeenCalledWith('/api/csrf', {
        method: 'GET',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
        },
      })

      // Verify token was set
      expect(result.current.csrfToken).toBe('test-token')
      expect(result.current.error).toBeNull()
    })

    it('should handle 401 errors gracefully without flashing', async () => {
      // Mock 401 response from fetchWithErrorLogging
      mockFetchWithErrorLogging.mockResolvedValueOnce({
        ok: false,
        status: 401,
        statusText: 'Unauthorized',
        json: async () => ({}),
        headers: new Headers(),
      } as Response)

      const { result } = renderHook(() => useCSRFProtection())

      // Wait for some state change
      await waitFor(() => {
        // Log current state for debugging
        console.log('Current hook state:', {
          isLoading: result.current.isLoading,
          error: result.current.error,
          csrfToken: result.current.csrfToken
        })

        // Wait for either error to be set or loading to be false
        return result.current.error !== null || result.current.isLoading === false
      }, { timeout: 5000 })

      // Check what we got
      console.log('Final state:', {
        isLoading: result.current.isLoading,
        error: result.current.error,
        csrfToken: result.current.csrfToken
      })

      // Should have error but with user-friendly message (not raw 401)
      expect(result.current.error).toBe('Authentication error - please refresh the page')
      expect(result.current.isLoading).toBe(false)
      expect(mockFetchWithErrorLogging).toHaveBeenCalledWith('/api/csrf', expect.any(Object), expect.any(Object))
    })

    it('should implement retry logic with exponential backoff', async () => {
      // Mock multiple failures then success
      mockFetch
        .mockRejectedValueOnce(new Error('Network error'))
        .mockRejectedValueOnce(new Error('Network error'))
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            csrfToken: 'retry-token',
            expiresAt: new Date(Date.now() + 3600000).toISOString(),
          }),
          headers: new Headers(),
        } as Response)

      const { result } = renderHook(() => useCSRFProtection())

      // Wait for retries to complete with real timers
      await waitFor(
        () => {
          expect(result.current.csrfToken).toBe('retry-token')
        },
        { timeout: 10000 } // Allow enough time for retries
      )

      // Should have made multiple attempts
      expect(mockFetch).toHaveBeenCalledTimes(3)
    })

    it('should validate token expiration correctly', async () => {
      const futureTime = Date.now() + 10 * 60 * 1000 // 10 minutes from now
      
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          csrfToken: 'valid-token',
          expiresAt: new Date(futureTime).toISOString(),
        }),
        headers: new Headers(),
      } as Response)

      const { result } = renderHook(() => useCSRFProtection())

      await waitFor(() => {
        expect(result.current.csrfToken).toBe('valid-token')
      })

      // Token should be valid
      expect(result.current.isTokenValid()).toBe(true)
    })

    it('should refresh token when near expiration', async () => {
      const nearExpiryTime = Date.now() + 2 * 60 * 1000 // 2 minutes from now
      
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            csrfToken: 'expiring-token',
            expiresAt: new Date(nearExpiryTime).toISOString(),
          }),
          headers: new Headers(),
        } as Response)
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            csrfToken: 'refreshed-token',
            expiresAt: new Date(Date.now() + 3600000).toISOString(),
          }),
          headers: new Headers(),
        } as Response)

      const { result } = renderHook(() => useCSRFProtection())

      await waitFor(() => {
        expect(result.current.csrfToken).toBe('expiring-token')
      })

      // Token should be considered invalid due to near expiration
      expect(result.current.isTokenValid()).toBe(false)

      // Should trigger refresh
      await act(async () => {
        await result.current.refreshToken()
      })

      await waitFor(() => {
        expect(result.current.csrfToken).toBe('refreshed-token')
      })
    })
  })

  describe('useFormCSRFProtection Hook', () => {
    it('should provide correct headers for form submission', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          csrfToken: 'form-token',
          expiresAt: new Date(Date.now() + 3600000).toISOString(),
        }),
        headers: new Headers(),
      } as Response)

      const { result } = renderHook(() => useFormCSRFProtection())

      await waitFor(() => {
        expect(result.current.csrfToken).toBe('form-token')
      })

      // Should provide CSRF input field
      const csrfInput = result.current.getCSRFInput()
      expect(csrfInput).toEqual({
        name: 'csrf_token',
        type: 'hidden',
        value: 'form-token',
      })
    })

    it('should handle form submission with CSRF protection', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            csrfToken: 'submit-token',
            expiresAt: new Date(Date.now() + 3600000).toISOString(),
          }),
          headers: new Headers(),
        } as Response)
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ success: true }),
          headers: new Headers(),
        } as Response)

      const { result } = renderHook(() => useFormCSRFProtection())

      await waitFor(() => {
        expect(result.current.csrfToken).toBe('submit-token')
      })

      // Submit form
      await act(async () => {
        await result.current.submitForm('/api/test', { data: 'test' })
      })

      // Should have made submission with CSRF token in both headers and body
      expect(mockFetch).toHaveBeenLastCalledWith('/api/test', {
        method: 'POST',
        credentials: 'include',
        headers: expect.any(Headers),
        body: JSON.stringify({ data: 'test', csrf_token: 'submit-token' }),
      })

      // Verify headers contain CSRF token
      const lastCall = mockFetch.mock.calls[mockFetch.mock.calls.length - 1]
      const headers = lastCall[1].headers
      expect(headers.get('X-CSRF-Token')).toBe('submit-token')
      expect(headers.get('Content-Type')).toBe('application/json')
    })
  })

  describe('Error Handling Improvements', () => {
    it('should not show 401 errors as user-facing errors', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        statusText: 'Unauthorized',
        json: async () => ({}),
        headers: new Headers(),
      } as Response)

      const { result } = renderHook(() => useCSRFProtection())

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      // Error should be logged but show user-friendly message (not raw 401)
      expect(result.current.error).toBe('Authentication error - please refresh the page')
    })

    it('should show meaningful errors for non-401 failures', async () => {
      // Mock network error that exhausts all retries
      mockFetch
        .mockRejectedValueOnce(new Error('Network error'))
        .mockRejectedValueOnce(new Error('Network error'))
        .mockRejectedValueOnce(new Error('Network error'))
        .mockRejectedValueOnce(new Error('Network error'))

      const { result } = renderHook(() => useCSRFProtection())

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      }, { timeout: 10000 })

      expect(result.current.error).toContain('Network error')
    })

    it('should clear errors on successful retry', async () => {
      mockFetch
        .mockRejectedValueOnce(new Error('Temporary error'))
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            csrfToken: 'success-token',
            expiresAt: new Date(Date.now() + 3600000).toISOString(),
          }),
          headers: new Headers(),
        } as Response)

      const { result } = renderHook(() => useCSRFProtection())

      // Wait for retry to succeed with longer timeout
      await waitFor(
        () => {
          expect(result.current.csrfToken).toBe('success-token')
        },
        { timeout: 10000 }
      )

      // Error should be cleared and loading should be false
      expect(result.current.error).toBeNull()
      expect(result.current.isLoading).toBe(false)
    })
  })

  describe('Performance and Reliability', () => {
    it('should not make excessive requests', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({
          csrfToken: 'stable-token',
          expiresAt: new Date(Date.now() + 3600000).toISOString(),
        }),
        headers: new Headers(),
      } as Response)

      const { result } = renderHook(() => useCSRFProtection())

      await waitFor(() => {
        expect(result.current.csrfToken).toBe('stable-token')
      })

      // Should only make one initial request
      expect(mockFetch).toHaveBeenCalledTimes(1)

      // Multiple calls to isTokenValid should not trigger new requests
      result.current.isTokenValid()
      result.current.isTokenValid()
      result.current.isTokenValid()

      expect(mockFetch).toHaveBeenCalledTimes(1)
    })

    it('should handle concurrent requests gracefully', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({
          csrfToken: 'concurrent-token',
          expiresAt: new Date(Date.now() + 3600000).toISOString(),
        }),
        headers: new Headers(),
      } as Response)

      // Render multiple hooks simultaneously
      const { result: result1 } = renderHook(() => useCSRFProtection())
      const { result: result2 } = renderHook(() => useCSRFProtection())

      await waitFor(() => {
        expect(result1.current.csrfToken).toBe('concurrent-token')
        expect(result2.current.csrfToken).toBe('concurrent-token')
      })

      // Should handle concurrent requests without issues
      expect(result1.current.error).toBeNull()
      expect(result2.current.error).toBeNull()
    })
  })
})
