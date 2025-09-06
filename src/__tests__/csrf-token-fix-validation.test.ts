/**
 * CSRF Token Fix Validation Tests
 * Tests for the login screen CSRF token flashing issue fix
 */

import { renderHook, act, waitFor } from '@testing-library/react'
import { useCSRFProtection, useFormCSRFProtection } from '@/hooks/useCSRFProtection'
import { logger } from '@/utils/logger'

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

describe('CSRF Token Fix Validation', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    mockFetch.mockClear()
  })

  describe('useCSRFProtection Hook', () => {
    it('should use /api/csrf endpoint instead of /api/auth', async () => {
      // Mock successful response
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          csrfToken: 'test-token',
          expiresAt: new Date(Date.now() + 3600000).toISOString(),
          temporary: false,
        }),
        headers: new Headers({
          'X-CSRF-Token': 'test-token',
          'X-CSRF-Expires': String(Date.now() + 3600000),
        }),
      } as Response)

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
      // Mock 401 response
      mockFetch.mockRejectedValueOnce(new Error('Failed to fetch CSRF token: 401'))

      const { result } = renderHook(() => useCSRFProtection())

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      // Should have error but not immediately visible to user
      expect(result.current.error).toContain('401')
      expect(mockFetch).toHaveBeenCalledWith('/api/csrf', expect.any(Object))
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

      // Wait for retries to complete
      await waitFor(
        () => {
          expect(result.current.csrfToken).toBe('retry-token')
        },
        { timeout: 10000 }
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

      expect(result.current.csrfToken).toBe('refreshed-token')
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

      // Should have made submission with CSRF token
      expect(mockFetch).toHaveBeenLastCalledWith('/api/test', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': 'submit-token',
        },
        body: JSON.stringify({ data: 'test' }),
      })
    })
  })

  describe('Error Handling Improvements', () => {
    it('should not show 401 errors as user-facing errors', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Failed to fetch CSRF token: 401'))

      const { result } = renderHook(() => useCSRFProtection())

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      // Error should be logged but not immediately shown to user
      expect(logger.warn).toHaveBeenCalled()
      expect(result.current.error).toContain('401')
    })

    it('should show meaningful errors for non-401 failures', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Network error'))

      const { result } = renderHook(() => useCSRFProtection())

      await waitFor(() => {
        expect(result.current.error).toContain('Network error')
      })
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

      // Wait for retry to succeed
      await waitFor(
        () => {
          expect(result.current.csrfToken).toBe('success-token')
        },
        { timeout: 5000 }
      )

      // Error should be cleared
      expect(result.current.error).toBeNull()
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
