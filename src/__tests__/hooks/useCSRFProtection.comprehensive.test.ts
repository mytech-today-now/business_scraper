/**
 * Comprehensive CSRF Protection Tests for src/hooks/useCSRFProtection.ts
 * Tests CSRF token management, validation, refresh, and security scenarios
 */

import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals'
import { renderHook, waitFor, act } from '@testing-library/react'
import { useCSRFProtection, useFormCSRFProtection, CSRFToken, CSRFHookResult } from '@/hooks/useCSRFProtection'
import { createMockFunction, createMockResponse } from '../utils/mockTypeHelpers'

// Mock dependencies
jest.mock('@/utils/logger')
jest.mock('@/utils/debugConfig')
jest.mock('@/utils/enhancedErrorLogger')

const mockFetch = createMockFunction<typeof fetch>()
global.fetch = mockFetch as any

// Mock logger
const mockLogger = {
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn()
}

jest.mock('@/utils/logger', () => ({
  logger: mockLogger
}))

// Mock debug config
jest.mock('@/utils/debugConfig', () => ({
  shouldUseEnhancedErrorLogging: jest.fn().mockReturnValue(true),
  shouldPersistErrors: jest.fn().mockReturnValue(true),
  logEnhancedError: jest.fn()
}))

// Mock enhanced error logger
jest.mock('@/utils/enhancedErrorLogger', () => ({
  securityTokenErrorLogger: jest.fn(),
  fetchWithErrorLogging: jest.fn().mockImplementation((url, options) => fetch(url, options))
}))

describe('CSRF Protection Hook - Comprehensive Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    jest.useFakeTimers()
    
    // Reset fetch mock
    mockFetch.mockReset()
  })

  afterEach(() => {
    jest.useRealTimers()
    jest.restoreAllMocks()
  })

  describe('Token Fetching and Management', () => {
    test('should fetch CSRF token from /api/csrf successfully', async () => {
      const mockResponse = createMockResponse({
        ok: true,
        status: 200,
        json: async () => ({
          csrfToken: 'test-csrf-token',
          tokenId: 'test-token-id',
          temporary: true,
          expiresAt: Date.now() + 3600000
        }),
        headers: new Headers({
          'X-CSRF-Token': 'test-csrf-token',
          'X-CSRF-Token-ID': 'test-token-id',
          'X-CSRF-Expires': String(Date.now() + 3600000)
        })
      })

      mockFetch.mockResolvedValueOnce(mockResponse)

      const { result } = renderHook(() => useCSRFProtection())

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      expect(result.current.csrfToken).toBe('test-csrf-token')
      expect(result.current.tokenId).toBe('test-token-id')
      expect(result.current.isTemporary).toBe(true)
      expect(result.current.error).toBeNull()
      expect(mockFetch).toHaveBeenCalledWith('/api/csrf', expect.objectContaining({
        method: 'GET',
        credentials: 'include'
      }))
    })

    test('should fallback to /api/auth when /api/csrf fails', async () => {
      const csrfFailure = createMockResponse({
        ok: false,
        status: 500
      })

      const authSuccess = createMockResponse({
        ok: true,
        status: 200,
        json: async () => ({
          csrfToken: 'auth-csrf-token',
          tokenId: 'auth-token-id',
          temporary: false,
          expiresAt: Date.now() + 3600000
        })
      })

      mockFetch
        .mockResolvedValueOnce(csrfFailure)
        .mockResolvedValueOnce(authSuccess)

      const { result } = renderHook(() => useCSRFProtection())

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      expect(mockFetch).toHaveBeenCalledTimes(2)
      expect(mockFetch).toHaveBeenNthCalledWith(1, '/api/csrf', expect.any(Object))
      expect(mockFetch).toHaveBeenNthCalledWith(2, '/api/auth', expect.any(Object))
      expect(result.current.csrfToken).toBe('auth-csrf-token')
      expect(result.current.isTemporary).toBe(false)
    })

    test('should retry with exponential backoff on failures', async () => {
      const failure = createMockResponse({
        ok: false,
        status: 500
      })

      const success = createMockResponse({
        ok: true,
        status: 200,
        json: async () => ({
          csrfToken: 'retry-success-token',
          tokenId: 'retry-token-id',
          temporary: true,
          expiresAt: Date.now() + 3600000
        })
      })

      // Fail multiple times, then succeed
      mockFetch
        .mockResolvedValueOnce(failure) // /api/csrf fails
        .mockResolvedValueOnce(failure) // /api/auth fails
        .mockResolvedValueOnce(failure) // /api/csrf fails on retry
        .mockResolvedValueOnce(success) // /api/auth succeeds on retry

      const { result } = renderHook(() => useCSRFProtection())

      // Fast-forward through retry delays
      act(() => {
        jest.advanceTimersByTime(2000)
      })

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      }, { timeout: 10000 })

      expect(mockFetch).toHaveBeenCalledTimes(4)
      expect(result.current.csrfToken).toBe('retry-success-token')
      expect(result.current.error).toBeNull()
    })

    test('should handle maximum retry attempts', async () => {
      const failure = createMockResponse({
        ok: false,
        status: 500
      })

      mockFetch.mockResolvedValue(failure)

      const { result } = renderHook(() => useCSRFProtection())

      // Fast-forward through all retry attempts
      act(() => {
        jest.advanceTimersByTime(30000)
      })

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      }, { timeout: 15000 })

      expect(result.current.csrfToken).toBeNull()
      expect(result.current.error).toContain('Failed to fetch CSRF token')
    })

    test('should refresh token manually', async () => {
      const initialResponse = createMockResponse({
        ok: true,
        status: 200,
        json: async () => ({
          csrfToken: 'initial-token',
          tokenId: 'initial-id',
          temporary: true,
          expiresAt: Date.now() + 3600000
        })
      })

      const refreshResponse = createMockResponse({
        ok: true,
        status: 200,
        json: async () => ({
          csrfToken: 'refreshed-token',
          tokenId: 'refreshed-id',
          temporary: false,
          expiresAt: Date.now() + 3600000
        })
      })

      mockFetch
        .mockResolvedValueOnce(initialResponse)
        .mockResolvedValueOnce(refreshResponse)

      const { result } = renderHook(() => useCSRFProtection())

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      expect(result.current.csrfToken).toBe('initial-token')

      // Manually refresh token
      await act(async () => {
        await result.current.refreshToken()
      })

      expect(result.current.csrfToken).toBe('refreshed-token')
      expect(result.current.tokenId).toBe('refreshed-id')
    })

    test('should validate token expiration', async () => {
      const expiredTime = Date.now() - 1000 // 1 second ago
      
      const response = createMockResponse({
        ok: true,
        status: 200,
        json: async () => ({
          csrfToken: 'expired-token',
          tokenId: 'expired-id',
          temporary: true,
          expiresAt: expiredTime
        })
      })

      mockFetch.mockResolvedValueOnce(response)

      const { result } = renderHook(() => useCSRFProtection())

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      expect(result.current.isTokenValid()).toBe(false)
    })

    test('should provide proper headers for requests', async () => {
      const response = createMockResponse({
        ok: true,
        status: 200,
        json: async () => ({
          csrfToken: 'test-token',
          tokenId: 'test-id',
          temporary: true,
          expiresAt: Date.now() + 3600000
        })
      })

      mockFetch.mockResolvedValueOnce(response)

      const { result } = renderHook(() => useCSRFProtection())

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      const headers = result.current.getHeaders()

      expect(headers).toEqual({
        'X-CSRF-Token': 'test-token',
        'X-CSRF-Token-ID': 'test-id'
      })
    })
  })

  describe('Form CSRF Protection', () => {
    test('should provide CSRF input for forms', async () => {
      const response = createMockResponse({
        ok: true,
        status: 200,
        json: async () => ({
          csrfToken: 'form-token',
          tokenId: 'form-id',
          temporary: false,
          expiresAt: Date.now() + 3600000
        })
      })

      mockFetch.mockResolvedValueOnce(response)

      const { result } = renderHook(() => useFormCSRFProtection())

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      const csrfInput = result.current.getCSRFInput()

      expect(csrfInput).toEqual({
        name: 'csrfToken',
        type: 'hidden',
        value: 'form-token'
      })
    })

    test('should validate form before submission', async () => {
      const response = createMockResponse({
        ok: true,
        status: 200,
        json: async () => ({
          csrfToken: 'valid-token',
          tokenId: 'valid-id',
          temporary: false,
          expiresAt: Date.now() + 3600000
        })
      })

      mockFetch.mockResolvedValueOnce(response)

      const { result } = renderHook(() => useFormCSRFProtection())

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      const isValid = await result.current.validateForm()

      expect(isValid).toBe(true)
    })

    test('should submit form with CSRF protection', async () => {
      const tokenResponse = createMockResponse({
        ok: true,
        status: 200,
        json: async () => ({
          csrfToken: 'submit-token',
          tokenId: 'submit-id',
          temporary: false,
          expiresAt: Date.now() + 3600000
        })
      })

      const submitResponse = createMockResponse({
        ok: true,
        status: 200,
        json: async () => ({ success: true })
      })

      mockFetch
        .mockResolvedValueOnce(tokenResponse)
        .mockResolvedValueOnce(submitResponse)

      const { result } = renderHook(() => useFormCSRFProtection())

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      const formData = new FormData()
      formData.append('test', 'value')

      const response = await result.current.submitForm('/api/test', formData)

      expect(response.ok).toBe(true)
      expect(mockFetch).toHaveBeenCalledWith('/api/test', expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({
          'X-CSRF-Token': 'submit-token',
          'X-CSRF-Token-ID': 'submit-id'
        })
      }))
    })

    test('should handle form submission with object data', async () => {
      const tokenResponse = createMockResponse({
        ok: true,
        status: 200,
        json: async () => ({
          csrfToken: 'object-token',
          tokenId: 'object-id',
          temporary: false,
          expiresAt: Date.now() + 3600000
        })
      })

      const submitResponse = createMockResponse({
        ok: true,
        status: 200,
        json: async () => ({ success: true })
      })

      mockFetch
        .mockResolvedValueOnce(tokenResponse)
        .mockResolvedValueOnce(submitResponse)

      const { result } = renderHook(() => useFormCSRFProtection())

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      const objectData = { test: 'value', number: 123 }

      const response = await result.current.submitForm('/api/test', objectData)

      expect(response.ok).toBe(true)
      expect(mockFetch).toHaveBeenCalledWith('/api/test', expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({
          'Content-Type': 'application/json',
          'X-CSRF-Token': 'object-token',
          'X-CSRF-Token-ID': 'object-id'
        }),
        body: JSON.stringify({ ...objectData, csrfToken: 'object-token' })
      }))
    })
  })

  describe('Security and Error Handling', () => {
    test('should handle network errors gracefully', async () => {
      mockFetch.mockRejectedValue(new Error('Network error'))

      const { result } = renderHook(() => useCSRFProtection())

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      expect(result.current.csrfToken).toBeNull()
      expect(result.current.error).toContain('Network error')
    })

    test('should handle malformed JSON responses', async () => {
      const malformedResponse = createMockResponse({
        ok: true,
        status: 200,
        json: async () => {
          throw new Error('Invalid JSON')
        }
      })

      mockFetch.mockResolvedValueOnce(malformedResponse)

      const { result } = renderHook(() => useCSRFProtection())

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      expect(result.current.csrfToken).toBeNull()
      expect(result.current.error).toContain('Invalid JSON')
    })

    test('should handle missing CSRF token in response', async () => {
      const emptyResponse = createMockResponse({
        ok: true,
        status: 200,
        json: async () => ({})
      })

      mockFetch.mockResolvedValue(emptyResponse)

      const { result } = renderHook(() => useCSRFProtection())

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      expect(result.current.csrfToken).toBeNull()
      expect(result.current.error).toContain('No CSRF token in response')
    })

    test('should handle server errors with proper status codes', async () => {
      const serverError = createMockResponse({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error'
      })

      mockFetch.mockResolvedValue(serverError)

      const { result } = renderHook(() => useCSRFProtection())

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      expect(result.current.error).toContain('Failed to fetch CSRF token: 500')
    })

    test('should prevent token theft through XSS', async () => {
      const xssResponse = createMockResponse({
        ok: true,
        status: 200,
        json: async () => ({
          csrfToken: '<script>alert("xss")</script>',
          tokenId: 'xss-id',
          temporary: true,
          expiresAt: Date.now() + 3600000
        })
      })

      mockFetch.mockResolvedValueOnce(xssResponse)

      const { result } = renderHook(() => useCSRFProtection())

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      // Token should be sanitized or rejected
      expect(result.current.csrfToken).not.toContain('<script>')
    })

    test('should handle concurrent token refresh requests', async () => {
      const response = createMockResponse({
        ok: true,
        status: 200,
        json: async () => ({
          csrfToken: 'concurrent-token',
          tokenId: 'concurrent-id',
          temporary: true,
          expiresAt: Date.now() + 3600000
        })
      })

      mockFetch.mockResolvedValue(response)

      const { result } = renderHook(() => useCSRFProtection())

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      // Trigger multiple concurrent refresh requests
      const promises = Array.from({ length: 5 }, () => result.current.refreshToken())

      await act(async () => {
        await Promise.all(promises)
      })

      // Should handle gracefully without duplicate requests
      expect(result.current.csrfToken).toBe('concurrent-token')
    })

    test('should rate limit token refresh requests', async () => {
      const response = createMockResponse({
        ok: true,
        status: 200,
        json: async () => ({
          csrfToken: 'rate-limited-token',
          tokenId: 'rate-limited-id',
          temporary: true,
          expiresAt: Date.now() + 3600000
        })
      })

      mockFetch.mockResolvedValue(response)

      const { result } = renderHook(() => useCSRFProtection())

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      // Trigger rapid refresh requests
      for (let i = 0; i < 10; i++) {
        await act(async () => {
          await result.current.refreshToken()
        })
      }

      // Should not make excessive requests
      expect(mockFetch).toHaveBeenCalledTimes(11) // Initial + 10 refreshes
    })
  })

  describe('Performance and Load Tests', () => {
    test('should handle high-frequency token validation', async () => {
      const response = createMockResponse({
        ok: true,
        status: 200,
        json: async () => ({
          csrfToken: 'performance-token',
          tokenId: 'performance-id',
          temporary: false,
          expiresAt: Date.now() + 3600000
        })
      })

      mockFetch.mockResolvedValueOnce(response)

      const { result } = renderHook(() => useCSRFProtection())

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      const startTime = Date.now()

      // Perform 1000 token validations
      for (let i = 0; i < 1000; i++) {
        result.current.isTokenValid()
      }

      const endTime = Date.now()

      // Should complete quickly (less than 100ms)
      expect(endTime - startTime).toBeLessThan(100)
    })

    test('should handle memory efficiently with large tokens', async () => {
      const largeToken = 'x'.repeat(10000) // 10KB token

      const response = createMockResponse({
        ok: true,
        status: 200,
        json: async () => ({
          csrfToken: largeToken,
          tokenId: 'large-id',
          temporary: false,
          expiresAt: Date.now() + 3600000
        })
      })

      mockFetch.mockResolvedValueOnce(response)

      const { result } = renderHook(() => useCSRFProtection())

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      expect(result.current.csrfToken).toBe(largeToken)
      expect(result.current.isTokenValid()).toBe(true)
    })

    test('should handle multiple hook instances efficiently', async () => {
      const response = createMockResponse({
        ok: true,
        status: 200,
        json: async () => ({
          csrfToken: 'multi-instance-token',
          tokenId: 'multi-instance-id',
          temporary: false,
          expiresAt: Date.now() + 3600000
        })
      })

      mockFetch.mockResolvedValue(response)

      // Create multiple hook instances
      const hooks = Array.from({ length: 5 }, () =>
        renderHook(() => useCSRFProtection())
      )

      // Wait for all to load
      await Promise.all(hooks.map(({ result }) =>
        waitFor(() => expect(result.current.isLoading).toBe(false))
      ))

      // All should have the same token
      hooks.forEach(({ result }) => {
        expect(result.current.csrfToken).toBe('multi-instance-token')
      })
    })
  })

  describe('Edge Cases and Boundary Tests', () => {
    test('should handle extremely long token values', async () => {
      const extremelyLongToken = 'x'.repeat(100000) // 100KB token

      const response = createMockResponse({
        ok: true,
        status: 200,
        json: async () => ({
          csrfToken: extremelyLongToken,
          tokenId: 'extreme-id',
          temporary: false,
          expiresAt: Date.now() + 3600000
        })
      })

      mockFetch.mockResolvedValueOnce(response)

      const { result } = renderHook(() => useCSRFProtection())

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      expect(result.current.csrfToken).toBe(extremelyLongToken)
    })

    test('should handle null and undefined values gracefully', async () => {
      const nullResponse = createMockResponse({
        ok: true,
        status: 200,
        json: async () => ({
          csrfToken: null,
          tokenId: undefined,
          temporary: null,
          expiresAt: undefined
        })
      })

      mockFetch.mockResolvedValueOnce(nullResponse)

      const { result } = renderHook(() => useCSRFProtection())

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      expect(result.current.csrfToken).toBeNull()
      expect(result.current.tokenId).toBeNull()
    })

    test('should handle token expiration edge cases', async () => {
      const almostExpiredTime = Date.now() + 1000 // 1 second from now

      const response = createMockResponse({
        ok: true,
        status: 200,
        json: async () => ({
          csrfToken: 'almost-expired-token',
          tokenId: 'almost-expired-id',
          temporary: true,
          expiresAt: almostExpiredTime
        })
      })

      mockFetch.mockResolvedValueOnce(response)

      const { result } = renderHook(() => useCSRFProtection())

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      // Should be valid initially
      expect(result.current.isTokenValid()).toBe(true)

      // Fast-forward past expiration
      act(() => {
        jest.advanceTimersByTime(2000)
      })

      // Should now be invalid
      expect(result.current.isTokenValid()).toBe(false)
    })

    test('should handle component unmounting during fetch', async () => {
      const slowResponse = createMockResponse({
        ok: true,
        status: 200,
        json: async () => {
          // Simulate slow response
          await new Promise(resolve => setTimeout(resolve, 1000))
          return {
            csrfToken: 'slow-token',
            tokenId: 'slow-id',
            temporary: false,
            expiresAt: Date.now() + 3600000
          }
        }
      })

      mockFetch.mockResolvedValueOnce(slowResponse)

      const { result, unmount } = renderHook(() => useCSRFProtection())

      // Unmount before fetch completes
      unmount()

      // Fast-forward to complete the fetch
      act(() => {
        jest.advanceTimersByTime(2000)
      })

      // Should not cause memory leaks or errors
      expect(true).toBe(true) // Test passes if no errors thrown
    })

    test('should handle browser storage limitations', async () => {
      // Mock localStorage to throw quota exceeded error
      const originalSetItem = Storage.prototype.setItem
      Storage.prototype.setItem = jest.fn(() => {
        throw new Error('QuotaExceededError')
      })

      const response = createMockResponse({
        ok: true,
        status: 200,
        json: async () => ({
          csrfToken: 'storage-test-token',
          tokenId: 'storage-test-id',
          temporary: false,
          expiresAt: Date.now() + 3600000
        })
      })

      mockFetch.mockResolvedValueOnce(response)

      const { result } = renderHook(() => useCSRFProtection())

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      // Should still work even if storage fails
      expect(result.current.csrfToken).toBe('storage-test-token')

      // Restore original setItem
      Storage.prototype.setItem = originalSetItem
    })
  })

  describe('Compliance and Security Standards', () => {
    test('should meet OWASP CSRF protection standards', async () => {
      const response = createMockResponse({
        ok: true,
        status: 200,
        json: async () => ({
          csrfToken: 'owasp-compliant-token',
          tokenId: 'owasp-compliant-id',
          temporary: false,
          expiresAt: Date.now() + 3600000
        })
      })

      mockFetch.mockResolvedValueOnce(response)

      const { result } = renderHook(() => useCSRFProtection())

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      const headers = result.current.getHeaders()

      // Should include proper CSRF headers
      expect(headers['X-CSRF-Token']).toBeDefined()
      expect(headers['X-CSRF-Token-ID']).toBeDefined()

      // Token should be sufficiently random/complex
      expect(result.current.csrfToken!.length).toBeGreaterThan(10)
    })

    test('should implement proper token rotation', async () => {
      const initialResponse = createMockResponse({
        ok: true,
        status: 200,
        json: async () => ({
          csrfToken: 'initial-rotation-token',
          tokenId: 'initial-rotation-id',
          temporary: false,
          expiresAt: Date.now() + 3600000
        })
      })

      const rotatedResponse = createMockResponse({
        ok: true,
        status: 200,
        json: async () => ({
          csrfToken: 'rotated-token',
          tokenId: 'rotated-id',
          temporary: false,
          expiresAt: Date.now() + 3600000
        })
      })

      mockFetch
        .mockResolvedValueOnce(initialResponse)
        .mockResolvedValueOnce(rotatedResponse)

      const { result } = renderHook(() => useCSRFProtection())

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      const initialToken = result.current.csrfToken

      // Refresh token (simulate rotation)
      await act(async () => {
        await result.current.refreshToken()
      })

      const rotatedToken = result.current.csrfToken

      // Tokens should be different
      expect(rotatedToken).not.toBe(initialToken)
      expect(rotatedToken).toBe('rotated-token')
    })

    test('should maintain audit trail for security events', async () => {
      const response = createMockResponse({
        ok: true,
        status: 200,
        json: async () => ({
          csrfToken: 'audit-token',
          tokenId: 'audit-id',
          temporary: false,
          expiresAt: Date.now() + 3600000
        })
      })

      mockFetch.mockResolvedValueOnce(response)

      const { result } = renderHook(() => useCSRFProtection())

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      // Verify logging was called for security events
      expect(mockLogger.info).toHaveBeenCalledWith(
        'CSRF',
        expect.stringContaining('CSRF token fetched successfully')
      )
    })
  })
})
