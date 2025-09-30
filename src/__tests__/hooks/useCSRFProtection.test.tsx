/**
 * Tests for useCSRFProtection hook
 * Tests the enhanced CSRF protection with fallback logic and retry mechanisms
 */

import { renderHook, waitFor } from '@testing-library/react'
import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals'
import { useCSRFProtection, useFormCSRFProtection } from '@/hooks/useCSRFProtection'
import { createMockFunction, MockedFunction, createMockResponse } from '../utils/mockTypeHelpers'
import { mockFetchResponses } from '../utils/commonMocks'

// Mock fetch globally
const mockFetch = createMockFunction<typeof fetch>()
global.fetch = mockFetch as any

// Mock logger
jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  },
}))

describe('useCSRFProtection Hook', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    jest.useFakeTimers()
  })

  afterEach(() => {
    jest.useRealTimers()
    jest.restoreAllMocks()
  })

  describe('Token Fetching with Fallback', () => {
    it('should fetch token from /api/csrf first', async () => {
      const mockCsrfResponse = mockFetchResponses.csrfToken('temp-csrf-token')

      mockFetch.mockResolvedValueOnce(mockCsrfResponse)

      const { result } = renderHook(() => useCSRFProtection())

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      expect(mockFetch).toHaveBeenCalledWith('/api/csrf', expect.objectContaining({
        method: 'GET',
        credentials: 'include',
      }))
      expect(result.current.csrfToken).toBe('temp-csrf-token')
      expect(result.current.tokenId).toBe('temp-token-id')
      expect(result.current.isTemporary).toBe(true)
      expect(result.current.error).toBeNull()
    })

    it('should fallback to /api/auth when /api/csrf fails', async () => {
      const mockCsrfFailure = mockFetchResponses.csrfFailure()
      const mockAuthSuccess = mockFetchResponses.csrfToken('auth-csrf-token', 3600000)

      mockFetch
        .mockResolvedValueOnce(mockCsrfFailure)
        .mockResolvedValueOnce(mockAuthSuccess)

      const { result } = renderHook(() => useCSRFProtection())

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      expect(mockFetch).toHaveBeenCalledTimes(2)
      expect(mockFetch).toHaveBeenNthCalledWith(1, '/api/csrf', expect.any(Object))
      expect(mockFetch).toHaveBeenNthCalledWith(2, '/api/auth', expect.any(Object))
      expect(result.current.csrfToken).toBe('auth-csrf-token')
      expect(result.current.isTemporary).toBe(false)
      expect(result.current.error).toBeNull()
    })

    it('should retry with exponential backoff on failures', async () => {
      const mockFailure = mockFetchResponses.serverError()
      const mockSuccess = mockFetchResponses.csrfToken('retry-success-token')

      // Fail twice, then succeed
      mockFetch
        .mockResolvedValueOnce(mockFailure) // /api/csrf fails
        .mockResolvedValueOnce(mockFailure) // /api/auth fails
        .mockResolvedValueOnce(mockFailure) // /api/csrf fails on retry
        .mockResolvedValueOnce(mockSuccess) // /api/auth succeeds on retry

      const { result } = renderHook(() => useCSRFProtection())

      // Fast-forward through the retry delay
      jest.advanceTimersByTime(1000)

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      }, { timeout: 5000 })

      expect(mockFetch).toHaveBeenCalledTimes(4)
      expect(result.current.csrfToken).toBe('retry-success-token')
      expect(result.current.error).toBeNull()
    })

    it('should set error after max retries exceeded', async () => {
      const mockFailure = createMockResponse(
        { error: 'Internal Server Error' },
        { status: 500 }
      )

      mockFetch.mockResolvedValue(mockFailure)

      const { result } = renderHook(() => useCSRFProtection())

      // Fast-forward through all retry delays
      jest.advanceTimersByTime(10000)

      await waitFor(() => {
        expect(result.current.error).toBeTruthy()
      }, { timeout: 10000 })

      expect(result.current.error).toContain('after')
      expect(result.current.error).toContain('attempts')
      expect(result.current.csrfToken).toBeNull()
    })
  })

  describe('Token Validation', () => {
    it('should validate token expiration correctly', async () => {
      const futureTime = Date.now() + 600000 // 10 minutes from now
      const mockResponse = createMockResponse({
        csrfToken: 'valid-token',
        expiresAt: new Date(futureTime).toISOString(),
      })

      mockFetch.mockResolvedValueOnce(mockResponse)

      const { result } = renderHook(() => useCSRFProtection())

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      expect(result.current.isTokenValid()).toBe(true)
    })

    it('should detect expired tokens', async () => {
      const pastTime = Date.now() - 60000 // 1 minute ago
      const mockResponse = createMockResponse({
        csrfToken: 'expired-token',
        expiresAt: new Date(pastTime).toISOString(),
      })

      mockFetch.mockResolvedValueOnce(mockResponse)

      const { result } = renderHook(() => useCSRFProtection())

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      expect(result.current.isTokenValid()).toBe(false)
    })
  })

  describe('Headers Generation', () => {
    it('should include CSRF token in headers', async () => {
      const mockResponse = createMockResponse({
        csrfToken: 'test-token',
        expiresAt: new Date(Date.now() + 600000).toISOString(),
      })

      mockFetch.mockResolvedValueOnce(mockResponse)

      const { result } = renderHook(() => useCSRFProtection())

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      const headers = result.current.getHeaders()
      expect(headers['X-CSRF-Token']).toBe('test-token')
      expect(headers['Content-Type']).toBe('application/json')
    })

    it('should include token ID for temporary tokens', async () => {
      const mockResponse = createMockResponse({
        csrfToken: 'temp-token',
        tokenId: 'temp-id',
        temporary: true,
        expiresAt: new Date(Date.now() + 600000).toISOString(),
      })

      mockFetch.mockResolvedValueOnce(mockResponse)

      const { result } = renderHook(() => useCSRFProtection())

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      const headers = result.current.getHeaders()
      expect(headers['X-CSRF-Token']).toBe('temp-token')
      expect(headers['X-CSRF-Token-ID']).toBe('temp-id')
    })
  })
})

describe('useFormCSRFProtection Hook', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    jest.useFakeTimers()
  })

  afterEach(() => {
    jest.useRealTimers()
  })

  it('should submit form with CSRF protection', async () => {
    const mockCsrfResponse = createMockResponse({
      csrfToken: 'form-token',
      expiresAt: new Date(Date.now() + 600000).toISOString(),
    })

    const mockSubmitResponse = mockFetchResponses.success({ success: true })

    mockFetch
      .mockResolvedValueOnce(mockCsrfResponse)
      .mockResolvedValueOnce(mockSubmitResponse)

    const { result } = renderHook(() => useFormCSRFProtection())

    await waitFor(() => {
      expect(result.current.isLoading).toBe(false)
    })

    const response = await result.current.submitForm('/api/test', {
      username: 'test',
      password: 'test',
    })

    expect(response.ok).toBe(true)
    expect(mockFetch).toHaveBeenCalledWith('/api/test', expect.objectContaining({
      method: 'POST',
      headers: expect.objectContaining({
        'X-CSRF-Token': 'form-token',
      }),
      body: expect.stringContaining('csrf_token'),
    }))
  })
})
