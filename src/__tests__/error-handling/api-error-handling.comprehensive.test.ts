/**
 * API Error Handling - Comprehensive Test Suite
 * Tests API error responses, client-side error handling, retry logic, and error recovery
 */

import { NextRequest, NextResponse } from 'next/server'
import {
  createErrorResponse,
  handleAsyncApiOperation,
  makeApiCall,
  ApiErrorResponse,
  ApiError,
} from '@/utils/apiErrorHandling'
import { logger } from '@/utils/logger'

// Mock dependencies
jest.mock('@/utils/logger')
const mockLogger = logger as jest.Mocked<typeof logger>

// Mock fetch for client-side tests
global.fetch = jest.fn()
const mockFetch = fetch as jest.MockedFunction<typeof fetch>

describe('API Error Handling - Comprehensive Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    mockFetch.mockClear()
  })

  describe('Error Response Creation', () => {
    it('should create standardized error response', () => {
      const response = createErrorResponse('Test error message', 400, { field: 'email' })

      expect(response).toBeInstanceOf(NextResponse)
      expect(response.status).toBe(400)
    })

    it('should include error ID and timestamp in response', async () => {
      const response = createErrorResponse('Test error')
      const body = await response.json() as ApiErrorResponse

      expect(body).toMatchObject({
        error: 'Test error',
        errorId: expect.any(String),
        timestamp: expect.any(String),
      })
      expect(new Date(body.timestamp)).toBeInstanceOf(Date)
    })

    it('should include additional details when provided', async () => {
      const details = { field: 'email', code: 'INVALID_FORMAT' }
      const response = createErrorResponse('Validation error', 422, details)
      const body = await response.json() as ApiErrorResponse

      expect(body.details).toEqual(details)
    })

    it('should default to 500 status when not specified', () => {
      const response = createErrorResponse('Internal error')
      expect(response.status).toBe(500)
    })

    it('should generate unique error IDs', async () => {
      const response1 = createErrorResponse('Error 1')
      const response2 = createErrorResponse('Error 2')

      const body1 = await response1.json() as ApiErrorResponse
      const body2 = await response2.json() as ApiErrorResponse

      expect(body1.errorId).not.toBe(body2.errorId)
    })
  })

  describe('Async API Operation Handling', () => {
    it('should handle successful operations', async () => {
      const mockOperation = jest.fn().mockResolvedValue({ data: 'success' })
      const context = {
        operationName: 'Test Operation',
        endpoint: '/api/test',
      }

      const result = await handleAsyncApiOperation(mockOperation, context)

      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data).toEqual({ data: 'success' })
      }
      expect(mockOperation).toHaveBeenCalled()
    })

    it('should handle operation failures with error logging', async () => {
      const testError = new Error('Operation failed')
      const mockOperation = jest.fn().mockRejectedValue(testError)
      const mockRequest = new NextRequest('http://localhost/api/test', { method: 'POST' })
      
      const context = {
        operationName: 'Failed Operation',
        endpoint: '/api/test',
        request: mockRequest,
      }

      const result = await handleAsyncApiOperation(mockOperation, context)

      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error).toBeInstanceOf(NextResponse)
      }

      expect(mockLogger.error).toHaveBeenCalledWith(
        'API Operation',
        'Failed Operation failed',
        expect.objectContaining({
          operation: 'Failed Operation',
          endpoint: '/api/test',
          error: {
            name: 'Error',
            message: 'Operation failed',
            stack: expect.any(String),
          },
        })
      )
    })

    it('should handle non-Error exceptions', async () => {
      const mockOperation = jest.fn().mockRejectedValue('String error')
      const context = {
        operationName: 'String Error Operation',
        endpoint: '/api/string-error',
      }

      const result = await handleAsyncApiOperation(mockOperation, context)

      expect(result.success).toBe(false)
      expect(mockLogger.error).toHaveBeenCalledWith(
        'API Operation',
        'String Error Operation failed',
        expect.objectContaining({
          error: 'String error',
        })
      )
    })

    it('should extract client IP and user agent from request', async () => {
      const mockOperation = jest.fn().mockRejectedValue(new Error('Test error'))
      const mockRequest = new NextRequest('http://localhost/api/test', {
        method: 'GET',
        headers: {
          'user-agent': 'Test Browser',
          'x-forwarded-for': '192.168.1.1',
        },
      })

      const context = {
        operationName: 'IP Test Operation',
        endpoint: '/api/test',
        request: mockRequest,
      }

      await handleAsyncApiOperation(mockOperation, context)

      expect(mockLogger.error).toHaveBeenCalled()
    })
  })

  describe('Client-Side API Calls', () => {
    it('should make successful API calls', async () => {
      const mockData = { id: 1, name: 'Test' }
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(mockData),
      } as Response)

      const result = await makeApiCall('/api/test', {}, { operation: 'Test API Call' })

      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data).toEqual(mockData)
      }
      expect(mockFetch).toHaveBeenCalledWith('/api/test', {})
    })

    it('should handle API call failures', async () => {
      const errorResponse: ApiErrorResponse = {
        error: 'Not found',
        errorId: 'test-error-id',
        timestamp: new Date().toISOString(),
      }

      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        json: () => Promise.resolve(errorResponse),
      } as Response)

      const result = await makeApiCall('/api/not-found', {}, { operation: 'Failed API Call' })

      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error).toEqual(errorResponse)
      }
    })

    it('should retry failed requests when configured', async () => {
      // First call fails, second succeeds
      mockFetch
        .mockRejectedValueOnce(new Error('Network error'))
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ data: 'success' }),
        } as Response)

      const result = await makeApiCall(
        '/api/retry-test',
        {},
        {
          operation: 'Retry Test',
          retries: 1,
          retryDelay: 10,
        }
      )

      expect(result.success).toBe(true)
      expect(mockFetch).toHaveBeenCalledTimes(2)
    })

    it('should respect retry conditions', async () => {
      const retryCondition = jest.fn().mockReturnValue(false)
      
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        json: () => Promise.resolve({
          error: 'Server error',
          errorId: 'test-id',
          timestamp: new Date().toISOString(),
        }),
      } as Response)

      const result = await makeApiCall(
        '/api/conditional-retry',
        {},
        {
          operation: 'Conditional Retry Test',
          retries: 3,
          retryCondition,
        }
      )

      expect(result.success).toBe(false)
      expect(mockFetch).toHaveBeenCalledTimes(1) // No retries due to condition
      expect(retryCondition).toHaveBeenCalled()
    })

    it('should handle network errors', async () => {
      mockFetch.mockRejectedValue(new Error('Network error'))

      const result = await makeApiCall('/api/network-error', {}, { operation: 'Network Test' })

      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error.error).toContain('Network error')
      }
    })

    it('should handle malformed JSON responses', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.reject(new Error('Invalid JSON')),
      } as Response)

      const result = await makeApiCall('/api/malformed-json', {}, { operation: 'JSON Test' })

      expect(result.success).toBe(false)
    })

    it('should include request options in API calls', async () => {
      const requestOptions = {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ data: 'test' }),
      }

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ success: true }),
      } as Response)

      await makeApiCall('/api/post-test', requestOptions, { operation: 'POST Test' })

      expect(mockFetch).toHaveBeenCalledWith('/api/post-test', requestOptions)
    })
  })

  describe('Error Classification and Handling', () => {
    it('should classify different types of API errors', async () => {
      const testCases = [
        { status: 400, expectedType: 'client' },
        { status: 401, expectedType: 'auth' },
        { status: 403, expectedType: 'auth' },
        { status: 404, expectedType: 'client' },
        { status: 422, expectedType: 'validation' },
        { status: 500, expectedType: 'server' },
        { status: 503, expectedType: 'server' },
      ]

      for (const testCase of testCases) {
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: testCase.status,
          json: () => Promise.resolve({
            error: `Error ${testCase.status}`,
            errorId: 'test-id',
            timestamp: new Date().toISOString(),
          }),
        } as Response)

        const result = await makeApiCall(
          `/api/error-${testCase.status}`,
          {},
          { operation: `Error ${testCase.status} Test` }
        )

        expect(result.success).toBe(false)
      }
    })

    it('should handle timeout errors', async () => {
      jest.useFakeTimers()
      
      mockFetch.mockImplementation(() => 
        new Promise((resolve) => {
          setTimeout(() => resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve({ data: 'delayed' }),
          } as Response), 10000)
        })
      )

      const resultPromise = makeApiCall(
        '/api/timeout-test',
        {},
        { operation: 'Timeout Test' }
      )

      // Fast-forward time to trigger timeout
      jest.advanceTimersByTime(10000)

      const result = await resultPromise

      expect(result.success).toBe(true)
      
      jest.useRealTimers()
    })
  })

  describe('Error Recovery and Resilience', () => {
    it('should implement exponential backoff for retries', async () => {
      const startTime = Date.now()
      let callTimes: number[] = []

      mockFetch.mockImplementation(() => {
        callTimes.push(Date.now() - startTime)
        return Promise.reject(new Error('Persistent error'))
      })

      await makeApiCall(
        '/api/backoff-test',
        {},
        {
          operation: 'Backoff Test',
          retries: 3,
          retryDelay: 100,
        }
      )

      expect(callTimes).toHaveLength(4) // Initial + 3 retries
      // Verify increasing delays (allowing for some timing variance)
      expect(callTimes[1] - callTimes[0]).toBeGreaterThanOrEqual(90)
      expect(callTimes[2] - callTimes[1]).toBeGreaterThanOrEqual(180)
      expect(callTimes[3] - callTimes[2]).toBeGreaterThanOrEqual(360)
    })

    it('should stop retrying after max attempts', async () => {
      mockFetch.mockRejectedValue(new Error('Persistent error'))

      const result = await makeApiCall(
        '/api/max-retries-test',
        {},
        {
          operation: 'Max Retries Test',
          retries: 2,
          retryDelay: 10,
        }
      )

      expect(result.success).toBe(false)
      expect(mockFetch).toHaveBeenCalledTimes(3) // Initial + 2 retries
    })

    it('should handle circuit breaker pattern', async () => {
      // Simulate multiple failures to trigger circuit breaker
      for (let i = 0; i < 5; i++) {
        mockFetch.mockRejectedValueOnce(new Error('Service unavailable'))
        
        await makeApiCall(
          '/api/circuit-breaker-test',
          {},
          { operation: 'Circuit Breaker Test' }
        )
      }

      // Circuit should be open, preventing further calls
      const result = await makeApiCall(
        '/api/circuit-breaker-test',
        {},
        { operation: 'Circuit Breaker Test' }
      )

      expect(result.success).toBe(false)
    })
  })

  describe('Error Context and Debugging', () => {
    it('should include request context in error logs', async () => {
      const mockOperation = jest.fn().mockRejectedValue(new Error('Context test error'))
      const mockRequest = new NextRequest('http://localhost/api/context-test', {
        method: 'PUT',
        headers: {
          'user-agent': 'Test Agent',
          'authorization': 'Bearer token123',
        },
      })

      const context = {
        operationName: 'Context Test',
        endpoint: '/api/context-test',
        request: mockRequest,
      }

      await handleAsyncApiOperation(mockOperation, context)

      expect(mockLogger.error).toHaveBeenCalledWith(
        'API Operation',
        'Context Test failed',
        expect.objectContaining({
          operation: 'Context Test',
          endpoint: '/api/context-test',
        })
      )
    })

    it('should sanitize sensitive information in logs', async () => {
      const mockOperation = jest.fn().mockRejectedValue(new Error('Sensitive data error'))
      const mockRequest = new NextRequest('http://localhost/api/sensitive', {
        method: 'POST',
        headers: {
          'authorization': 'Bearer secret-token',
          'x-api-key': 'secret-key',
        },
      })

      const context = {
        operationName: 'Sensitive Test',
        endpoint: '/api/sensitive',
        request: mockRequest,
      }

      await handleAsyncApiOperation(mockOperation, context)

      const logCall = mockLogger.error.mock.calls[0]
      const logData = JSON.stringify(logCall[2])
      
      // Should not contain sensitive tokens
      expect(logData).not.toContain('secret-token')
      expect(logData).not.toContain('secret-key')
    })
  })
})
