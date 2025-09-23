/**
 * Regression Tests for Streaming Connection Functionality
 * 
 * Tests for the streaming connection error where EventSource connections
 * immediately close with readyState 2 (CLOSED).
 * 
 * GitHub Issue: #191
 */

import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals'

// Mock dependencies
jest.mock('@/lib/streamingSearchService', () => ({
  streamingSearchService: {
    processStreamingSearch: jest.fn(),
    stopAllStreams: jest.fn(),
  },
}))

jest.mock('@/utils/validation', () => ({
  validationService: {
    sanitizeInput: jest.fn((input: string) => input),
  },
}))

jest.mock('@/lib/advancedRateLimit', () => ({
  advancedRateLimitService: {
    checkRateLimit: jest.fn().mockResolvedValue({ allowed: true }),
  },
}))

jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}))

describe('Streaming Connection Regression Tests', () => {
  let mockStreamingService: any
  let mockRateLimitService: any
  let mockLogger: any

  beforeEach(() => {
    // Reset all mocks
    jest.clearAllMocks()
    
    mockStreamingService = require('@/lib/streamingSearchService').streamingSearchService
    mockRateLimitService = require('@/lib/advancedRateLimit').advancedRateLimitService
    mockLogger = require('@/utils/logger').logger
  })

  afterEach(() => {
    jest.resetAllMocks()
  })

  describe('EventSource Connection Establishment', () => {
    test('should establish streaming connection successfully', async () => {
      // Test that the streaming endpoint is accessible
      const baseUrl = process.env.TEST_BASE_URL || 'http://localhost:3000'
      const streamingUrl = `${baseUrl}/api/stream-search?q=test&location=12345&maxResults=10&batchSize=5`

      try {
        const response = await fetch(streamingUrl, {
          method: 'GET',
          headers: {
            'Accept': 'text/event-stream',
            'Cache-Control': 'no-cache'
          },
          signal: AbortSignal.timeout(5000)
        })

        // Check if the endpoint responds (even if it's an error, it should not be a connection failure)
        expect(response.status).toBeGreaterThanOrEqual(200)
        expect(response.status).toBeLessThan(600)

        // If successful, verify streaming headers
        if (response.ok) {
          expect(response.headers.get('Content-Type')).toContain('text/event-stream')
          expect(response.headers.get('Cache-Control')).toContain('no-cache')
        }
      } catch (error) {
        // If there's a connection error, the test should fail
        expect(error.name).not.toBe('TypeError') // Avoid connection errors
      }
    })

    test('should handle missing query parameter', async () => {
      const request = new NextRequest('http://localhost:3000/api/stream-search?location=12345', {
        method: 'GET',
      })

      const response = await GET(request)

      expect(response.status).toBe(400)
      const data = await response.json()
      expect(data.error).toBe('Query parameter "q" is required')
    })

    test('should handle rate limiting', async () => {
      mockRateLimitService.checkRateLimit.mockResolvedValue({
        allowed: false,
        retryAfter: 60,
      })

      const request = new NextRequest('http://localhost:3000/api/stream-search?q=test&location=12345', {
        method: 'GET',
        headers: {
          'x-forwarded-for': '127.0.0.1',
        },
      })

      const response = await GET(request)

      expect(response.status).toBe(429)
      const data = await response.json()
      expect(data.error).toBe('Rate limit exceeded for streaming search')
      expect(data.retryAfter).toBe(60)
    })
  })

  describe('Data Streaming', () => {
    test('should stream business results correctly', async () => {
      const mockBusiness = {
        id: '1',
        name: 'Test Business',
        website: 'https://test.com',
        description: 'Test description',
      }

      mockStreamingService.processStreamingSearch.mockImplementation(
        (query: string, location: string, onResult: Function, onProgress: Function, onComplete: Function) => {
          setTimeout(() => {
            onResult(mockBusiness)
            onProgress({ processed: 1, totalFound: 1 })
            onComplete(1)
          }, 10)
          return Promise.resolve()
        }
      )

      const request = new NextRequest('http://localhost:3000/api/stream-search?q=test&location=12345', {
        method: 'GET',
      })

      const response = await GET(request)
      expect(response.status).toBe(200)
      expect(mockLogger.debug).toHaveBeenCalledWith(
        'StreamSearchAPI',
        'Sent business result: Test Business'
      )
    })

    test('should handle null business results gracefully', async () => {
      mockStreamingService.processStreamingSearch.mockImplementation(
        (query: string, location: string, onResult: Function, onProgress: Function, onComplete: Function) => {
          setTimeout(() => {
            onResult(null) // Simulate null result
            onComplete(0)
          }, 10)
          return Promise.resolve()
        }
      )

      const request = new NextRequest('http://localhost:3000/api/stream-search?q=test&location=12345', {
        method: 'GET',
      })

      const response = await GET(request)
      expect(response.status).toBe(200)
      expect(mockLogger.warn).toHaveBeenCalledWith(
        'StreamSearchAPI',
        'Received null/undefined business result'
      )
    })

    test('should handle progress updates correctly', async () => {
      const mockProgress = { processed: 5, totalFound: 10 }

      mockStreamingService.processStreamingSearch.mockImplementation(
        (query: string, location: string, onResult: Function, onProgress: Function, onComplete: Function) => {
          setTimeout(() => {
            onProgress(mockProgress)
            onComplete(5)
          }, 10)
          return Promise.resolve()
        }
      )

      const request = new NextRequest('http://localhost:3000/api/stream-search?q=test&location=12345', {
        method: 'GET',
      })

      const response = await GET(request)
      expect(response.status).toBe(200)
      expect(mockLogger.debug).toHaveBeenCalledWith(
        'StreamSearchAPI',
        'Sent progress update: 5/10'
      )
    })
  })

  describe('Error Handling', () => {
    test('should handle streaming service errors gracefully', async () => {
      const errorMessage = 'Streaming service error'
      mockStreamingService.processStreamingSearch.mockRejectedValue(new Error(errorMessage))

      const request = new NextRequest('http://localhost:3000/api/stream-search?q=test&location=12345', {
        method: 'GET',
      })

      const response = await GET(request)
      expect(response.status).toBe(200) // Stream starts successfully
      expect(mockLogger.error).toHaveBeenCalledWith(
        'StreamSearchAPI',
        'Streaming search failed',
        expect.any(Error)
      )
    })

    test('should handle onError callback correctly', async () => {
      const errorMessage = 'Search processing error'

      mockStreamingService.processStreamingSearch.mockImplementation(
        (query: string, location: string, onResult: Function, onProgress: Function, onComplete: Function, onError: Function) => {
          setTimeout(() => {
            onError(errorMessage)
          }, 10)
          return Promise.resolve()
        }
      )

      const request = new NextRequest('http://localhost:3000/api/stream-search?q=test&location=12345', {
        method: 'GET',
      })

      const response = await GET(request)
      expect(response.status).toBe(200)
      expect(mockLogger.error).toHaveBeenCalledWith(
        'StreamSearchAPI',
        `Streaming search error: ${errorMessage}`
      )
    })

    test('should handle server errors during stream initialization', async () => {
      // Mock a server error during initialization
      const request = new NextRequest('http://localhost:3000/api/stream-search?q=test&location=12345', {
        method: 'GET',
      })

      // Mock validation service to throw an error
      const mockValidation = require('@/utils/validation').validationService
      mockValidation.sanitizeInput.mockImplementation(() => {
        throw new Error('Validation error')
      })

      const response = await GET(request)
      expect(response.status).toBe(500)
      const data = await response.json()
      expect(data.error).toBe('Internal server error')
      expect(data.message).toBe('Failed to start streaming search')
    })
  })

  describe('Health Check Integration', () => {
    test('should verify health endpoint is accessible', async () => {
      const request = new NextRequest('http://localhost:3000/api/health', {
        method: 'GET',
      })

      const response = await healthGet(request)
      expect(response.status).toBeGreaterThanOrEqual(200)
      expect(response.status).toBeLessThan(300)
    })
  })

  describe('Connection Recovery Scenarios', () => {
    test('should handle connection completion correctly', async () => {
      const totalResults = 42

      mockStreamingService.processStreamingSearch.mockImplementation(
        (query: string, location: string, onResult: Function, onProgress: Function, onComplete: Function) => {
          setTimeout(() => {
            onComplete(totalResults)
          }, 10)
          return Promise.resolve()
        }
      )

      const request = new NextRequest('http://localhost:3000/api/stream-search?q=test&location=12345', {
        method: 'GET',
      })

      const response = await GET(request)
      expect(response.status).toBe(200)
      expect(mockLogger.info).toHaveBeenCalledWith(
        'StreamSearchAPI',
        `Streaming search completed with ${totalResults} results`
      )
    })

    test('should handle zero results completion', async () => {
      mockStreamingService.processStreamingSearch.mockImplementation(
        (query: string, location: string, onResult: Function, onProgress: Function, onComplete: Function) => {
          setTimeout(() => {
            onComplete(0)
          }, 10)
          return Promise.resolve()
        }
      )

      const request = new NextRequest('http://localhost:3000/api/stream-search?q=test&location=12345', {
        method: 'GET',
      })

      const response = await GET(request)
      expect(response.status).toBe(200)
      expect(mockLogger.info).toHaveBeenCalledWith(
        'StreamSearchAPI',
        'Streaming search completed with 0 results'
      )
    })
  })
})
