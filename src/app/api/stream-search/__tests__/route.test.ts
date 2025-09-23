/**
 * Tests for the stream-search API route
 * Tests for GitHub Issue #192: Server-side streaming connection issues
 */

import { NextRequest } from 'next/server'
import { GET } from '../route'

// Mock dependencies
jest.mock('@/lib/streamingSearchService', () => ({
  streamingSearchService: {
    healthCheck: jest.fn(),
    processStreamingSearch: jest.fn(),
    stopAllStreams: jest.fn(),
  },
}))

jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
    warn: jest.fn(),
  },
}))

jest.mock('@/utils/validation', () => ({
  validationService: {
    sanitizeInput: jest.fn((input) => input),
  },
}))

jest.mock('@/lib/advancedRateLimit', () => ({
  advancedRateLimitService: {
    checkEndpointRateLimit: jest.fn(),
  },
}))

import { streamingSearchService } from '@/lib/streamingSearchService'
import { logger } from '@/utils/logger'
import { advancedRateLimitService } from '@/lib/advancedRateLimit'

describe('/api/stream-search', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    
    // Default mocks
    ;(advancedRateLimitService.checkEndpointRateLimit as jest.Mock).mockResolvedValue({
      allowed: true,
      retryAfter: null,
    })
    
    ;(streamingSearchService.healthCheck as jest.Mock).mockResolvedValue({
      healthy: true,
      details: { servicesInitialized: true },
    })
  })

  describe('Request Validation', () => {
    test('should return 400 for missing query parameter', async () => {
      const request = new NextRequest('http://localhost:3000/api/stream-search')
      
      const response = await GET(request)
      
      expect(response.status).toBe(400)
      const data = await response.json()
      expect(data.error).toContain('Query parameter "q" is required')
    })

    test('should accept valid query parameters', async () => {
      const url = 'http://localhost:3000/api/stream-search?q=test&location=test&maxResults=100&batchSize=10'
      const request = new NextRequest(url)
      
      // Mock successful streaming
      ;(streamingSearchService.processStreamingSearch as jest.Mock).mockImplementation(
        (query, location, onResult, onProgress, onComplete, onError, options) => {
          setTimeout(() => onComplete(0), 10)
          return Promise.resolve()
        }
      )
      
      const response = await GET(request)
      
      expect(response.status).toBe(200)
      expect(response.headers.get('content-type')).toBe('text/event-stream')
    })
  })

  describe('Rate Limiting', () => {
    test('should return 429 when rate limited', async () => {
      ;(advancedRateLimitService.checkEndpointRateLimit as jest.Mock).mockResolvedValue({
        allowed: false,
        retryAfter: 60,
      })
      
      const url = 'http://localhost:3000/api/stream-search?q=test'
      const request = new NextRequest(url)
      
      const response = await GET(request)
      
      expect(response.status).toBe(429)
      const data = await response.json()
      expect(data.error).toContain('Rate limit exceeded')
    })

    test('should proceed when rate limit allows', async () => {
      ;(advancedRateLimitService.checkEndpointRateLimit as jest.Mock).mockResolvedValue({
        allowed: true,
        retryAfter: null,
      })
      
      const url = 'http://localhost:3000/api/stream-search?q=test'
      const request = new NextRequest(url)
      
      // Mock successful streaming
      ;(streamingSearchService.processStreamingSearch as jest.Mock).mockImplementation(
        (query, location, onResult, onProgress, onComplete, onError, options) => {
          setTimeout(() => onComplete(0), 10)
          return Promise.resolve()
        }
      )
      
      const response = await GET(request)
      
      expect(response.status).toBe(200)
    })
  })

  describe('Health Check Integration', () => {
    test('should return 503 when health check fails', async () => {
      ;(streamingSearchService.healthCheck as jest.Mock).mockResolvedValue({
        healthy: false,
        details: { error: 'Service unavailable' },
      })
      
      const url = 'http://localhost:3000/api/stream-search?q=test'
      const request = new NextRequest(url)
      
      const response = await GET(request)
      
      expect(response.status).toBe(503)
      const data = await response.json()
      expect(data.error).toBe('Streaming service unavailable')
    })

    test('should proceed when health check passes', async () => {
      ;(streamingSearchService.healthCheck as jest.Mock).mockResolvedValue({
        healthy: true,
        details: { servicesInitialized: true },
      })
      
      const url = 'http://localhost:3000/api/stream-search?q=test'
      const request = new NextRequest(url)
      
      // Mock successful streaming
      ;(streamingSearchService.processStreamingSearch as jest.Mock).mockImplementation(
        (query, location, onResult, onProgress, onComplete, onError, options) => {
          setTimeout(() => onComplete(0), 10)
          return Promise.resolve()
        }
      )
      
      const response = await GET(request)
      
      expect(response.status).toBe(200)
    })

    test('should handle health check errors gracefully', async () => {
      ;(streamingSearchService.healthCheck as jest.Mock).mockRejectedValue(
        new Error('Health check failed')
      )
      
      const url = 'http://localhost:3000/api/stream-search?q=test'
      const request = new NextRequest(url)
      
      const response = await GET(request)
      
      expect(response.status).toBe(503)
      const data = await response.json()
      expect(data.error).toBe('Service health check failed')
    })
  })

  describe('SSE Response Headers', () => {
    test('should set correct SSE headers', async () => {
      const url = 'http://localhost:3000/api/stream-search?q=test'
      const request = new NextRequest(url)
      
      // Mock successful streaming
      ;(streamingSearchService.processStreamingSearch as jest.Mock).mockImplementation(
        (query, location, onResult, onProgress, onComplete, onError, options) => {
          setTimeout(() => onComplete(0), 10)
          return Promise.resolve()
        }
      )
      
      const response = await GET(request)
      
      expect(response.headers.get('content-type')).toBe('text/event-stream')
      expect(response.headers.get('cache-control')).toBe('no-cache, no-transform')
      expect(response.headers.get('connection')).toBe('keep-alive')
      expect(response.headers.get('access-control-allow-origin')).toBe('*')
    })
  })

  describe('Streaming Process', () => {
    test('should handle streaming service errors', async () => {
      ;(streamingSearchService.processStreamingSearch as jest.Mock).mockRejectedValue(
        new Error('Streaming failed')
      )
      
      const url = 'http://localhost:3000/api/stream-search?q=test'
      const request = new NextRequest(url)
      
      const response = await GET(request)
      
      expect(response.status).toBe(200) // SSE starts successfully
      expect(logger.error).toHaveBeenCalledWith(
        'StreamSearchAPI',
        'Streaming search failed',
        expect.any(Error)
      )
    })

    test('should call processStreamingSearch with correct parameters', async () => {
      const url = 'http://localhost:3000/api/stream-search?q=test+query&location=test+location&maxResults=500&batchSize=25'
      const request = new NextRequest(url)
      
      // Mock successful streaming
      ;(streamingSearchService.processStreamingSearch as jest.Mock).mockImplementation(
        (query, location, onResult, onProgress, onComplete, onError, options) => {
          setTimeout(() => onComplete(0), 10)
          return Promise.resolve()
        }
      )
      
      await GET(request)
      
      expect(streamingSearchService.processStreamingSearch).toHaveBeenCalledWith(
        'test query',
        'test location',
        expect.any(Function), // onResult
        expect.any(Function), // onProgress
        expect.any(Function), // onComplete
        expect.any(Function), // onError
        {
          maxResults: 500,
          batchSize: 25,
          delayBetweenBatches: 200,
          enableRealTimeUpdates: true,
        }
      )
    })
  })

  describe('Error Handling', () => {
    test('should handle general API errors', async () => {
      // Mock a general error
      ;(streamingSearchService.healthCheck as jest.Mock).mockImplementation(() => {
        throw new Error('Unexpected error')
      })
      
      const url = 'http://localhost:3000/api/stream-search?q=test'
      const request = new NextRequest(url)
      
      const response = await GET(request)
      
      expect(response.status).toBe(500)
      const data = await response.json()
      expect(data.error).toBe('Internal server error')
    })
  })

  describe('CORS Support', () => {
    test('should handle OPTIONS requests', async () => {
      // This would be tested in a separate OPTIONS export test
      // For now, we verify the headers are set correctly in GET requests
      const url = 'http://localhost:3000/api/stream-search?q=test'
      const request = new NextRequest(url)
      
      // Mock successful streaming
      ;(streamingSearchService.processStreamingSearch as jest.Mock).mockImplementation(
        (query, location, onResult, onProgress, onComplete, onError, options) => {
          setTimeout(() => onComplete(0), 10)
          return Promise.resolve()
        }
      )
      
      const response = await GET(request)
      
      expect(response.headers.get('access-control-allow-origin')).toBe('*')
      expect(response.headers.get('access-control-allow-methods')).toBe('GET')
    })
  })
})
