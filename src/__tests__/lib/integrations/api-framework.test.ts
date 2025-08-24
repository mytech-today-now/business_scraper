/**
 * API Framework Tests
 * Test suite for the RESTful API framework
 */

import { NextRequest } from 'next/server'
import { ApiFramework } from '@/lib/integrations/api-framework'
import { ApiRequestContext, ApiResponse } from '@/types/integrations'

// Mock dependencies
jest.mock('@/lib/analytics/api-metrics', () => ({
  apiMetricsService: {
    checkRateLimit: jest.fn(),
    recordRequest: jest.fn()
  }
}))

jest.mock('@/lib/security', () => ({
  getClientIP: jest.fn(() => '127.0.0.1')
}))

describe('ApiFramework', () => {
  let apiFramework: ApiFramework
  let mockRequest: NextRequest
  let mockHandler: jest.Mock

  beforeEach(() => {
    apiFramework = new ApiFramework()
    mockHandler = jest.fn()
    
    // Create mock request
    mockRequest = new NextRequest('https://example.com/api/v1/test', {
      method: 'GET',
      headers: {
        'user-agent': 'test-agent',
        'authorization': 'Bearer test-token'
      }
    })

    // Reset mocks
    jest.clearAllMocks()
  })

  describe('Handler Creation', () => {
    test('should create handler with default options', () => {
      const handler = apiFramework.createHandler(mockHandler)
      
      expect(typeof handler).toBe('function')
    })

    test('should create handler with custom options', () => {
      const handler = apiFramework.createHandler(mockHandler, {
        permissions: ['read:businesses'],
        rateLimit: {
          requestsPerMinute: 50,
          requestsPerHour: 500
        }
      })
      
      expect(typeof handler).toBe('function')
    })
  })

  describe('Request Processing', () => {
    test('should process successful request', async () => {
      const mockResponse: ApiResponse = {
        success: true,
        data: { message: 'test response' },
        metadata: {
          requestId: 'test-id',
          timestamp: new Date().toISOString(),
          version: 'v1'
        }
      }

      mockHandler.mockResolvedValue(mockResponse)

      // Mock rate limit check
      const { apiMetricsService } = require('@/lib/analytics/api-metrics')
      apiMetricsService.checkRateLimit.mockReturnValue({
        allowed: true,
        remaining: { minute: 99, hour: 999, day: 9999 },
        resetTime: { minute: 60, hour: 3600, day: 86400 },
        rateLimitHit: false
      })

      const handler = apiFramework.createHandler(mockHandler)
      const response = await handler(mockRequest)

      expect(response.status).toBe(200)
      expect(mockHandler).toHaveBeenCalledWith(
        mockRequest,
        expect.objectContaining({
          requestId: expect.any(String),
          permissions: expect.any(Array),
          metadata: expect.objectContaining({
            ip: '127.0.0.1',
            method: 'GET',
            userAgent: 'test-agent'
          })
        })
      )
    })

    test('should handle rate limit exceeded', async () => {
      const { apiMetricsService } = require('@/lib/analytics/api-metrics')
      apiMetricsService.checkRateLimit.mockReturnValue({
        allowed: false,
        remaining: { minute: 0, hour: 0, day: 0 },
        resetTime: { minute: 60, hour: 3600, day: 86400 },
        rateLimitHit: true
      })

      const handler = apiFramework.createHandler(mockHandler)
      const response = await handler(mockRequest)

      expect(response.status).toBe(429)
      expect(mockHandler).not.toHaveBeenCalled()
      
      const responseData = await response.json()
      expect(responseData.error.message).toBe('Rate limit exceeded')
    })

    test('should handle handler errors', async () => {
      mockHandler.mockRejectedValue(new Error('Test error'))

      // Mock rate limit check
      const { apiMetricsService } = require('@/lib/analytics/api-metrics')
      apiMetricsService.checkRateLimit.mockReturnValue({
        allowed: true,
        remaining: { minute: 99, hour: 999, day: 9999 },
        resetTime: { minute: 60, hour: 3600, day: 86400 },
        rateLimitHit: false
      })

      const handler = apiFramework.createHandler(mockHandler)
      const response = await handler(mockRequest)

      expect(response.status).toBe(500)
      
      const responseData = await response.json()
      expect(responseData.success).toBe(false)
      expect(responseData.error.message).toBe('Test error')
    })
  })

  describe('Authentication', () => {
    test('should handle missing authentication', async () => {
      const requestWithoutAuth = new NextRequest('https://example.com/api/v1/test', {
        method: 'GET'
      })

      // Mock rate limit check
      const { apiMetricsService } = require('@/lib/analytics/api-metrics')
      apiMetricsService.checkRateLimit.mockReturnValue({
        allowed: true,
        remaining: { minute: 99, hour: 999, day: 9999 },
        resetTime: { minute: 60, hour: 3600, day: 86400 },
        rateLimitHit: false
      })

      mockHandler.mockResolvedValue({
        success: true,
        data: { message: 'test' },
        metadata: { requestId: 'test', timestamp: new Date().toISOString(), version: 'v1' }
      })

      const handler = apiFramework.createHandler(mockHandler)
      const response = await handler(requestWithoutAuth)

      // Should still work with anonymous permissions
      expect(response.status).toBe(200)
    })

    test('should handle API key authentication', async () => {
      const requestWithApiKey = new NextRequest('https://example.com/api/v1/test', {
        method: 'GET',
        headers: {
          'x-api-key': 'test-api-key'
        }
      })

      // Mock rate limit check
      const { apiMetricsService } = require('@/lib/analytics/api-metrics')
      apiMetricsService.checkRateLimit.mockReturnValue({
        allowed: true,
        remaining: { minute: 99, hour: 999, day: 9999 },
        resetTime: { minute: 60, hour: 3600, day: 86400 },
        rateLimitHit: false
      })

      mockHandler.mockResolvedValue({
        success: true,
        data: { message: 'test' },
        metadata: { requestId: 'test', timestamp: new Date().toISOString(), version: 'v1' }
      })

      const handler = apiFramework.createHandler(mockHandler)
      const response = await handler(requestWithApiKey)

      expect(response.status).toBe(200)
      expect(mockHandler).toHaveBeenCalledWith(
        requestWithApiKey,
        expect.objectContaining({
          clientId: 'api-client',
          userId: 'api-user'
        })
      )
    })
  })

  describe('Authorization', () => {
    test('should enforce permission requirements', async () => {
      // Mock rate limit check
      const { apiMetricsService } = require('@/lib/analytics/api-metrics')
      apiMetricsService.checkRateLimit.mockReturnValue({
        allowed: true,
        remaining: { minute: 99, hour: 999, day: 9999 },
        resetTime: { minute: 60, hour: 3600, day: 86400 },
        rateLimitHit: false
      })

      const handler = apiFramework.createHandler(mockHandler, {
        permissions: ['admin:all'] // Require admin permission
      })

      const response = await handler(mockRequest)

      expect(response.status).toBe(403)
      expect(mockHandler).not.toHaveBeenCalled()
      
      const responseData = await response.json()
      expect(responseData.error.message).toBe('Insufficient permissions')
    })

    test('should allow access with correct permissions', async () => {
      // Mock rate limit check
      const { apiMetricsService } = require('@/lib/analytics/api-metrics')
      apiMetricsService.checkRateLimit.mockReturnValue({
        allowed: true,
        remaining: { minute: 99, hour: 999, day: 9999 },
        resetTime: { minute: 60, hour: 3600, day: 86400 },
        rateLimitHit: false
      })

      mockHandler.mockResolvedValue({
        success: true,
        data: { message: 'test' },
        metadata: { requestId: 'test', timestamp: new Date().toISOString(), version: 'v1' }
      })

      const handler = apiFramework.createHandler(mockHandler, {
        permissions: ['read:businesses'] // Permission that anonymous users have
      })

      const response = await handler(mockRequest)

      expect(response.status).toBe(200)
      expect(mockHandler).toHaveBeenCalled()
    })
  })

  describe('CORS Handling', () => {
    test('should handle OPTIONS preflight request', async () => {
      const optionsRequest = new NextRequest('https://example.com/api/v1/test', {
        method: 'OPTIONS'
      })

      const handler = apiFramework.createHandler(mockHandler)
      const response = await handler(optionsRequest)

      expect(response.status).toBe(200)
      expect(response.headers.get('Access-Control-Allow-Origin')).toBeTruthy()
      expect(response.headers.get('Access-Control-Allow-Methods')).toBeTruthy()
      expect(mockHandler).not.toHaveBeenCalled()
    })

    test('should add CORS headers to responses', async () => {
      // Mock rate limit check
      const { apiMetricsService } = require('@/lib/analytics/api-metrics')
      apiMetricsService.checkRateLimit.mockReturnValue({
        allowed: true,
        remaining: { minute: 99, hour: 999, day: 9999 },
        resetTime: { minute: 60, hour: 3600, day: 86400 },
        rateLimitHit: false
      })

      mockHandler.mockResolvedValue({
        success: true,
        data: { message: 'test' },
        metadata: { requestId: 'test', timestamp: new Date().toISOString(), version: 'v1' }
      })

      const handler = apiFramework.createHandler(mockHandler)
      const response = await handler(mockRequest)

      expect(response.headers.get('Access-Control-Allow-Origin')).toBeTruthy()
    })
  })

  describe('Response Headers', () => {
    test('should include standard headers', async () => {
      // Mock rate limit check
      const { apiMetricsService } = require('@/lib/analytics/api-metrics')
      apiMetricsService.checkRateLimit.mockReturnValue({
        allowed: true,
        remaining: { minute: 99, hour: 999, day: 9999 },
        resetTime: { minute: 60, hour: 3600, day: 86400 },
        rateLimitHit: false
      })

      mockHandler.mockResolvedValue({
        success: true,
        data: { message: 'test' },
        metadata: { requestId: 'test', timestamp: new Date().toISOString(), version: 'v1' }
      })

      const handler = apiFramework.createHandler(mockHandler)
      const response = await handler(mockRequest)

      expect(response.headers.get('X-Request-ID')).toBeTruthy()
      expect(response.headers.get('X-API-Version')).toBe('v1')
      expect(response.headers.get('X-RateLimit-Remaining')).toBeTruthy()
      expect(response.headers.get('X-RateLimit-Reset')).toBeTruthy()
    })
  })

  describe('Metrics Integration', () => {
    test('should record request metrics', async () => {
      // Mock rate limit check
      const { apiMetricsService } = require('@/lib/analytics/api-metrics')
      apiMetricsService.checkRateLimit.mockReturnValue({
        allowed: true,
        remaining: { minute: 99, hour: 999, day: 9999 },
        resetTime: { minute: 60, hour: 3600, day: 86400 },
        rateLimitHit: false
      })

      mockHandler.mockResolvedValue({
        success: true,
        data: { message: 'test' },
        metadata: { requestId: 'test', timestamp: new Date().toISOString(), version: 'v1' }
      })

      const handler = apiFramework.createHandler(mockHandler)
      await handler(mockRequest)

      expect(apiMetricsService.recordRequest).toHaveBeenCalledWith(
        expect.any(String), // clientId
        expect.any(String), // endpoint
        'GET', // method
        200, // statusCode
        expect.any(Number), // responseTime
        expect.any(Number), // dataTransferred
        expect.objectContaining({
          ip: '127.0.0.1',
          userAgent: 'test-agent'
        })
      )
    })

    test('should record rate limit hits', async () => {
      // Mock rate limit check to return not allowed
      const { apiMetricsService } = require('@/lib/analytics/api-metrics')
      apiMetricsService.checkRateLimit.mockReturnValue({
        allowed: false,
        remaining: { minute: 0, hour: 0, day: 0 },
        resetTime: { minute: 60, hour: 3600, day: 86400 },
        rateLimitHit: true
      })

      const handler = apiFramework.createHandler(mockHandler)
      await handler(mockRequest)

      expect(apiMetricsService.recordRequest).toHaveBeenCalledWith(
        expect.any(String), // clientId
        expect.any(String), // endpoint
        'GET', // method
        429, // statusCode
        expect.any(Number), // responseTime
        0, // dataTransferred
        expect.objectContaining({
          rateLimitHit: true
        })
      )
    })
  })

  describe('Health and Metrics', () => {
    test('should provide health status', () => {
      const health = apiFramework.getHealthStatus()
      
      expect(health.status).toBe('healthy')
      expect(health.version).toBe('v1')
      expect(health.uptime).toBeGreaterThan(0)
      expect(health.memory).toBeDefined()
    })

    test('should provide metrics', () => {
      const metrics = apiFramework.getMetrics()
      
      expect(typeof metrics).toBe('object')
    })
  })
})
