/**
 * Ping API Tests
 * Comprehensive tests for /api/ping endpoint
 * Target: 95% coverage for ping functionality
 */

import { NextRequest } from 'next/server'

// Mock dependencies
jest.mock('@/lib/security', () => ({
  getClientIP: jest.fn(() => '127.0.0.1'),
}))

jest.mock('@/utils/apiErrorHandling', () => ({
  handleAsyncApiOperation: jest.fn((operation) => operation()),
}))

describe('Ping API Tests', () => {
  describe('GET /api/ping', () => {
    test('should return ping response with correct structure', async () => {
      // Import the ping route
      const { GET } = await import('@/app/api/ping/route')

      const request = new NextRequest('http://localhost:3000/api/ping', {
        method: 'GET',
      })

      const response = await GET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data).toHaveProperty('status', 'ok')
      expect(data).toHaveProperty('timestamp')
      expect(data).toHaveProperty('server', 'business-scraper')
      expect(data).toHaveProperty('responseTime')
      expect(typeof data.responseTime).toBe('number')
      expect(data.responseTime).toBeGreaterThanOrEqual(0)
    })

    test('should include valid timestamp', async () => {
      const { GET } = await import('@/app/api/ping/route')
      
      const request = new NextRequest('http://localhost:3000/api/ping', {
        method: 'GET',
      })

      const beforeTime = Date.now()
      const response = await GET(request)
      const afterTime = Date.now()
      const data = await response.json()

      const responseTime = new Date(data.timestamp).getTime()
      expect(responseTime).toBeGreaterThanOrEqual(beforeTime)
      expect(responseTime).toBeLessThanOrEqual(afterTime)
    })

    test('should include server information', async () => {
      const { GET } = await import('@/app/api/ping/route')

      const request = new NextRequest('http://localhost:3000/api/ping', {
        method: 'GET',
      })

      const response = await GET(request)
      const data = await response.json()

      expect(data.server).toBeDefined()
      expect(data.server).toBe('business-scraper')
      expect(data.responseTime).toBeDefined()
      expect(typeof data.responseTime).toBe('number')
      expect(data.responseTime).toBeGreaterThanOrEqual(0)
    })
  })

  describe('HEAD /api/ping', () => {
    test('should return 200 status without body', async () => {
      const { HEAD } = await import('@/app/api/ping/route')
      
      const request = new NextRequest('http://localhost:3000/api/ping', {
        method: 'HEAD',
      })

      const response = await HEAD(request)

      expect(response.status).toBe(200)
      // HEAD requests may have content-type header but no body
      
      // HEAD requests should not have a body
      const text = await response.text()
      expect(text).toBe('')
    })

    test('should include proper headers', async () => {
      const { HEAD } = await import('@/app/api/ping/route')
      
      const request = new NextRequest('http://localhost:3000/api/ping', {
        method: 'HEAD',
      })

      const response = await HEAD(request)

      expect(response.headers.get('cache-control')).toBe('no-cache, no-store, must-revalidate')
      expect(response.headers.get('pragma')).toBe('no-cache')
    })
  })

  describe('OPTIONS /api/ping', () => {
    test('should return CORS headers', async () => {
      const { OPTIONS } = await import('@/app/api/ping/route')
      
      const request = new NextRequest('http://localhost:3000/api/ping', {
        method: 'OPTIONS',
      })

      const response = await OPTIONS(request)

      expect(response.status).toBe(200)
      expect(response.headers.get('access-control-allow-origin')).toBe('*')
      expect(response.headers.get('access-control-allow-methods')).toContain('GET')
      expect(response.headers.get('access-control-allow-methods')).toContain('HEAD')
      expect(response.headers.get('access-control-allow-methods')).toContain('OPTIONS')
    })

    test('should handle preflight requests', async () => {
      const { OPTIONS } = await import('@/app/api/ping/route')
      
      const request = new NextRequest('http://localhost:3000/api/ping', {
        method: 'OPTIONS',
        headers: {
          'origin': 'https://example.com',
          'access-control-request-method': 'GET',
        },
      })

      const response = await OPTIONS(request)

      expect(response.status).toBe(200)
      expect(response.headers.get('access-control-allow-origin')).toBe('*')
    })
  })

  describe('Performance and Load Testing', () => {
    test('should respond quickly under normal load', async () => {
      const { GET } = await import('@/app/api/ping/route')
      
      const request = new NextRequest('http://localhost:3000/api/ping', {
        method: 'GET',
      })

      const startTime = Date.now()
      const response = await GET(request)
      const endTime = Date.now()
      
      const responseTime = endTime - startTime
      
      expect(response.status).toBe(200)
      expect(responseTime).toBeLessThan(100) // Should respond in less than 100ms
    })

    test('should handle concurrent requests', async () => {
      const { GET } = await import('@/app/api/ping/route')
      
      const requests = Array.from({ length: 10 }, () => 
        new NextRequest('http://localhost:3000/api/ping', {
          method: 'GET',
        })
      )

      const startTime = Date.now()
      const responses = await Promise.all(
        requests.map(request => GET(request))
      )
      const endTime = Date.now()

      // All requests should succeed
      responses.forEach(response => {
        expect(response.status).toBe(200)
      })

      // Total time should be reasonable for concurrent requests
      const totalTime = endTime - startTime
      expect(totalTime).toBeLessThan(500) // Should complete in less than 500ms
    })
  })

  describe('Error Handling', () => {
    test('should handle malformed requests gracefully', async () => {
      const { GET } = await import('@/app/api/ping/route')
      
      // Create a request with invalid URL (should still work for ping)
      const request = new NextRequest('http://localhost:3000/api/ping?invalid=param', {
        method: 'GET',
      })

      const response = await GET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.status).toBe('ok')
    })

    test('should maintain consistent response format', async () => {
      const { GET } = await import('@/app/api/ping/route')
      
      const requests = Array.from({ length: 5 }, () => 
        new NextRequest('http://localhost:3000/api/ping', {
          method: 'GET',
        })
      )

      const responses = await Promise.all(
        requests.map(async request => {
          const response = await GET(request)
          return response.json()
        })
      )

      // All responses should have the same structure
      responses.forEach(data => {
        expect(data).toHaveProperty('status', 'ok')
        expect(data).toHaveProperty('timestamp')
        expect(data).toHaveProperty('server', 'business-scraper')
        expect(data).toHaveProperty('responseTime')
        expect(typeof data.responseTime).toBe('number')
        expect(data.responseTime).toBeGreaterThanOrEqual(0)
      })
    })
  })

  describe('Security Tests', () => {
    test('should not expose sensitive information', async () => {
      const { GET } = await import('@/app/api/ping/route')
      
      const request = new NextRequest('http://localhost:3000/api/ping', {
        method: 'GET',
      })

      const response = await GET(request)
      const data = await response.json()

      // Should not expose internal paths, secrets, or detailed system info
      const responseString = JSON.stringify(data)
      expect(responseString).not.toMatch(/password|secret|key|token/i)
      expect(responseString).not.toMatch(/\/home\/|\/usr\/|C:\\/i)
    })

    test('should handle different client IPs', async () => {
      // The ping endpoint doesn't return clientIP in response, but logs it
      // This test verifies the endpoint works with different IPs
      const { getClientIP } = require('@/lib/security')

      const testIPs = ['192.168.1.1', '10.0.0.1', '172.16.0.1']

      for (const ip of testIPs) {
        getClientIP.mockReturnValue(ip)

        const { GET } = await import('@/app/api/ping/route')

        const request = new NextRequest('http://localhost:3000/api/ping', {
          method: 'GET',
        })

        const response = await GET(request)
        const data = await response.json()

        // Verify the response is still valid regardless of client IP
        expect(response.status).toBe(200)
        expect(data.status).toBe('ok')
      }
    })
  })

  describe('HTTP Method Validation', () => {
    test('should support only allowed methods', async () => {
      const allowedMethods = ['GET', 'HEAD', 'OPTIONS']
      
      for (const method of allowedMethods) {
        const request = new NextRequest('http://localhost:3000/api/ping', {
          method,
        })

        // Import the appropriate handler
        const route = await import('@/app/api/ping/route')
        const handler = route[method as keyof typeof route]
        
        expect(handler).toBeDefined()
        
        if (handler) {
          const response = await handler(request)
          expect(response.status).toBe(200)
        }
      }
    })
  })
})
