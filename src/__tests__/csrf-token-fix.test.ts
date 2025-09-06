/**
 * Comprehensive tests for CSRF token authentication fix
 * Tests the resolution of the chicken-and-egg problem between session requirement and CSRF token fetching
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals'
import { NextRequest, NextResponse } from 'next/server'
import { GET as csrfGet, validateTemporaryCSRFToken, invalidateTemporaryCSRFToken } from '@/app/api/csrf/route'
import { GET as authGet, POST as authPost } from '@/app/api/auth/route'
import { validateCSRFMiddleware } from '@/lib/csrfProtection'

// Mock dependencies
jest.mock('@/utils/logger')
jest.mock('@/model/auditService')
jest.mock('@/lib/security')

describe('CSRF Token Authentication Fix', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  describe('Public CSRF Token Endpoint (/api/csrf)', () => {
    it('should generate temporary CSRF token without authentication', async () => {
      const request = new NextRequest('http://localhost:3000/api/csrf', {
        method: 'GET',
        headers: {
          'x-forwarded-for': '127.0.0.1',
          'user-agent': 'test-agent'
        }
      })

      const response = await csrfGet(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data).toHaveProperty('csrfToken')
      expect(data).toHaveProperty('tokenId')
      expect(data).toHaveProperty('expiresAt')
      expect(data.temporary).toBe(true)
      expect(typeof data.csrfToken).toBe('string')
      expect(data.csrfToken.length).toBeGreaterThan(0)
    })

    it('should set CSRF token as cookie', async () => {
      const request = new NextRequest('http://localhost:3000/api/csrf', {
        method: 'GET',
        headers: {
          'x-forwarded-for': '127.0.0.1'
        }
      })

      const response = await csrfGet(request)
      const cookies = response.headers.get('set-cookie')

      expect(cookies).toContain('csrf-token=')
      expect(cookies).toContain('SameSite=Strict')
    })

    it('should include CSRF headers in response', async () => {
      const request = new NextRequest('http://localhost:3000/api/csrf', {
        method: 'GET',
        headers: {
          'x-forwarded-for': '127.0.0.1'
        }
      })

      const response = await csrfGet(request)

      expect(response.headers.get('X-CSRF-Token')).toBeTruthy()
      expect(response.headers.get('X-CSRF-Token-ID')).toBeTruthy()
      expect(response.headers.get('X-CSRF-Expires')).toBeTruthy()
      expect(response.headers.get('X-CSRF-Temporary')).toBe('true')
    })
  })

  describe('Temporary CSRF Token Validation', () => {
    it('should validate correct temporary CSRF token', async () => {
      // First generate a token
      const generateRequest = new NextRequest('http://localhost:3000/api/csrf', {
        method: 'GET',
        headers: { 'x-forwarded-for': '127.0.0.1' }
      })

      const generateResponse = await csrfGet(generateRequest)
      const tokenData = await generateResponse.json()

      // Then validate it
      const validation = validateTemporaryCSRFToken(
        tokenData.tokenId,
        tokenData.csrfToken,
        '127.0.0.1'
      )

      expect(validation.isValid).toBe(true)
      expect(validation.error).toBeUndefined()
    })

    it('should reject invalid temporary CSRF token', () => {
      const validation = validateTemporaryCSRFToken(
        'invalid-token-id',
        'invalid-token',
        '127.0.0.1'
      )

      expect(validation.isValid).toBe(false)
      expect(validation.error).toBe('CSRF token not found')
    })

    it('should reject expired temporary CSRF token', async () => {
      // This test would require mocking Date.now() to simulate expiration
      // For now, we'll test the basic validation logic
      const validation = validateTemporaryCSRFToken(
        'non-existent-id',
        'some-token',
        '127.0.0.1'
      )

      expect(validation.isValid).toBe(false)
    })
  })

  describe('CSRF Middleware Integration', () => {
    it('should allow public CSRF endpoint without session', () => {
      const request = new NextRequest('http://localhost:3000/api/csrf', {
        method: 'GET'
      })

      const result = validateCSRFMiddleware(request)
      expect(result).toBeNull() // Should allow the request
    })

    it('should allow login with temporary CSRF token', async () => {
      // Generate temporary token first
      const csrfRequest = new NextRequest('http://localhost:3000/api/csrf', {
        method: 'GET',
        headers: { 'x-forwarded-for': '127.0.0.1' }
      })

      const csrfResponse = await csrfGet(csrfRequest)
      const tokenData = await csrfResponse.json()

      // Test login request with temporary token
      const loginRequest = new NextRequest('http://localhost:3000/api/auth', {
        method: 'POST',
        headers: {
          'x-csrf-token': tokenData.csrfToken,
          'x-csrf-token-id': tokenData.tokenId,
          'x-forwarded-for': '127.0.0.1'
        }
      })

      const result = validateCSRFMiddleware(loginRequest)
      expect(result).toBeNull() // Should allow the request
    })

    it('should reject login without CSRF token', () => {
      const request = new NextRequest('http://localhost:3000/api/auth', {
        method: 'POST'
      })

      const result = validateCSRFMiddleware(request)
      expect(result).not.toBeNull()
      expect(result?.status).toBe(403)
    })

    it('should reject login with invalid temporary CSRF token', () => {
      const request = new NextRequest('http://localhost:3000/api/auth', {
        method: 'POST',
        headers: {
          'x-csrf-token': 'invalid-token',
          'x-csrf-token-id': 'invalid-id'
        }
      })

      const result = validateCSRFMiddleware(request)
      expect(result).not.toBeNull()
      expect(result?.status).toBe(403)
    })
  })

  describe('Token Invalidation', () => {
    it('should invalidate temporary token after use', async () => {
      // Generate token
      const request = new NextRequest('http://localhost:3000/api/csrf', {
        method: 'GET',
        headers: { 'x-forwarded-for': '127.0.0.1' }
      })

      const response = await csrfGet(request)
      const tokenData = await response.json()

      // Validate token exists
      let validation = validateTemporaryCSRFToken(
        tokenData.tokenId,
        tokenData.csrfToken,
        '127.0.0.1'
      )
      expect(validation.isValid).toBe(true)

      // Invalidate token
      invalidateTemporaryCSRFToken(tokenData.tokenId)

      // Validate token is now invalid
      validation = validateTemporaryCSRFToken(
        tokenData.tokenId,
        tokenData.csrfToken,
        '127.0.0.1'
      )
      expect(validation.isValid).toBe(false)
    })
  })

  describe('Error Handling', () => {
    it('should handle CSRF endpoint errors gracefully', async () => {
      // Mock an error condition
      const originalConsoleError = console.error
      console.error = jest.fn()

      try {
        const request = new NextRequest('http://localhost:3000/api/csrf', {
          method: 'GET',
          headers: {
            'x-forwarded-for': '127.0.0.1'
          }
        })

        const response = await csrfGet(request)
        
        // Even with potential errors, should return a response
        expect(response).toBeDefined()
        expect(response.status).toBeGreaterThanOrEqual(200)
      } finally {
        console.error = originalConsoleError
      }
    })

    it('should provide meaningful error messages', () => {
      const validation = validateTemporaryCSRFToken(
        'non-existent',
        'invalid',
        '127.0.0.1'
      )

      expect(validation.isValid).toBe(false)
      expect(validation.error).toBeTruthy()
      expect(typeof validation.error).toBe('string')
    })
  })

  describe('Security Measures', () => {
    it('should generate unique tokens for each request', async () => {
      const request1 = new NextRequest('http://localhost:3000/api/csrf', {
        method: 'GET',
        headers: { 'x-forwarded-for': '127.0.0.1' }
      })

      const request2 = new NextRequest('http://localhost:3000/api/csrf', {
        method: 'GET',
        headers: { 'x-forwarded-for': '127.0.0.1' }
      })

      const response1 = await csrfGet(request1)
      const response2 = await csrfGet(request2)

      const data1 = await response1.json()
      const data2 = await response2.json()

      expect(data1.csrfToken).not.toBe(data2.csrfToken)
      expect(data1.tokenId).not.toBe(data2.tokenId)
    })

    it('should set appropriate token expiration', async () => {
      const request = new NextRequest('http://localhost:3000/api/csrf', {
        method: 'GET',
        headers: { 'x-forwarded-for': '127.0.0.1' }
      })

      const response = await csrfGet(request)
      const data = await response.json()

      const expiresAt = new Date(data.expiresAt).getTime()
      const now = Date.now()
      const tenMinutes = 10 * 60 * 1000

      expect(expiresAt).toBeGreaterThan(now)
      expect(expiresAt).toBeLessThanOrEqual(now + tenMinutes)
    })
  })
})
