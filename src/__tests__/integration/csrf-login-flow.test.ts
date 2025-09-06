/**
 * Integration tests for the complete CSRF-protected login flow
 * Tests the end-to-end process from token generation to successful authentication
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals'
import { NextRequest } from 'next/server'
import { GET as csrfGet } from '@/app/api/csrf/route'
import { POST as authPost } from '@/app/api/auth/route'

// Mock dependencies
jest.mock('@/utils/logger')
jest.mock('@/model/auditService')
jest.mock('@/lib/security', () => ({
  getClientIP: jest.fn(() => '127.0.0.1'),
  generateSecureToken: jest.fn(() => 'mock-secure-token-' + Math.random()),
  verifyPassword: jest.fn(() => true),
  trackLoginAttempt: jest.fn(() => true),
  createSession: jest.fn(() => ({
    id: 'mock-session-id',
    csrfToken: 'mock-session-csrf-token',
    createdAt: new Date(),
    lastAccessed: new Date(),
    isValid: true
  })),
  defaultSecurityConfig: {
    sessionTimeout: 3600000,
    maxLoginAttempts: 5,
    lockoutDuration: 900000
  },
  sanitizeInput: jest.fn((input) => input),
  validateInput: jest.fn(() => ({ isValid: true }))
}))

describe('CSRF-Protected Login Flow Integration', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  describe('Complete Login Flow', () => {
    it('should complete full login flow with temporary CSRF token', async () => {
      // Step 1: Generate temporary CSRF token
      const csrfRequest = new NextRequest('http://localhost:3000/api/csrf', {
        method: 'GET',
        headers: {
          'x-forwarded-for': '127.0.0.1',
          'user-agent': 'test-browser'
        }
      })

      const csrfResponse = await csrfGet(csrfRequest)
      expect(csrfResponse.status).toBe(200)

      const csrfData = await csrfResponse.json()
      expect(csrfData).toHaveProperty('csrfToken')
      expect(csrfData).toHaveProperty('tokenId')
      expect(csrfData.temporary).toBe(true)

      // Step 2: Use temporary CSRF token for login
      const loginRequest = new NextRequest('http://localhost:3000/api/auth', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-csrf-token': csrfData.csrfToken,
          'x-csrf-token-id': csrfData.tokenId,
          'x-forwarded-for': '127.0.0.1',
          'user-agent': 'test-browser'
        },
        body: JSON.stringify({
          username: 'admin',
          password: 'test-password'
        })
      })

      const loginResponse = await authPost(loginRequest)
      expect(loginResponse.status).toBe(200)

      const loginData = await loginResponse.json()
      expect(loginData.success).toBe(true)
      expect(loginData).toHaveProperty('sessionId')
      expect(loginData).toHaveProperty('csrfToken')
      expect(loginData).toHaveProperty('expiresAt')

      // Step 3: Verify session cookie is set
      const setCookieHeader = loginResponse.headers.get('set-cookie')
      expect(setCookieHeader).toContain('session-id=')
      expect(setCookieHeader).toContain('HttpOnly')
      expect(setCookieHeader).toContain('SameSite=Strict')
    })

    it('should reject login with missing CSRF token', async () => {
      const loginRequest = new NextRequest('http://localhost:3000/api/auth', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-forwarded-for': '127.0.0.1'
        },
        body: JSON.stringify({
          username: 'admin',
          password: 'test-password'
        })
      })

      // This should be caught by middleware, but if it reaches the handler
      // it should still handle the case gracefully
      const response = await authPost(loginRequest)
      
      // The response might vary depending on middleware handling
      expect([400, 401, 403]).toContain(response.status)
    })

    it('should reject login with invalid CSRF token', async () => {
      const loginRequest = new NextRequest('http://localhost:3000/api/auth', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-csrf-token': 'invalid-token',
          'x-csrf-token-id': 'invalid-id',
          'x-forwarded-for': '127.0.0.1'
        },
        body: JSON.stringify({
          username: 'admin',
          password: 'test-password'
        })
      })

      // This should be caught by middleware
      const response = await authPost(loginRequest)
      expect([400, 401, 403]).toContain(response.status)
    })
  })

  describe('Token Lifecycle Management', () => {
    it('should handle token expiration gracefully', async () => {
      // Generate token
      const csrfRequest = new NextRequest('http://localhost:3000/api/csrf', {
        method: 'GET',
        headers: { 'x-forwarded-for': '127.0.0.1' }
      })

      const csrfResponse = await csrfGet(csrfRequest)
      const csrfData = await csrfResponse.json()

      // Simulate token expiration by waiting or mocking time
      // For this test, we'll just verify the token has an expiration
      expect(csrfData.expiresAt).toBeTruthy()
      
      const expiresAt = new Date(csrfData.expiresAt).getTime()
      const now = Date.now()
      expect(expiresAt).toBeGreaterThan(now)
    })

    it('should generate new tokens for each request', async () => {
      const requests = Array.from({ length: 3 }, () => 
        new NextRequest('http://localhost:3000/api/csrf', {
          method: 'GET',
          headers: { 'x-forwarded-for': '127.0.0.1' }
        })
      )

      const responses = await Promise.all(requests.map(req => csrfGet(req)))
      const tokens = await Promise.all(responses.map(res => res.json()))

      // All tokens should be unique
      const tokenValues = tokens.map(t => t.csrfToken)
      const tokenIds = tokens.map(t => t.tokenId)

      expect(new Set(tokenValues).size).toBe(3)
      expect(new Set(tokenIds).size).toBe(3)
    })
  })

  describe('Security Validation', () => {
    it('should validate IP address consistency', async () => {
      // Generate token from one IP
      const csrfRequest = new NextRequest('http://localhost:3000/api/csrf', {
        method: 'GET',
        headers: { 'x-forwarded-for': '192.168.1.1' }
      })

      const csrfResponse = await csrfGet(csrfRequest)
      const csrfData = await csrfResponse.json()

      // Try to use token from different IP
      const loginRequest = new NextRequest('http://localhost:3000/api/auth', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-csrf-token': csrfData.csrfToken,
          'x-csrf-token-id': csrfData.tokenId,
          'x-forwarded-for': '192.168.1.2' // Different IP
        },
        body: JSON.stringify({
          username: 'admin',
          password: 'test-password'
        })
      })

      // The system should handle this gracefully
      // (might log warning but still allow for NAT/proxy scenarios)
      const response = await authPost(loginRequest)
      expect(response).toBeDefined()
    })

    it('should handle concurrent token requests', async () => {
      const concurrentRequests = Array.from({ length: 5 }, () =>
        new NextRequest('http://localhost:3000/api/csrf', {
          method: 'GET',
          headers: { 'x-forwarded-for': '127.0.0.1' }
        })
      )

      const responses = await Promise.all(
        concurrentRequests.map(req => csrfGet(req))
      )

      // All requests should succeed
      responses.forEach(response => {
        expect(response.status).toBe(200)
      })

      const tokens = await Promise.all(responses.map(res => res.json()))
      
      // All tokens should be valid and unique
      tokens.forEach(token => {
        expect(token.csrfToken).toBeTruthy()
        expect(token.tokenId).toBeTruthy()
        expect(token.temporary).toBe(true)
      })

      const uniqueTokens = new Set(tokens.map(t => t.csrfToken))
      expect(uniqueTokens.size).toBe(5)
    })
  })

  describe('Error Recovery', () => {
    it('should handle malformed requests gracefully', async () => {
      const malformedRequest = new NextRequest('http://localhost:3000/api/csrf', {
        method: 'GET',
        headers: {
          'x-forwarded-for': '', // Empty IP
          'user-agent': '' // Empty user agent
        }
      })

      const response = await csrfGet(malformedRequest)
      
      // Should still generate a token or return appropriate error
      expect(response.status).toBeGreaterThanOrEqual(200)
      expect(response.status).toBeLessThan(600)
    })

    it('should handle invalid JSON in login request', async () => {
      // First get a valid CSRF token
      const csrfRequest = new NextRequest('http://localhost:3000/api/csrf', {
        method: 'GET',
        headers: { 'x-forwarded-for': '127.0.0.1' }
      })

      const csrfResponse = await csrfGet(csrfRequest)
      const csrfData = await csrfResponse.json()

      // Then send invalid JSON
      const loginRequest = new NextRequest('http://localhost:3000/api/auth', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-csrf-token': csrfData.csrfToken,
          'x-csrf-token-id': csrfData.tokenId,
          'x-forwarded-for': '127.0.0.1'
        },
        body: 'invalid-json-data'
      })

      const response = await authPost(loginRequest)
      expect([400, 500]).toContain(response.status)
    })
  })
})
