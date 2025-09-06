/**
 * Integration test for CSRF authentication fix
 * Verifies that the route conflict between NextAuth.js and CSRF endpoints is resolved
 * 
 * This test addresses GitHub Issue #149: CSRF Token Authentication Failure
 */

import { NextRequest } from 'next/server'
import { GET as csrfGet } from '@/app/api/csrf/route'
import { POST as authPost } from '@/app/api/auth/route'

// Mock dependencies
jest.mock('@/lib/security', () => ({
  createSession: jest.fn(() => ({
    id: 'mock-session-id',
    csrfToken: 'mock-csrf-token',
    createdAt: new Date(),
    lastAccessed: new Date(),
    isValid: true,
  })),
  getSession: jest.fn(),
  getClientIP: jest.fn(() => '127.0.0.1'),
  sanitizeInput: jest.fn((input) => input),
  validateInput: jest.fn(() => ({ isValid: true })),
  verifyPassword: jest.fn(() => true),
  trackLoginAttempt: jest.fn(() => true),
  defaultSecurityConfig: {
    sessionTimeout: 3600000,
  },
}))

jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  },
}))

jest.mock('@/model/auditService', () => ({
  auditService: {
    logAuditEvent: jest.fn(),
    logSecurityEvent: jest.fn(),
  },
}))

jest.mock('@/lib/oauth/oauth-middleware', () => ({
  getOAuthContext: jest.fn(),
}))

jest.mock('@/app/api/csrf/route', () => ({
  invalidateTemporaryCSRFToken: jest.fn(),
}))

describe('CSRF Authentication Fix Integration Test', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    
    // Set up environment variables for testing
    process.env.ADMIN_USERNAME = 'admin'
    process.env.ADMIN_PASSWORD = 'admin123'
  })

  afterEach(() => {
    // Clean up environment variables
    delete process.env.ADMIN_USERNAME
    delete process.env.ADMIN_PASSWORD
  })

  describe('CSRF Token Fetching', () => {
    it('should successfully fetch CSRF token from /api/csrf without 401 error', async () => {
      const request = new NextRequest('http://localhost:3000/api/csrf', {
        method: 'GET',
        headers: {
          'Accept': 'application/json',
          'User-Agent': 'test-browser',
        },
      })

      const response = await csrfGet(request)
      const data = await response.json()

      // Verify successful response
      expect(response.status).toBe(200)
      expect(data).toHaveProperty('csrfToken')
      expect(data).toHaveProperty('sessionId')
      expect(data).toHaveProperty('expiresAt')
      expect(data.authenticated).toBe(false) // Should be false for new session
      expect(data.temporary).toBe(false) // Should use session-based tokens

      // Verify CSRF token is present in headers
      expect(response.headers.get('X-CSRF-Token')).toBe('mock-csrf-token')
      expect(response.headers.get('X-CSRF-Temporary')).toBe('false')
    })

    it('should set proper cookies for session and CSRF token', async () => {
      const request = new NextRequest('http://localhost:3000/api/csrf', {
        method: 'GET',
        headers: {
          'Accept': 'application/json',
          'User-Agent': 'test-browser',
        },
      })

      const response = await csrfGet(request)

      // Check that session cookie is set
      const setCookieHeaders = response.headers.getSetCookie()
      const sessionCookie = setCookieHeaders.find(cookie => cookie.includes('session-id='))
      const csrfCookie = setCookieHeaders.find(cookie => cookie.includes('csrf-token='))

      expect(sessionCookie).toBeDefined()
      expect(csrfCookie).toBeDefined()
      expect(sessionCookie).toContain('HttpOnly')
      expect(sessionCookie).toContain('SameSite=Strict')
      expect(csrfCookie).toContain('SameSite=Strict')
    })
  })

  describe('Authentication Flow', () => {
    it('should complete full authentication flow without CSRF errors', async () => {
      // Step 1: Fetch CSRF token
      const csrfRequest = new NextRequest('http://localhost:3000/api/csrf', {
        method: 'GET',
        headers: {
          'Accept': 'application/json',
          'User-Agent': 'test-browser',
        },
      })

      const csrfResponse = await csrfGet(csrfRequest)
      const csrfData = await csrfResponse.json()

      expect(csrfResponse.status).toBe(200)
      expect(csrfData.csrfToken).toBeDefined()

      // Step 2: Use CSRF token for login
      const loginRequest = new NextRequest('http://localhost:3000/api/auth', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfData.csrfToken,
          'User-Agent': 'test-browser',
          'Cookie': `session-id=${csrfData.sessionId}`,
        },
        body: JSON.stringify({
          username: 'admin',
          password: 'admin123',
        }),
      })

      const loginResponse = await authPost(loginRequest)
      const loginData = await loginResponse.json()

      // Verify successful login
      expect(loginResponse.status).toBe(200)
      expect(loginData.success).toBe(true)
      expect(loginData.csrfToken).toBeDefined()
      expect(loginData.sessionId).toBeDefined()
    })
  })

  describe('Error Handling', () => {
    it('should handle CSRF endpoint errors gracefully', async () => {
      // Mock an error in session creation
      const { createSession } = require('@/lib/security')
      createSession.mockImplementationOnce(() => {
        throw new Error('Session creation failed')
      })

      const request = new NextRequest('http://localhost:3000/api/csrf', {
        method: 'GET',
        headers: {
          'Accept': 'application/json',
          'User-Agent': 'test-browser',
        },
      })

      const response = await csrfGet(request)
      const data = await response.json()

      expect(response.status).toBe(500)
      expect(data.error).toBe('Internal server error')
    })
  })

  describe('Security Compliance', () => {
    it('should log security events for audit compliance', async () => {
      const { auditService } = require('@/model/auditService')

      const request = new NextRequest('http://localhost:3000/api/csrf', {
        method: 'GET',
        headers: {
          'Accept': 'application/json',
          'User-Agent': 'test-browser',
        },
      })

      await csrfGet(request)

      // Verify audit logging
      expect(auditService.logAuditEvent).toHaveBeenCalledWith(
        'csrf_token_created',
        'security',
        expect.objectContaining({
          sessionId: 'mock-session-id',
          ipAddress: '127.0.0.1',
          severity: 'low',
          category: 'security',
          complianceFlags: ['SOC2'],
        })
      )
    })

    it('should include proper security headers', async () => {
      const request = new NextRequest('http://localhost:3000/api/csrf', {
        method: 'GET',
        headers: {
          'Accept': 'application/json',
          'User-Agent': 'test-browser',
        },
      })

      const response = await csrfGet(request)

      // Verify security headers
      expect(response.headers.get('X-CSRF-Token')).toBeDefined()
      expect(response.headers.get('X-CSRF-Expires')).toBeDefined()
      expect(response.headers.get('X-CSRF-Temporary')).toBe('false')
    })
  })
})
