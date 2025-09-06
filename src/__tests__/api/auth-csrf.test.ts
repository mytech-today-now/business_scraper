/**
 * CSRF Token Authentication Tests
 * Comprehensive tests for CSRF token fetching and authentication flow
 */

import { NextRequest, NextResponse } from 'next/server'
import { GET, POST } from '@/app/api/auth/route'
import { createSession, getSession, invalidateSession } from '@/lib/security'
import { csrfProtectionService } from '@/lib/csrfProtection'
import { logger } from '@/utils/logger'

// Mock dependencies
jest.mock('@/lib/security')
jest.mock('@/lib/csrfProtection')
jest.mock('@/utils/logger')
jest.mock('@/model/auditService')

const mockCreateSession = createSession as jest.MockedFunction<typeof createSession>
const mockGetSession = getSession as jest.MockedFunction<typeof getSession>
const mockInvalidateSession = invalidateSession as jest.MockedFunction<typeof invalidateSession>

describe('Auth API CSRF Token Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('GET /api/auth - CSRF Token Fetching', () => {
    it('should create new session and return CSRF token for unauthenticated users', async () => {
      const mockSession = {
        id: 'new-session-123',
        createdAt: new Date(),
        lastAccessed: new Date(),
        isValid: true,
        csrfToken: 'csrf-token-123',
      }

      mockCreateSession.mockReturnValue(mockSession)

      const request = new NextRequest('http://localhost/api/auth', {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await GET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data).toEqual({
        authenticated: false,
        sessionId: 'new-session-123',
        csrfToken: 'csrf-token-123',
        expiresAt: expect.any(String),
      })

      // Verify session cookie is set
      const setCookieHeader = response.headers.get('set-cookie')
      expect(setCookieHeader).toContain('session-id=new-session-123')
      expect(setCookieHeader).toContain('HttpOnly')
      expect(setCookieHeader).toContain('SameSite=Strict')

      expect(mockCreateSession).toHaveBeenCalledTimes(1)
    })

    it('should return existing session data for authenticated users', async () => {
      const mockSession = {
        id: 'existing-session-456',
        createdAt: new Date(),
        lastAccessed: new Date(),
        isValid: true,
        csrfToken: 'csrf-token-456',
      }

      mockGetSession.mockReturnValue(mockSession)

      const request = new NextRequest('http://localhost/api/auth', {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          Cookie: 'session-id=existing-session-456',
        },
      })

      const response = await GET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data).toEqual({
        authenticated: true,
        sessionId: 'existing-session-456',
        csrfToken: 'csrf-token-456',
        expiresAt: expect.any(String),
      })

      expect(mockGetSession).toHaveBeenCalledWith('existing-session-456')
      expect(mockCreateSession).not.toHaveBeenCalled()
    })

    it('should create new session when existing session is invalid', async () => {
      const mockNewSession = {
        id: 'replacement-session-789',
        createdAt: new Date(),
        lastAccessed: new Date(),
        isValid: true,
        csrfToken: 'csrf-token-789',
      }

      mockGetSession.mockReturnValue(null) // Invalid session
      mockCreateSession.mockReturnValue(mockNewSession)

      const request = new NextRequest('http://localhost/api/auth', {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          Cookie: 'session-id=invalid-session',
        },
      })

      const response = await GET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data).toEqual({
        authenticated: false,
        sessionId: 'replacement-session-789',
        csrfToken: 'csrf-token-789',
        expiresAt: expect.any(String),
      })

      expect(mockGetSession).toHaveBeenCalledWith('invalid-session')
      expect(mockCreateSession).toHaveBeenCalledTimes(1)
    })

    it('should handle expired sessions by creating new ones', async () => {
      const expiredSession = {
        id: 'expired-session',
        createdAt: new Date(),
        lastAccessed: new Date(),
        isValid: false, // Expired session
        csrfToken: 'old-csrf-token',
      }

      const newSession = {
        id: 'new-session-after-expiry',
        createdAt: new Date(),
        lastAccessed: new Date(),
        isValid: true,
        csrfToken: 'new-csrf-token',
      }

      mockGetSession.mockReturnValue(expiredSession)
      mockCreateSession.mockReturnValue(newSession)

      const request = new NextRequest('http://localhost/api/auth', {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          Cookie: 'session-id=expired-session',
        },
      })

      const response = await GET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data).toEqual({
        authenticated: false,
        sessionId: 'new-session-after-expiry',
        csrfToken: 'new-csrf-token',
        expiresAt: expect.any(String),
      })

      expect(mockCreateSession).toHaveBeenCalledTimes(1)
    })

    it('should handle errors gracefully', async () => {
      mockCreateSession.mockImplementation(() => {
        throw new Error('Session creation failed')
      })

      const request = new NextRequest('http://localhost/api/auth', {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await GET(request)
      const data = await response.json()

      expect(response.status).toBe(500)
      expect(data.error).toBe('Internal server error')
    })
  })

  describe('CSRF Token Integration', () => {
    it('should provide valid CSRF tokens that can be used for authentication', async () => {
      const mockSession = {
        id: 'csrf-test-session',
        createdAt: new Date(),
        lastAccessed: new Date(),
        isValid: true,
        csrfToken: 'valid-csrf-token',
      }

      mockCreateSession.mockReturnValue(mockSession)
      mockGetSession.mockReturnValue(mockSession)

      // First, get CSRF token
      const getRequest = new NextRequest('http://localhost/api/auth', {
        method: 'GET',
      })

      const getResponse = await GET(getRequest)
      const getData = await getResponse.json()

      expect(getData.csrfToken).toBe('valid-csrf-token')

      // Then, use the token for authentication (this would be tested in login flow)
      expect(getData.sessionId).toBe('csrf-test-session')
    })
  })

  describe('Security Headers and Cookies', () => {
    it('should set secure session cookies with proper attributes', async () => {
      const mockSession = {
        id: 'secure-session',
        createdAt: new Date(),
        lastAccessed: new Date(),
        isValid: true,
        csrfToken: 'secure-csrf-token',
      }

      mockCreateSession.mockReturnValue(mockSession)

      const request = new NextRequest('http://localhost/api/auth', {
        method: 'GET',
      })

      const response = await GET(request)
      const setCookieHeader = response.headers.get('set-cookie')

      expect(setCookieHeader).toContain('session-id=secure-session')
      expect(setCookieHeader).toContain('HttpOnly')
      expect(setCookieHeader).toContain('SameSite=Strict')
      expect(setCookieHeader).toContain('Path=/')
      expect(setCookieHeader).toContain('Max-Age=')
    })

    it('should include secure flag in production environment', async () => {
      const originalEnv = process.env.NODE_ENV
      process.env.NODE_ENV = 'production'

      const mockSession = {
        id: 'prod-session',
        createdAt: new Date(),
        lastAccessed: new Date(),
        isValid: true,
        csrfToken: 'prod-csrf-token',
      }

      mockCreateSession.mockReturnValue(mockSession)

      const request = new NextRequest('http://localhost/api/auth', {
        method: 'GET',
      })

      const response = await GET(request)
      const setCookieHeader = response.headers.get('set-cookie')

      expect(setCookieHeader).toContain('Secure')

      process.env.NODE_ENV = originalEnv
    })
  })
})
