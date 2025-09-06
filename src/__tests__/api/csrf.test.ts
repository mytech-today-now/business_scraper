/**
 * Tests for CSRF Token API endpoint
 * Verifies the fix for the authentication route conflict issue
 */

import { NextRequest } from 'next/server'
import { GET, POST } from '@/app/api/csrf/route'
import { createSession, getSession } from '@/lib/security'

// Mock dependencies
jest.mock('@/lib/security', () => ({
  createSession: jest.fn(),
  getSession: jest.fn(),
  getClientIP: jest.fn(() => '127.0.0.1'),
  defaultSecurityConfig: {
    sessionTimeout: 3600000, // 1 hour
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

const mockCreateSession = createSession as jest.MockedFunction<typeof createSession>
const mockGetSession = getSession as jest.MockedFunction<typeof getSession>

describe('/api/csrf', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('GET /api/csrf', () => {
    it('should create new session and return CSRF token for unauthenticated user', async () => {
      const mockSession = {
        id: 'test-session-id',
        csrfToken: 'test-csrf-token',
        createdAt: new Date(),
        lastAccessed: new Date(),
        isValid: true,
      }

      mockCreateSession.mockReturnValue(mockSession)

      const request = new NextRequest('http://localhost:3000/api/csrf', {
        method: 'GET',
        headers: {
          'user-agent': 'test-agent',
        },
      })

      const response = await GET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data).toEqual({
        authenticated: false,
        sessionId: 'test-session-id',
        csrfToken: 'test-csrf-token',
        expiresAt: expect.any(String),
        temporary: false,
      })

      expect(mockCreateSession).toHaveBeenCalledTimes(1)
    })

    it('should return existing CSRF token for valid session', async () => {
      const mockSession = {
        id: 'existing-session-id',
        csrfToken: 'existing-csrf-token',
        createdAt: new Date(),
        lastAccessed: new Date(),
        isValid: true,
      }

      mockGetSession.mockReturnValue(mockSession)

      const request = new NextRequest('http://localhost:3000/api/csrf', {
        method: 'GET',
        headers: {
          'user-agent': 'test-agent',
          cookie: 'session-id=existing-session-id',
        },
      })

      const response = await GET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data).toEqual({
        authenticated: true,
        sessionId: 'existing-session-id',
        csrfToken: 'existing-csrf-token',
        expiresAt: expect.any(String),
        temporary: false,
      })

      expect(mockGetSession).toHaveBeenCalledWith('existing-session-id')
    })

    it('should create new session when existing session is invalid', async () => {
      const mockNewSession = {
        id: 'new-session-id',
        csrfToken: 'new-csrf-token',
        createdAt: new Date(),
        lastAccessed: new Date(),
        isValid: true,
      }

      mockGetSession.mockReturnValue(null) // Invalid session
      mockCreateSession.mockReturnValue(mockNewSession)

      const request = new NextRequest('http://localhost:3000/api/csrf', {
        method: 'GET',
        headers: {
          'user-agent': 'test-agent',
          cookie: 'session-id=invalid-session-id',
        },
      })

      const response = await GET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data).toEqual({
        authenticated: false,
        sessionId: 'new-session-id',
        csrfToken: 'new-csrf-token',
        expiresAt: expect.any(String),
        temporary: false,
      })

      expect(mockGetSession).toHaveBeenCalledWith('invalid-session-id')
      expect(mockCreateSession).toHaveBeenCalledTimes(1)
    })

    it('should handle errors gracefully', async () => {
      mockCreateSession.mockImplementation(() => {
        throw new Error('Session creation failed')
      })

      const request = new NextRequest('http://localhost:3000/api/csrf', {
        method: 'GET',
        headers: {
          'user-agent': 'test-agent',
        },
      })

      const response = await GET(request)
      const data = await response.json()

      expect(response.status).toBe(500)
      expect(data).toEqual({
        error: 'Internal server error',
      })
    })
  })

  describe('POST /api/csrf', () => {
    it('should refresh CSRF token for valid session', async () => {
      const mockSession = {
        id: 'test-session-id',
        csrfToken: 'old-csrf-token',
        createdAt: new Date(),
        lastAccessed: new Date(),
        isValid: true,
      }

      const mockNewSession = {
        id: 'new-session-id',
        csrfToken: 'new-csrf-token',
        createdAt: new Date(),
        lastAccessed: new Date(),
        isValid: true,
      }

      mockGetSession.mockReturnValue(mockSession)
      mockCreateSession.mockReturnValue(mockNewSession)

      const request = new NextRequest('http://localhost:3000/api/csrf', {
        method: 'POST',
        headers: {
          'user-agent': 'test-agent',
          cookie: 'session-id=test-session-id',
        },
      })

      const response = await POST(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data).toEqual({
        authenticated: true,
        sessionId: 'test-session-id',
        csrfToken: 'new-csrf-token', // Should be the new token
        expiresAt: expect.any(String),
        temporary: false,
      })

      expect(mockGetSession).toHaveBeenCalledWith('test-session-id')
      expect(mockCreateSession).toHaveBeenCalledTimes(1)
    })

    it('should return 401 for missing session', async () => {
      const request = new NextRequest('http://localhost:3000/api/csrf', {
        method: 'POST',
        headers: {
          'user-agent': 'test-agent',
        },
      })

      const response = await POST(request)
      const data = await response.json()

      expect(response.status).toBe(401)
      expect(data).toEqual({
        error: 'No session found',
      })
    })

    it('should return 401 for invalid session', async () => {
      mockGetSession.mockReturnValue(null)

      const request = new NextRequest('http://localhost:3000/api/csrf', {
        method: 'POST',
        headers: {
          'user-agent': 'test-agent',
          cookie: 'session-id=invalid-session-id',
        },
      })

      const response = await POST(request)
      const data = await response.json()

      expect(response.status).toBe(401)
      expect(data).toEqual({
        error: 'Invalid session',
      })

      expect(mockGetSession).toHaveBeenCalledWith('invalid-session-id')
    })
  })
})
