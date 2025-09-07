/**
 * Authentication Fix Verification Tests
 * Tests to verify that the login authentication issues have been resolved
 */

import { describe, it, expect, beforeEach, jest } from '@jest/globals'
import { NextRequest } from 'next/server'
import { GET, POST } from '@/app/api/auth/route'

// Mock dependencies
jest.mock('@/lib/security')
jest.mock('@/utils/logger')
jest.mock('@/model/auditService')

const mockSecurity = require('@/lib/security')

describe('Authentication Fix Verification', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    
    // Setup default mocks
    mockSecurity.getClientIP.mockReturnValue('127.0.0.1')
    mockSecurity.sanitizeInput.mockImplementation((input: string) => input)
    mockSecurity.validateInput.mockReturnValue({ isValid: true })
    mockSecurity.trackLoginAttempt.mockReturnValue(true)
    mockSecurity.verifyPassword.mockReturnValue(true)
    mockSecurity.defaultSecurityConfig = {
      sessionTimeout: 3600000,
      maxLoginAttempts: 5,
      lockoutDuration: 900000
    }
  })

  describe('GET /api/auth - Session Management', () => {
    it('should create new session for unauthenticated users', async () => {
      const mockSession = {
        id: 'new-session-123',
        createdAt: new Date(),
        lastAccessed: new Date(),
        isValid: true,
        csrfToken: 'csrf-token-123',
      }

      mockSecurity.getSession.mockReturnValue(null)
      mockSecurity.createSession.mockReturnValue(mockSession)

      const request = new NextRequest('http://localhost/api/auth', {
        method: 'GET',
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

      expect(mockSecurity.createSession).toHaveBeenCalledTimes(1)
    })

    it('should return existing session for authenticated users', async () => {
      const mockSession = {
        id: 'existing-session-456',
        createdAt: new Date(),
        lastAccessed: new Date(),
        isValid: true,
        csrfToken: 'csrf-token-456',
      }

      mockSecurity.getSession.mockReturnValue(mockSession)

      const request = new NextRequest('http://localhost/api/auth', {
        method: 'GET',
        headers: {
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
    })
  })

  describe('POST /api/auth - Login Authentication', () => {
    it('should authenticate admin user with correct credentials', async () => {
      const mockSession = {
        id: 'login-session-789',
        createdAt: new Date(),
        lastAccessed: new Date(),
        isValid: true,
        csrfToken: 'login-csrf-token',
      }

      mockSecurity.createSession.mockReturnValue(mockSession)

      // Set environment variables for test
      process.env.ADMIN_USERNAME = 'admin'
      process.env.ADMIN_PASSWORD_HASH = '50ea037a8c1f7365ce632efae5ff87e53010d9dbfa756c785cd33573994f7095fa07d4006dee2bb281aa727f7455f0c48d9e1d87c6262dd5bcc5b03004c8168c'
      process.env.ADMIN_PASSWORD_SALT = '5acf2b02b38f79fe378864ea702d1fa6'

      const request = new NextRequest('http://localhost/api/auth', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          username: 'admin',
          password: 'Wq+D%xj]O5$$yjVAy4fT',
        }),
      })

      const response = await POST(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data.sessionId).toBe('login-session-789')
      expect(data.csrfToken).toBe('login-csrf-token')

      // Verify session cookie is set
      const setCookieHeader = response.headers.get('set-cookie')
      expect(setCookieHeader).toContain('session-id=login-session-789')
      expect(setCookieHeader).toContain('HttpOnly')
      expect(setCookieHeader).toContain('SameSite=Strict')
    })

    it('should reject invalid credentials', async () => {
      mockSecurity.verifyPassword.mockReturnValue(false)

      const request = new NextRequest('http://localhost/api/auth', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          username: 'admin',
          password: 'wrong-password',
        }),
      })

      const response = await POST(request)
      const data = await response.json()

      expect(response.status).toBe(401)
      expect(data.error).toBe('Invalid credentials')
    })
  })

  describe('Authentication Flow Integration', () => {
    it('should support complete login flow', async () => {
      // Step 1: Get session/CSRF token
      const sessionMock = {
        id: 'flow-session',
        createdAt: new Date(),
        lastAccessed: new Date(),
        isValid: true,
        csrfToken: 'flow-csrf-token',
      }

      mockSecurity.getSession.mockReturnValue(null)
      mockSecurity.createSession.mockReturnValue(sessionMock)

      const getRequest = new NextRequest('http://localhost/api/auth', {
        method: 'GET',
      })

      const getResponse = await GET(getRequest)
      const getData = await getResponse.json()

      expect(getData.authenticated).toBe(false)
      expect(getData.csrfToken).toBe('flow-csrf-token')

      // Step 2: Login with credentials
      mockSecurity.getSession.mockReturnValue(sessionMock)
      
      const postRequest = new NextRequest('http://localhost/api/auth', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: 'session-id=flow-session',
        },
        body: JSON.stringify({
          username: 'admin',
          password: 'Wq+D%xj]O5$$yjVAy4fT',
        }),
      })

      const postResponse = await POST(postRequest)
      const postData = await postResponse.json()

      expect(postResponse.status).toBe(200)
      expect(postData.success).toBe(true)
    })
  })
})
