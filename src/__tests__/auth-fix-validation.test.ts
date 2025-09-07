/**
 * Authentication Fix Validation Tests
 * Tests for the login screen authentication issue fix
 */

import { NextRequest, NextResponse } from 'next/server'
import { POST, GET } from '@/app/api/auth/route'
import { verifyPassword } from '@/lib/security'
import { logger } from '@/utils/logger'

// Mock logger
jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  },
}))

// Mock audit service
jest.mock('@/model/auditService', () => ({
  auditService: {
    logSecurityEvent: jest.fn(),
    logAuditEvent: jest.fn(),
  },
}))

// Mock CSRF route
jest.mock('@/app/api/csrf/route', () => ({
  invalidateTemporaryCSRFToken: jest.fn(),
}))

describe('Authentication Fix Validation', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    // Reset environment variables
    process.env.ADMIN_USERNAME = 'admin'
    process.env.ADMIN_PASSWORD = 'Wq+D%xj]O5$$yjVAy4fT'
    process.env.ENABLE_AUTH = 'true'
  })

  describe('Password Verification', () => {
    it('should verify the admin password correctly', () => {
      const password = 'Wq+D%xj]O5$$yjVAy4fT'
      const hash = '50ea037a8c1f7365ce632efae5ff87e53010d9dbfa756c785cd33573994f7095fa07d4006dee2bb281aa727f7455f0c48d9e1d87c6262dd5bcc5b03004c8168c'
      const salt = '5acf2b02b38f79fe378864ea702d1fa6'

      const isValid = verifyPassword(password, hash, salt)
      expect(isValid).toBe(true)
    })

    it('should reject invalid passwords', () => {
      const password = 'wrongpassword'
      const hash = '50ea037a8c1f7365ce632efae5ff87e53010d9dbfa756c785cd33573994f7095fa07d4006dee2bb281aa727f7455f0c48d9e1d87c6262dd5bcc5b03004c8168c'
      const salt = '5acf2b02b38f79fe378864ea702d1fa6'

      const isValid = verifyPassword(password, hash, salt)
      expect(isValid).toBe(false)
    })
  })

  describe('Authentication API Endpoints', () => {
    it('should handle GET requests for session status', async () => {
      const request = new NextRequest('http://localhost:3000/api/auth', {
        method: 'GET',
      })

      const response = await GET(request)
      expect(response.status).toBe(200)

      const data = await response.json()
      expect(data).toHaveProperty('authenticated')
      expect(data).toHaveProperty('sessionId')
      expect(data).toHaveProperty('csrfToken')
    })

    it('should handle POST requests for login with valid credentials', async () => {
      const request = new NextRequest('http://localhost:3000/api/auth', {
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
      expect(response.status).toBe(200)

      const data = await response.json()
      expect(data.success).toBe(true)
      expect(data).toHaveProperty('sessionId')
      expect(data).toHaveProperty('csrfToken')
    })

    it('should reject POST requests with invalid credentials', async () => {
      const request = new NextRequest('http://localhost:3000/api/auth', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          username: 'admin',
          password: 'wrongpassword',
        }),
      })

      const response = await POST(request)
      expect(response.status).toBe(401)

      const data = await response.json()
      expect(data.error).toBe('Invalid credentials')
    })

    it('should reject POST requests with missing credentials', async () => {
      const request = new NextRequest('http://localhost:3000/api/auth', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          username: '',
          password: '',
        }),
      })

      const response = await POST(request)
      expect(response.status).toBe(400)

      const data = await response.json()
      expect(data.error).toBe('Username and password are required')
    })
  })

  describe('Session Management', () => {
    it('should create a valid session on successful login', async () => {
      const request = new NextRequest('http://localhost:3000/api/auth', {
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
      expect(response.status).toBe(200)

      // Check that session cookie is set
      const setCookieHeader = response.headers.get('set-cookie')
      expect(setCookieHeader).toContain('session-id=')
      expect(setCookieHeader).toContain('HttpOnly')
      expect(setCookieHeader).toContain('SameSite=Strict')
    })
  })

  describe('Environment Configuration', () => {
    it('should use correct admin credentials from environment', () => {
      expect(process.env.ADMIN_USERNAME).toBe('admin')
      expect(process.env.ADMIN_PASSWORD).toBe('Wq+D%xj]O5$$yjVAy4fT')
      expect(process.env.ENABLE_AUTH).toBe('true')
    })
  })
})
