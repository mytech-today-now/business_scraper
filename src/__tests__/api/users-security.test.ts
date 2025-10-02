/**
 * Users API Security Tests
 * Tests user management endpoints for sensitive data exposure
 */

import { NextRequest } from 'next/server'
import { GET, POST } from '@/app/api/users/route'

// Mock dependencies
jest.mock('@/lib/rbac-middleware', () => ({
  withRBAC: jest.fn((handler) => handler)
}))

jest.mock('@/lib/user-management', () => ({
  UserManagementService: {
    createUser: jest.fn(() => ({
      user: {
        id: '123',
        username: 'testuser',
        email: 'test@example.com',
        password_hash: 'hashed_password_123',
        password_salt: 'salt_123',
        first_name: 'Test',
        last_name: 'User',
        created_at: new Date()
      }
    }))
  }
}))

jest.mock('@/lib/postgresql-database', () => ({
  database: {
    executeQuery: jest.fn(() => ({
      rows: [
        {
          id: '1',
          username: 'user1',
          first_name: 'John',
          last_name: 'Doe',
          email: 'john@example.com',
          password_hash: 'secret_hash_123',
          password_salt: 'secret_salt_456',
          is_active: true,
          total_count: 1
        }
      ]
    }))
  }
}))

jest.mock('@/lib/security', () => ({
  getClientIP: jest.fn(() => '127.0.0.1')
}))

jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn()
  }
}))

jest.mock('@/lib/data-classification', () => ({
  dataClassificationService: {
    classifyObject: jest.fn(() => new Map([
      ['id', { protectionPolicy: { allowInResponses: true, maskInProduction: false } }],
      ['username', { protectionPolicy: { allowInResponses: true, maskInProduction: false } }],
      ['email', { protectionPolicy: { allowInResponses: true, maskInProduction: true } }],
      ['password_hash', { protectionPolicy: { allowInResponses: false, maskInProduction: true } }]
    ]))
  }
}))

jest.mock('@/lib/pii-detection', () => ({
  piiDetectionService: {
    redactPII: jest.fn((text) => ({ redactedText: text.replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, 'jo***@example.com') }))
  }
}))

describe('Users API Security Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    process.env.NODE_ENV = 'test'
  })

  describe('GET /api/users - List Users', () => {
    test('should never expose password hashes in user list', async () => {
      const request = new NextRequest('http://localhost:3000/api/users', {
        method: 'GET'
      })

      const mockContext = {
        session: { user: { id: 'admin' } }
      }

      const response = await GET(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data.data).toBeInstanceOf(Array)
      
      // Check that no user object contains sensitive fields
      data.data.forEach((user: any) => {
        expect(user).not.toHaveProperty('password')
        expect(user).not.toHaveProperty('password_hash')
        expect(user).not.toHaveProperty('password_salt')
        expect(user).not.toHaveProperty('passwordhash')
        expect(user).not.toHaveProperty('passwordsalt')
        expect(user).not.toHaveProperty('secret')
        expect(user).not.toHaveProperty('token')
        expect(user).not.toHaveProperty('api_key')
      })
    })

    test('should mask PII data in production', async () => {
      const originalEnv = process.env.NODE_ENV
      process.env.NODE_ENV = 'production'

      const request = new NextRequest('http://localhost:3000/api/users', {
        method: 'GET'
      })

      const mockContext = {
        session: { user: { id: 'admin' } }
      }

      const response = await GET(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(200)
      
      // Check that email is masked in production
      if (data.data.length > 0 && data.data[0].email) {
        expect(data.data[0].email).toMatch(/jo\*+@example\.com/)
      }

      process.env.NODE_ENV = originalEnv
    })

    test('should sanitize error responses', async () => {
      const { database } = require('@/lib/postgresql-database')
      database.executeQuery.mockRejectedValueOnce(new Error('Database error: password=secret123'))

      const request = new NextRequest('http://localhost:3000/api/users', {
        method: 'GET'
      })

      const mockContext = {
        session: { user: { id: 'admin' } }
      }

      const response = await GET(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(500)
      expect(data.error).not.toContain('password=secret123')
      expect(data.error).not.toContain('Database error')
    })

    test('should remove total_count from individual user objects', async () => {
      const request = new NextRequest('http://localhost:3000/api/users', {
        method: 'GET'
      })

      const mockContext = {
        session: { user: { id: 'admin' } }
      }

      const response = await GET(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(200)
      
      data.data.forEach((user: any) => {
        expect(user).not.toHaveProperty('total_count')
      })
    })
  })

  describe('POST /api/users - Create User', () => {
    test('should never expose password data in user creation response', async () => {
      const request = new NextRequest('http://localhost:3000/api/users', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          username: 'newuser',
          email: 'newuser@example.com',
          password: 'newpassword123',
          firstName: 'New',
          lastName: 'User'
        })
      })

      const mockContext = {
        session: { user: { id: 'admin' } }
      }

      const response = await POST(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(201)
      expect(data.success).toBe(true)
      expect(data.data).not.toHaveProperty('password')
      expect(data.data).not.toHaveProperty('password_hash')
      expect(data.data).not.toHaveProperty('password_salt')
      expect(data.data).not.toHaveProperty('passwordhash')
      expect(data.data).not.toHaveProperty('passwordsalt')
      expect(data.data).not.toHaveProperty('secret')
      expect(data.data).not.toHaveProperty('token')
      expect(data.data).not.toHaveProperty('api_key')
    })

    test('should validate required fields without exposing sensitive data', async () => {
      const request = new NextRequest('http://localhost:3000/api/users', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          username: 'incomplete'
          // Missing required fields
        })
      })

      const mockContext = {
        session: { user: { id: 'admin' } }
      }

      const response = await POST(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(400)
      expect(data.error).toBe('Missing required fields')
      expect(data).not.toHaveProperty('password')
      expect(data).not.toHaveProperty('sessionId')
    })

    test('should sanitize user creation error responses', async () => {
      const { UserManagementService } = require('@/lib/user-management')
      UserManagementService.createUser.mockRejectedValueOnce(
        new Error('User creation failed: database_url=postgresql://user:pass@localhost')
      )

      const request = new NextRequest('http://localhost:3000/api/users', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          username: 'newuser',
          email: 'newuser@example.com',
          password: 'newpassword123',
          firstName: 'New',
          lastName: 'User'
        })
      })

      const mockContext = {
        session: { user: { id: 'admin' } }
      }

      const response = await POST(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(400)
      expect(data.error).not.toContain('database_url=postgresql://user:pass@localhost')
      expect(data.error).not.toContain('User creation failed')
    })

    test('should handle all authentication field variations', async () => {
      // Mock user data with various sensitive field names
      const { UserManagementService } = require('@/lib/user-management')
      UserManagementService.createUser.mockResolvedValueOnce({
        user: {
          id: '123',
          username: 'testuser',
          password: 'plaintext_password',
          password_hash: 'hashed_password',
          password_salt: 'salt_value',
          passwordHash: 'camelCase_hash',
          passwordSalt: 'camelCase_salt',
          secret: 'secret_value',
          token: 'token_value',
          apiKey: 'api_key_value',
          api_key: 'snake_case_api_key',
          privateKey: 'private_key_value',
          private_key: 'snake_case_private_key',
          sessionId: 'session_id_value',
          session_id: 'snake_case_session_id',
          csrfToken: 'csrf_token_value',
          csrf_token: 'snake_case_csrf_token',
          authToken: 'auth_token_value',
          auth_token: 'snake_case_auth_token',
          accessToken: 'access_token_value',
          access_token: 'snake_case_access_token',
          refreshToken: 'refresh_token_value',
          refresh_token: 'snake_case_refresh_token',
          salt: 'salt_value',
          hash: 'hash_value',
          encrypted_password: 'encrypted_password_value',
          first_name: 'Test',
          last_name: 'User'
        }
      })

      const request = new NextRequest('http://localhost:3000/api/users', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          username: 'testuser',
          email: 'test@example.com',
          password: 'password123',
          firstName: 'Test',
          lastName: 'User'
        })
      })

      const mockContext = {
        session: { user: { id: 'admin' } }
      }

      const response = await POST(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(201)
      
      // Check that ALL sensitive field variations are removed
      const sensitiveFields = [
        'password', 'password_hash', 'password_salt', 'passwordHash', 'passwordSalt',
        'secret', 'token', 'apiKey', 'api_key', 'privateKey', 'private_key',
        'sessionId', 'session_id', 'csrfToken', 'csrf_token', 'authToken', 'auth_token',
        'accessToken', 'access_token', 'refreshToken', 'refresh_token',
        'salt', 'hash', 'encrypted_password'
      ]
      
      sensitiveFields.forEach(field => {
        expect(data.data).not.toHaveProperty(field)
      })
      
      // Ensure safe fields are still present
      expect(data.data).toHaveProperty('first_name')
      expect(data.data).toHaveProperty('last_name')
    })
  })
})
