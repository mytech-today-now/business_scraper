/**
 * Comprehensive Security Tests for Sensitive Data Protection
 * Tests all API endpoints for sensitive data exposure vulnerabilities
 */

import { NextRequest, NextResponse } from 'next/server'
import { ResponseSanitizer, sanitizeErrorMessage, sanitizeSessionData, DataClassification } from '@/lib/response-sanitization'

describe('Sensitive Data Protection Tests', () => {
  let sanitizer: ResponseSanitizer

  beforeEach(() => {
    sanitizer = new ResponseSanitizer()
  })

  describe('Response Sanitization', () => {
    test('should remove password fields from responses', () => {
      const testData = {
        id: '123',
        username: 'testuser',
        password: 'secret123',
        password_hash: 'hashed_password',
        password_salt: 'salt123',
        email: 'test@example.com'
      }

      const result = sanitizer.sanitize(testData)
      
      expect(result.sanitizedData).not.toHaveProperty('password')
      expect(result.sanitizedData).not.toHaveProperty('password_hash')
      expect(result.sanitizedData).not.toHaveProperty('password_salt')
      expect(result.sanitizedData).toHaveProperty('id')
      expect(result.sanitizedData).toHaveProperty('username')
      expect(result.removedFields).toContain('password')
      expect(result.removedFields).toContain('password_hash')
      expect(result.removedFields).toContain('password_salt')
    })

    test('should remove session IDs from responses', () => {
      const testData = {
        authenticated: true,
        sessionId: 'abc123def456',
        session_id: 'xyz789uvw012',
        csrfToken: 'csrf_token_123',
        userData: { name: 'Test User' }
      }

      const result = sanitizer.sanitize(testData)
      
      expect(result.sanitizedData).not.toHaveProperty('sessionId')
      expect(result.sanitizedData).not.toHaveProperty('session_id')
      expect(result.sanitizedData).not.toHaveProperty('csrfToken')
      expect(result.sanitizedData).toHaveProperty('authenticated')
      expect(result.removedFields).toContain('sessionId')
      expect(result.removedFields).toContain('session_id')
      expect(result.removedFields).toContain('csrfToken')
    })

    test('should remove internal configuration data', () => {
      // Use more restrictive config to remove INTERNAL level fields
      const restrictiveSanitizer = new ResponseSanitizer({
        maxClassificationLevel: DataClassification.PUBLIC
      })

      const testData = {
        status: 'operational',
        capabilities: {
          maxResults: 1000,
          internalLimits: { rate: 100 },
          systemConfig: { debug: true }
        },
        internal_config: { secret: 'value' },
        debug_info: 'debug data'
      }

      const result = restrictiveSanitizer.sanitize(testData)

      expect(result.sanitizedData).not.toHaveProperty('internal_config')
      expect(result.sanitizedData).not.toHaveProperty('debug_info')
      expect(result.sanitizedData).toHaveProperty('status')
      expect(result.removedFields).toContain('internal_config')
      expect(result.removedFields).toContain('debug_info')
    })

    test('should mask PII data appropriately', () => {
      // Use less restrictive config to allow masking CONFIDENTIAL level fields
      const maskingSanitizer = new ResponseSanitizer({
        maxClassificationLevel: DataClassification.CONFIDENTIAL
      })

      const testData = {
        name: 'John Doe',
        email: 'john.doe@example.com',
        phone: '555-123-4567',
        address: '123 Main St'
      }

      const result = maskingSanitizer.sanitize(testData)

      // Email should be masked since it's CONFIDENTIAL level
      expect(result.sanitizedData.email).toMatch(/jo\*+@example\.com/)
      expect(result.maskedFields).toContain('email')

      // Phone should be masked since it's CONFIDENTIAL level
      expect(result.sanitizedData.phone).toMatch(/\*\*\*-\*\*\*-4567/)
      expect(result.maskedFields).toContain('phone')
    })

    test('should detect and redact PII in text content', () => {
      const testData = {
        description: 'Contact John at john.doe@example.com or call 555-123-4567',
        notes: 'SSN: 123-45-6789, Credit Card: 4111-1111-1111-1111'
      }

      const result = sanitizer.sanitize(testData)
      
      expect(result.sanitizedData.description).not.toContain('john.doe@example.com')
      expect(result.sanitizedData.description).not.toContain('555-123-4567')
      expect(result.sanitizedData.notes).not.toContain('123-45-6789')
      expect(result.sanitizedData.notes).not.toContain('4111-1111-1111-1111')
      expect(result.piiDetected.length).toBeGreaterThan(0)
    })
  })

  describe('Error Message Sanitization', () => {
    test('should sanitize error messages containing sensitive data', () => {
      const error = new Error('Database connection failed: password=secret123, token=abc123')
      const sanitized = sanitizeErrorMessage(error)
      
      expect(sanitized).not.toContain('secret123')
      expect(sanitized).not.toContain('abc123')
      expect(sanitized).toContain('[REDACTED]')
    })

    test('should remove stack traces in production', () => {
      const originalEnv = process.env.NODE_ENV
      process.env.NODE_ENV = 'production'
      
      const error = new Error('Error message\n    at function1\n    at function2')
      const sanitized = sanitizeErrorMessage(error)
      
      expect(sanitized).toBe('Error message')
      expect(sanitized).not.toContain('at function1')
      
      process.env.NODE_ENV = originalEnv
    })

    test('should provide generic error for sensitive internal errors in production', () => {
      const originalEnv = process.env.NODE_ENV
      process.env.NODE_ENV = 'production'
      
      const error = new Error('Database connection string invalid')
      const sanitized = sanitizeErrorMessage(error)
      
      expect(sanitized).toBe('An internal error occurred. Please try again later.')
      
      process.env.NODE_ENV = originalEnv
    })
  })

  describe('Session Data Sanitization', () => {
    test('should completely sanitize session data', () => {
      const sessionData = {
        id: 'session_123',
        sessionId: 'abc123',
        token: 'token_456',
        csrfToken: 'csrf_789',
        user: { name: 'Test User' },
        authenticated: true
      }

      const sanitized = sanitizeSessionData(sessionData)
      
      expect(sanitized).not.toHaveProperty('id')
      expect(sanitized).not.toHaveProperty('sessionId')
      expect(sanitized).not.toHaveProperty('token')
      expect(sanitized).not.toHaveProperty('csrfToken')
      expect(sanitized).toHaveProperty('authenticated')
    })
  })

  describe('Token and Key Detection', () => {
    test('should detect and remove hex token patterns', () => {
      const testData = {
        data: 'some data',
        suspiciousField: 'a1b2c3d4e5f6789012345678901234567890abcdef'
      }

      const result = sanitizer.sanitize(testData)
      
      expect(result.sanitizedData).not.toHaveProperty('suspiciousField')
      expect(result.removedFields).toContain('suspiciousField')
    })

    test('should detect and remove base64 token patterns', () => {
      const testData = {
        data: 'some data',
        suspiciousField: 'dGhpcyBpcyBhIGJhc2U2NCBlbmNvZGVkIHN0cmluZw=='
      }

      const result = sanitizer.sanitize(testData)
      
      expect(result.sanitizedData).not.toHaveProperty('suspiciousField')
      expect(result.removedFields).toContain('suspiciousField')
    })
  })

  describe('Nested Object Sanitization', () => {
    test('should sanitize nested objects recursively', () => {
      // Use restrictive config to remove INTERNAL and above level fields
      const restrictiveSanitizer = new ResponseSanitizer({
        maxClassificationLevel: DataClassification.PUBLIC
      })

      const testData = {
        user: {
          id: '123',
          password: 'secret',
          profile: {
            email: 'test@example.com',
            sessionId: 'session123',
            preferences: {
              theme: 'dark',
              api_key: 'key123'
            }
          }
        },
        metadata: {
          internal_config: { debug: true }
        }
      }

      const result = restrictiveSanitizer.sanitize(testData)

      expect(result.sanitizedData.user).not.toHaveProperty('password')
      expect(result.sanitizedData.user.profile).not.toHaveProperty('sessionId')
      expect(result.sanitizedData.user.profile.preferences).not.toHaveProperty('api_key')
      expect(result.sanitizedData.metadata).not.toHaveProperty('internal_config')
      expect(result.removedFields).toContain('user.password')
      expect(result.removedFields).toContain('user.profile.sessionId')
      expect(result.removedFields).toContain('user.profile.preferences.api_key')
      expect(result.removedFields).toContain('metadata.internal_config')
    })
  })

  describe('Array Sanitization', () => {
    test('should sanitize arrays of objects', () => {
      const testData = {
        users: [
          { id: '1', username: 'user1', password: 'secret1' },
          { id: '2', username: 'user2', password: 'secret2' }
        ]
      }

      const result = sanitizer.sanitize(testData)
      
      expect(result.sanitizedData.users[0]).not.toHaveProperty('password')
      expect(result.sanitizedData.users[1]).not.toHaveProperty('password')
      expect(result.sanitizedData.users[0]).toHaveProperty('username')
      expect(result.sanitizedData.users[1]).toHaveProperty('username')
      expect(result.removedFields).toContain('users[0].password')
      expect(result.removedFields).toContain('users[1].password')
    })
  })
})
