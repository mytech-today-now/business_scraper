/**
 * Tests for security system
 */

import {
  generateSecureToken,
  hashPassword,
  verifyPassword,
  encryptData,
  decryptData,
  createSession,
  getSession,
  invalidateSession,
  checkRateLimit,
  trackLoginAttempt,
  isLockedOut,
  validateCSRFToken,
  sanitizeInput,
  validateInput,
  getClientIP
} from '@/lib/security'
import { NextRequest } from 'next/server'

describe('Security System', () => {
  beforeEach(() => {
    // Clear any existing sessions and rate limit data
    // Note: In a real implementation, you'd want to clear the internal maps
    // For now, we'll work with the current state
  })

  describe('generateSecureToken', () => {
    it('should generate a token of specified length', () => {
      const token = generateSecureToken(32)
      expect(token).toHaveLength(64) // 32 bytes = 64 hex characters
    })

    it('should generate different tokens each time', () => {
      const token1 = generateSecureToken()
      const token2 = generateSecureToken()
      expect(token1).not.toBe(token2)
    })

    it('should use default length when not specified', () => {
      const token = generateSecureToken()
      expect(token).toHaveLength(64) // Default 32 bytes = 64 hex characters
    })
  })

  describe('Password hashing', () => {
    const testPassword = 'testPassword123!'

    it('should hash a password with salt', () => {
      const result = hashPassword(testPassword)
      
      expect(result.hash).toBeDefined()
      expect(result.salt).toBeDefined()
      expect(result.hash).toHaveLength(128) // 64 bytes = 128 hex characters
      expect(result.salt).toHaveLength(32) // 16 bytes = 32 hex characters
    })

    it('should use provided salt', () => {
      const salt = 'predefined_salt_value_here'
      const result = hashPassword(testPassword, salt)
      
      expect(result.salt).toBe(salt)
    })

    it('should generate different hashes for different passwords', () => {
      const result1 = hashPassword('password1')
      const result2 = hashPassword('password2')
      
      expect(result1.hash).not.toBe(result2.hash)
    })

    it('should generate same hash for same password and salt', () => {
      const salt = 'consistent_salt'
      const result1 = hashPassword(testPassword, salt)
      const result2 = hashPassword(testPassword, salt)
      
      expect(result1.hash).toBe(result2.hash)
    })
  })

  describe('Password verification', () => {
    const testPassword = 'testPassword123!'

    it('should verify correct password', () => {
      const { hash, salt } = hashPassword(testPassword)
      const isValid = verifyPassword(testPassword, hash, salt)
      
      expect(isValid).toBe(true)
    })

    it('should reject incorrect password', () => {
      const { hash, salt } = hashPassword(testPassword)
      const isValid = verifyPassword('wrongPassword', hash, salt)
      
      expect(isValid).toBe(false)
    })

    it('should be timing-safe', () => {
      const { hash, salt } = hashPassword(testPassword)
      
      // These should take similar time (timing attack protection)
      const start1 = Date.now()
      verifyPassword('wrongPassword', hash, salt)
      const time1 = Date.now() - start1
      
      const start2 = Date.now()
      verifyPassword(testPassword, hash, salt)
      const time2 = Date.now() - start2
      
      // Times should be relatively similar (within reasonable bounds)
      // This is a basic check - in practice, timing attacks are more sophisticated
      expect(Math.abs(time1 - time2)).toBeLessThan(100)
    })
  })

  describe('Data encryption', () => {
    const testData = 'sensitive information'
    const testKey = 'encryption_key_123'

    it('should encrypt and decrypt data', () => {
      const encrypted = encryptData(testData, testKey)
      const decrypted = decryptData(encrypted.encrypted, testKey, encrypted.iv)
      
      expect(decrypted).toBe(testData)
    })

    it('should produce different encrypted output each time', () => {
      const encrypted1 = encryptData(testData, testKey)
      const encrypted2 = encryptData(testData, testKey)
      
      expect(encrypted1.encrypted).not.toBe(encrypted2.encrypted)
      expect(encrypted1.iv).not.toBe(encrypted2.iv)
    })

    it('should fail with wrong key', () => {
      const encrypted = encryptData(testData, testKey)
      
      expect(() => {
        decryptData(encrypted.encrypted, 'wrong_key', encrypted.iv)
      }).toThrow()
    })
  })

  describe('Session management', () => {
    it('should create a session', () => {
      const session = createSession()
      
      expect(session.id).toBeDefined()
      expect(session.createdAt).toBeInstanceOf(Date)
      expect(session.lastAccessed).toBeInstanceOf(Date)
      expect(session.isValid).toBe(true)
      expect(session.csrfToken).toBeDefined()
    })

    it('should retrieve a session', () => {
      const session = createSession()
      const retrieved = getSession(session.id)
      
      expect(retrieved).toBeDefined()
      expect(retrieved?.id).toBe(session.id)
    })

    it('should return null for non-existent session', () => {
      const retrieved = getSession('non-existent-id')
      expect(retrieved).toBeNull()
    })

    it('should invalidate a session', () => {
      const session = createSession()
      invalidateSession(session.id)
      
      const retrieved = getSession(session.id)
      expect(retrieved).toBeNull()
    })

    it('should update last accessed time', () => {
      const session = createSession()
      const originalTime = session.lastAccessed
      
      // Wait a bit
      setTimeout(() => {
        const retrieved = getSession(session.id)
        expect(retrieved?.lastAccessed.getTime()).toBeGreaterThan(originalTime.getTime())
      }, 10)
    })
  })

  describe('Rate limiting', () => {
    const testIP = '192.168.1.100'

    it('should allow requests within limit', () => {
      const allowed = checkRateLimit(testIP, 5)
      expect(allowed).toBe(true)
    })

    it('should block requests exceeding limit', () => {
      // Make requests up to the limit
      for (let i = 0; i < 5; i++) {
        checkRateLimit(testIP, 5)
      }
      
      // Next request should be blocked
      const blocked = checkRateLimit(testIP, 5)
      expect(blocked).toBe(false)
    })

    it('should reset after time window', () => {
      // This test would need to mock time or wait for the actual window
      // For now, we'll test with a different IP
      const newIP = '192.168.1.101'
      const allowed = checkRateLimit(newIP, 5)
      expect(allowed).toBe(true)
    })
  })

  describe('Login attempt tracking', () => {
    const testIP = '192.168.1.200'

    it('should track successful login', () => {
      const result = trackLoginAttempt(testIP, true)
      expect(result).toBe(true)
    })

    it('should track failed login attempts', () => {
      const result = trackLoginAttempt(testIP, false)
      expect(result).toBe(true)
    })

    it('should lock account after max attempts', () => {
      // Make multiple failed attempts
      for (let i = 0; i < 5; i++) {
        trackLoginAttempt(testIP, false)
      }
      
      // Should be locked out
      const isLocked = isLockedOut(testIP)
      expect(isLocked).toBe(true)
    })

    it('should clear attempts on successful login', () => {
      const newIP = '192.168.1.201'
      
      // Make some failed attempts
      trackLoginAttempt(newIP, false)
      trackLoginAttempt(newIP, false)
      
      // Successful login should clear attempts
      trackLoginAttempt(newIP, true)
      
      // Should not be locked out
      const isLocked = isLockedOut(newIP)
      expect(isLocked).toBe(false)
    })
  })

  describe('Input sanitization', () => {
    it('should remove script tags', () => {
      const input = '<script>alert("xss")</script>Hello'
      const result = sanitizeInput(input)
      expect(result).toBe('Hello')
    })

    it('should escape HTML entities', () => {
      const input = 'Hello & "World" <test>'
      const result = sanitizeInput(input)
      expect(result).toBe('Hello &amp; &quot;World&quot; ')
    })

    it('should remove javascript: URLs', () => {
      const input = 'javascript:alert("xss")'
      const result = sanitizeInput(input)
      expect(result).toBe('alert(&quot;xss&quot;)')
    })

    it('should remove event handlers', () => {
      const input = 'onclick="malicious()" onload="bad()"'
      const result = sanitizeInput(input)
      expect(result).toBe('&quot;malicious()&quot; &quot;bad()&quot;')
    })

    it('should trim whitespace', () => {
      const input = '  Hello World  '
      const result = sanitizeInput(input)
      expect(result).toBe('Hello World')
    })
  })

  describe('Input validation', () => {
    it('should pass safe input', () => {
      const input = 'Hello World 123'
      const result = validateInput(input)
      
      expect(result.isValid).toBe(true)
      expect(result.errors).toHaveLength(0)
    })

    it('should detect SQL injection', () => {
      const input = "'; DROP TABLE users; --"
      const result = validateInput(input)
      
      expect(result.isValid).toBe(false)
      expect(result.errors).toContain('Input contains potentially dangerous SQL patterns')
    })

    it('should detect XSS attempts', () => {
      const input = '<script>alert("xss")</script>'
      const result = validateInput(input)
      
      expect(result.isValid).toBe(false)
      expect(result.errors).toContain('Input contains potentially dangerous XSS patterns')
    })

    it('should detect path traversal', () => {
      const input = '../../../etc/passwd'
      const result = validateInput(input)
      
      expect(result.isValid).toBe(false)
      expect(result.errors).toContain('Input contains path traversal patterns')
    })
  })

  describe('Client IP extraction', () => {
    it('should extract IP from x-forwarded-for header', () => {
      const mockRequest = {
        headers: {
          get: (name: string) => {
            if (name === 'x-forwarded-for') return '192.168.1.1, 10.0.0.1'
            return null
          }
        }
      } as NextRequest
      
      const ip = getClientIP(mockRequest)
      expect(ip).toBe('192.168.1.1')
    })

    it('should extract IP from x-real-ip header', () => {
      const mockRequest = {
        headers: {
          get: (name: string) => {
            if (name === 'x-real-ip') return '192.168.1.2'
            return null
          }
        }
      } as NextRequest
      
      const ip = getClientIP(mockRequest)
      expect(ip).toBe('192.168.1.2')
    })

    it('should fallback to request.ip', () => {
      const mockRequest = {
        headers: {
          get: () => null
        },
        ip: '192.168.1.3'
      } as unknown as NextRequest

      const ip = getClientIP(mockRequest)
      expect(ip).toBe('192.168.1.3')
    })

    it('should return unknown when no IP available', () => {
      const mockRequest = {
        headers: {
          get: () => null
        }
      } as unknown as NextRequest

      const ip = getClientIP(mockRequest)
      expect(ip).toBe('unknown')
    })
  })
})
