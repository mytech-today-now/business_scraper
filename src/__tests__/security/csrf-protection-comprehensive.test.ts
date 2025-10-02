/**
 * Comprehensive CSRF Protection Security Tests
 * Tests for CSRF token validation bypass vulnerability fixes
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals'
import { NextRequest, NextResponse } from 'next/server'
import { csrfProtectionService } from '@/lib/csrfProtection'
import { logger } from '@/utils/logger'

// Mock dependencies
jest.mock('@/utils/logger')
jest.mock('@/lib/security', () => ({
  getSession: jest.fn(),
  generateSecureToken: jest.fn()
}))

const mockGetSession = jest.mocked(require('@/lib/security').getSession)
const mockGenerateSecureToken = jest.mocked(require('@/lib/security').generateSecureToken)

describe('CSRF Protection Security Tests', () => {
  const validSessionId = 'test-session-123'
  const validOrigin = 'http://localhost:3000'

  beforeEach(() => {
    jest.clearAllMocks()
    
    // Mock valid session
    mockGetSession.mockReturnValue({
      isValid: true,
      userId: 'test-user',
      csrfToken: 'mock-csrf-token'
    })
    
    // Mock secure token generation
    mockGenerateSecureToken.mockReturnValue('secure-random-token-12345678901234567890')
  })

  afterEach(() => {
    jest.clearAllMocks()
  })

  describe('Timing Attack Prevention', () => {
    it('should prevent timing attacks in token comparison', async () => {
      // Debug: Check if the mock is working
      console.log('Mock return value:', mockGenerateSecureToken())

      const tokenInfo = csrfProtectionService.generateCSRFToken(validSessionId)
      console.log('Generated token info:', tokenInfo)
      
      // Create request with valid origin
      const request = new NextRequest('http://localhost:3000/api/test', {
        method: 'POST',
        headers: {
          'origin': validOrigin,
          'content-type': 'application/json'
        }
      })

      // Test with correct token
      const startTime1 = process.hrtime.bigint()
      const result1 = csrfProtectionService.validateCSRFToken(validSessionId, tokenInfo.token, request)
      const endTime1 = process.hrtime.bigint()
      const duration1 = Number(endTime1 - startTime1)

      // Test with incorrect token of same length
      const wrongToken = 'wrong-token-12345678901234567890'
      const startTime2 = process.hrtime.bigint()
      const result2 = csrfProtectionService.validateCSRFToken(validSessionId, wrongToken, request)
      const endTime2 = process.hrtime.bigint()
      const duration2 = Number(endTime2 - startTime2)

      expect(result1.isValid).toBe(true)
      expect(result2.isValid).toBe(false)
      
      // Timing difference should be minimal (within 10% variance)
      const timingDifference = Math.abs(duration1 - duration2)
      const averageTime = (duration1 + duration2) / 2
      const variance = timingDifference / averageTime
      
      expect(variance).toBeLessThan(0.1) // Less than 10% timing variance
    })

    it('should handle different token lengths securely', () => {
      const tokenInfo = csrfProtectionService.generateCSRFToken(validSessionId)

      const request = new NextRequest('http://localhost:3000/api/test', {
        method: 'POST',
        headers: { 'origin': validOrigin }
      })

      // Test with shorter token
      const shortToken = 'short'
      const result1 = csrfProtectionService.validateCSRFToken(validSessionId, shortToken, request)

      // Test with longer token
      const longToken = 'very-long-token-that-exceeds-normal-length-significantly'
      const result2 = csrfProtectionService.validateCSRFToken(validSessionId, longToken, request)

      expect(result1.isValid).toBe(false)
      expect(result2.isValid).toBe(false)
      expect(result1.securityViolation).toBe(true)
      expect(result2.securityViolation).toBe(true)
    })
  })

  describe('Origin Header Validation', () => {
    it('should validate origin headers correctly', () => {
      const tokenInfo = csrfProtectionService.generateCSRFToken(validSessionId)

      // Test with valid origin
      const validRequest = new NextRequest('http://localhost:3000/api/test', {
        method: 'POST',
        headers: { 'origin': 'http://localhost:3000' }
      })

      const result1 = csrfProtectionService.validateCSRFToken(validSessionId, tokenInfo.token, validRequest)
      expect(result1.isValid).toBe(true)
      expect(result1.originValidated).toBe(true)

      // Test with invalid origin
      const invalidRequest = new NextRequest('http://localhost:3000/api/test', {
        method: 'POST',
        headers: { 'origin': 'http://malicious-site.com' }
      })

      const result2 = csrfProtectionService.validateCSRFToken(validSessionId, tokenInfo.token, invalidRequest)
      expect(result2.isValid).toBe(false)
      expect(result2.securityViolation).toBe(true)
      expect(result2.originValidated).toBe(false)
    })

    it('should validate referer headers as fallback', () => {
      const tokenInfo = csrfProtectionService.generateCSRFToken(validSessionId)

      // Test with valid referer (no origin)
      const validRequest = new NextRequest('http://localhost:3000/api/test', {
        method: 'POST',
        headers: { 'referer': 'http://localhost:3000/some-page' }
      })

      const result1 = csrfProtectionService.validateCSRFToken(validSessionId, tokenInfo.token, validRequest)
      expect(result1.isValid).toBe(true)
      expect(result1.originValidated).toBe(true)

      // Test with invalid referer
      const invalidRequest = new NextRequest('http://localhost:3000/api/test', {
        method: 'POST',
        headers: { 'referer': 'http://malicious-site.com/attack' }
      })

      const result2 = csrfProtectionService.validateCSRFToken(validSessionId, tokenInfo.token, invalidRequest)
      expect(result2.isValid).toBe(false)
      expect(result2.securityViolation).toBe(true)
    })

    it('should reject requests without origin or referer for state-changing methods', () => {
      const tokenInfo = csrfProtectionService.generateCSRFToken(validSessionId)

      const request = new NextRequest('http://localhost:3000/api/test', {
        method: 'POST',
        headers: { 'content-type': 'application/json' }
        // No origin or referer headers
      })

      const result = csrfProtectionService.validateCSRFToken(validSessionId, tokenInfo.token, request)
      expect(result.isValid).toBe(false)
      expect(result.securityViolation).toBe(true)
      expect(result.error).toContain('Missing origin and referer headers')
    })
  })

  describe('Double-Submit Cookie Pattern', () => {
    it('should validate double-submit cookies correctly', () => {
      const tokenInfo = csrfProtectionService.generateCSRFToken(validSessionId)

      // Create request with matching cookie
      const request = new NextRequest('http://localhost:3000/api/test', {
        method: 'POST',
        headers: {
          'origin': validOrigin,
          'cookie': `csrf-token=${tokenInfo.token}`
        }
      })

      const result = csrfProtectionService.validateCSRFToken(validSessionId, tokenInfo.token, request)
      expect(result.isValid).toBe(true)
    })

    it('should reject mismatched double-submit cookies', () => {
      const tokenInfo = csrfProtectionService.generateCSRFToken(validSessionId)

      // Create request with mismatched cookie
      const request = new NextRequest('http://localhost:3000/api/test', {
        method: 'POST',
        headers: {
          'origin': validOrigin,
          'cookie': 'csrf-token=different-token-value'
        }
      })

      const result = csrfProtectionService.validateCSRFToken(validSessionId, tokenInfo.token, request)
      expect(result.isValid).toBe(false)
      expect(result.securityViolation).toBe(true)
    })
  })

  describe('Token Rotation', () => {
    it('should rotate tokens on authentication', () => {
      const originalToken = csrfProtectionService.generateCSRFToken(validSessionId)
      
      // Rotate token
      const newToken = csrfProtectionService.rotateTokenOnAuthentication(validSessionId)
      
      expect(newToken.token).not.toBe(originalToken.token)
      expect(newToken.issuedAt).toBeGreaterThan(originalToken.issuedAt)
      
      // Old token should be invalid
      const request = new NextRequest('http://localhost:3000/api/test', {
        method: 'POST',
        headers: { 'origin': validOrigin }
      })
      
      const oldTokenResult = csrfProtectionService.validateCSRFToken(validSessionId, originalToken.token, request)
      expect(oldTokenResult.isValid).toBe(false)
      
      // New token should be valid
      const newTokenResult = csrfProtectionService.validateCSRFToken(validSessionId, newToken.token, request)
      expect(newTokenResult.isValid).toBe(true)
    })

    it('should force token rotation for security events', () => {
      const originalToken = csrfProtectionService.generateCSRFToken(validSessionId)
      
      // Force rotation due to security event
      const newToken = csrfProtectionService.forceTokenRotation(validSessionId, 'Suspicious activity detected')
      
      expect(newToken.token).not.toBe(originalToken.token)
      expect(newToken.issuedAt).toBeGreaterThan(originalToken.issuedAt)
    })
  })

  describe('Token Expiration and Cleanup', () => {
    it('should handle expired tokens correctly', () => {
      // Create token with past expiry
      const expiredTokenInfo = {
        token: 'expired-token',
        expiresAt: Date.now() - 1000, // 1 second ago
        issuedAt: Date.now() - 3600000 // 1 hour ago
      }
      
      // Manually set expired token (for testing)
      csrfService['tokenStore'].set(validSessionId, expiredTokenInfo)
      
      const request = new NextRequest('http://localhost:3000/api/test', {
        method: 'POST',
        headers: { 'origin': validOrigin }
      })
      
      const result = csrfProtectionService.validateCSRFToken(validSessionId, expiredTokenInfo.token, request)
      expect(result.isValid).toBe(false)
      expect(result.needsRefresh).toBe(true)
      expect(result.error).toContain('expired')
    })

    it('should clean up expired tokens', () => {
      // Add some expired tokens
      const now = Date.now()
      csrfService['tokenStore'].set('expired-1', {
        token: 'token1',
        expiresAt: now - 1000,
        issuedAt: now - 3600000
      })
      csrfService['tokenStore'].set('expired-2', {
        token: 'token2',
        expiresAt: now - 2000,
        issuedAt: now - 3600000
      })
      csrfService['tokenStore'].set('valid-1', {
        token: 'token3',
        expiresAt: now + 3600000,
        issuedAt: now
      })

      const initialSize = csrfService['tokenStore'].size
      expect(initialSize).toBe(3)

      // Run cleanup
      csrfProtectionService.cleanupExpiredTokens()

      // Only valid token should remain
      expect(csrfService['tokenStore'].size).toBe(1)
      expect(csrfService['tokenStore'].has('valid-1')).toBe(true)
    })
  })

  describe('Security Headers and Cookies', () => {
    it('should set secure cookie attributes correctly', () => {
      const tokenInfo = csrfProtectionService.generateCSRFToken(validSessionId)
      const response = new NextResponse()
      
      // Set NODE_ENV to production for testing
      const originalEnv = process.env.NODE_ENV
      process.env.NODE_ENV = 'production'
      
      const updatedResponse = csrfProtectionService.addCSRFHeaders(response, validSessionId)
      
      // Check if cookie was set with secure attributes
      const setCookieHeader = updatedResponse.headers.get('set-cookie')
      expect(setCookieHeader).toContain('csrf-token=')
      expect(setCookieHeader).toContain('Secure')
      expect(setCookieHeader).toContain('SameSite=Strict')
      expect(setCookieHeader).toContain('Path=/')
      
      // Check security headers
      expect(updatedResponse.headers.get('X-Content-Type-Options')).toBe('nosniff')
      expect(updatedResponse.headers.get('X-Frame-Options')).toBe('DENY')
      expect(updatedResponse.headers.get('Referrer-Policy')).toBe('strict-origin-when-cross-origin')
      
      // Restore environment
      process.env.NODE_ENV = originalEnv
    })
  })

  describe('Input Validation', () => {
    it('should validate input parameters', () => {
      // Test with invalid session ID
      const result1 = csrfProtectionService.validateCSRFToken('', 'some-token')
      expect(result1.isValid).toBe(false)
      expect(result1.securityViolation).toBe(true)

      // Test with invalid token
      const result2 = csrfProtectionService.validateCSRFToken(validSessionId, '')
      expect(result2.isValid).toBe(false)
      expect(result2.securityViolation).toBe(true)

      // Test with non-string inputs
      const result3 = csrfProtectionService.validateCSRFToken(null as any, 'token')
      expect(result3.isValid).toBe(false)
      expect(result3.securityViolation).toBe(true)
    })

    it('should handle malformed requests gracefully', () => {
      const tokenInfo = csrfProtectionService.generateCSRFToken(validSessionId)
      
      // Test with malformed origin header
      const request = new NextRequest('http://localhost:3000/api/test', {
        method: 'POST',
        headers: { 'origin': 'not-a-valid-url' }
      })

      const result = csrfProtectionService.validateCSRFToken(validSessionId, tokenInfo.token, request)
      expect(result.isValid).toBe(false)
      expect(result.securityViolation).toBe(true)
    })
  })
})
