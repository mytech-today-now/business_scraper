/**
 * CSRF Attack Scenarios Tests
 * Tests various CSRF attack vectors and ensures they are properly blocked
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals'
import { NextRequest, NextResponse } from 'next/server'
import { validateCSRFMiddleware, csrfProtectionService } from '@/lib/csrfProtection'
import { logger } from '@/utils/logger'

// Mock dependencies
jest.mock('@/utils/logger')
jest.mock('@/lib/security', () => ({
  getSession: jest.fn(),
  generateSecureToken: jest.fn()
}))

const mockGetSession = jest.mocked(require('@/lib/security').getSession)
const mockGenerateSecureToken = jest.mocked(require('@/lib/security').generateSecureToken)

describe('CSRF Attack Scenarios', () => {
  const validSessionId = 'test-session-123'
  const attackerOrigin = 'http://malicious-site.com'
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

  describe('Classic CSRF Attacks', () => {
    it('should block cross-origin form submissions without CSRF token', () => {
      const request = new NextRequest('http://localhost:3000/api/transfer-money', {
        method: 'POST',
        headers: {
          'origin': attackerOrigin,
          'content-type': 'application/x-www-form-urlencoded',
          'cookie': `session-id=${validSessionId}`
        },
        body: 'amount=1000&to=attacker-account'
      })

      const response = validateCSRFMiddleware(request)
      expect(response).not.toBeNull()
      expect(response?.status).toBe(403)
    })

    it('should block cross-origin AJAX requests without proper CSRF token', () => {
      const request = new NextRequest('http://localhost:3000/api/change-password', {
        method: 'POST',
        headers: {
          'origin': attackerOrigin,
          'content-type': 'application/json',
          'cookie': `session-id=${validSessionId}`
        },
        body: JSON.stringify({ newPassword: 'hacked123' })
      })

      const response = validateCSRFMiddleware(request)
      expect(response).not.toBeNull()
      expect(response?.status).toBe(403)
    })

    it('should block requests with stolen CSRF tokens from different origins', () => {
      // Generate a valid token
      const tokenInfo = csrfProtectionService.generateCSRFToken(validSessionId)
      
      // Attacker tries to use stolen token from different origin
      const request = new NextRequest('http://localhost:3000/api/delete-account', {
        method: 'DELETE',
        headers: {
          'origin': attackerOrigin,
          'x-csrf-token': tokenInfo.token,
          'cookie': `session-id=${validSessionId}; csrf-token=${tokenInfo.token}`
        }
      })

      const response = validateCSRFMiddleware(request)
      expect(response).not.toBeNull()
      expect(response?.status).toBe(403)
    })
  })

  describe('Advanced CSRF Attack Vectors', () => {
    it('should block subdomain attacks', () => {
      const tokenInfo = csrfProtectionService.generateCSRFToken(validSessionId)
      
      // Attack from subdomain
      const request = new NextRequest('http://localhost:3000/api/admin/delete-user', {
        method: 'DELETE',
        headers: {
          'origin': 'http://evil.localhost:3000',
          'x-csrf-token': tokenInfo.token,
          'cookie': `session-id=${validSessionId}`
        }
      })

      const response = validateCSRFMiddleware(request)
      expect(response).not.toBeNull()
      expect(response?.status).toBe(403)
    })

    it('should block null origin attacks', () => {
      const tokenInfo = csrfProtectionService.generateCSRFToken(validSessionId)
      
      // Attack with null origin (file:// or data: URLs)
      const request = new NextRequest('http://localhost:3000/api/sensitive-action', {
        method: 'POST',
        headers: {
          'origin': 'null',
          'x-csrf-token': tokenInfo.token,
          'cookie': `session-id=${validSessionId}`
        }
      })

      const response = validateCSRFMiddleware(request)
      expect(response).not.toBeNull()
      expect(response?.status).toBe(403)
    })

    it('should block referer spoofing attacks', () => {
      const tokenInfo = csrfProtectionService.generateCSRFToken(validSessionId)
      
      // Attack with spoofed referer (no origin header)
      const request = new NextRequest('http://localhost:3000/api/transfer-funds', {
        method: 'POST',
        headers: {
          'referer': 'http://localhost:3000/legitimate-page',
          'x-csrf-token': 'fake-token',
          'cookie': `session-id=${validSessionId}`
        }
      })

      const response = validateCSRFMiddleware(request)
      expect(response).not.toBeNull()
      expect(response?.status).toBe(403)
    })
  })

  describe('Token Manipulation Attacks', () => {
    it('should block requests with modified tokens', () => {
      const tokenInfo = csrfProtectionService.generateCSRFToken(validSessionId)
      
      // Modify the token slightly
      const modifiedToken = tokenInfo.token.slice(0, -1) + 'X'
      
      const request = new NextRequest('http://localhost:3000/api/update-profile', {
        method: 'PUT',
        headers: {
          'origin': validOrigin,
          'x-csrf-token': modifiedToken,
          'cookie': `session-id=${validSessionId}`
        }
      })

      const response = validateCSRFMiddleware(request)
      expect(response).not.toBeNull()
      expect(response?.status).toBe(403)
    })

    it('should block requests with truncated tokens', () => {
      const tokenInfo = csrfProtectionService.generateCSRFToken(validSessionId)
      
      // Truncate the token
      const truncatedToken = tokenInfo.token.slice(0, 10)
      
      const request = new NextRequest('http://localhost:3000/api/admin/settings', {
        method: 'PATCH',
        headers: {
          'origin': validOrigin,
          'x-csrf-token': truncatedToken,
          'cookie': `session-id=${validSessionId}`
        }
      })

      const response = validateCSRFMiddleware(request)
      expect(response).not.toBeNull()
      expect(response?.status).toBe(403)
    })

    it('should block requests with padded tokens', () => {
      const tokenInfo = csrfProtectionService.generateCSRFToken(validSessionId)
      
      // Pad the token with extra characters
      const paddedToken = tokenInfo.token + '000'
      
      const request = new NextRequest('http://localhost:3000/api/payment/process', {
        method: 'POST',
        headers: {
          'origin': validOrigin,
          'x-csrf-token': paddedToken,
          'cookie': `session-id=${validSessionId}`
        }
      })

      const response = validateCSRFMiddleware(request)
      expect(response).not.toBeNull()
      expect(response?.status).toBe(403)
    })
  })

  describe('Session Fixation and Hijacking', () => {
    it('should block requests with invalid session IDs', () => {
      const tokenInfo = csrfProtectionService.generateCSRFToken(validSessionId)
      
      // Use different session ID
      const request = new NextRequest('http://localhost:3000/api/sensitive-data', {
        method: 'GET',
        headers: {
          'origin': validOrigin,
          'x-csrf-token': tokenInfo.token,
          'cookie': 'session-id=different-session-id'
        }
      })

      const response = validateCSRFMiddleware(request)
      expect(response).not.toBeNull()
      expect(response?.status).toBe(403)
    })

    it('should handle session hijacking attempts', () => {
      // Mock invalid session
      mockGetSession.mockReturnValue(null)
      
      const request = new NextRequest('http://localhost:3000/api/user/data', {
        method: 'POST',
        headers: {
          'origin': validOrigin,
          'x-csrf-token': 'any-token',
          'cookie': 'session-id=hijacked-session'
        }
      })

      const response = validateCSRFMiddleware(request)
      expect(response).not.toBeNull()
      expect(response?.status).toBe(401)
    })
  })

  describe('Timing Attack Scenarios', () => {
    it('should prevent timing-based token discovery', async () => {
      const tokenInfo = csrfProtectionService.generateCSRFToken(validSessionId)
      const correctToken = tokenInfo.token
      
      // Test multiple incorrect tokens of same length
      const incorrectTokens = [
        'a'.repeat(correctToken.length),
        'b'.repeat(correctToken.length),
        'c'.repeat(correctToken.length),
        '1'.repeat(correctToken.length),
        '0'.repeat(correctToken.length)
      ]

      const timings: number[] = []

      for (const token of incorrectTokens) {
        const request = new NextRequest('http://localhost:3000/api/test', {
          method: 'POST',
          headers: {
            'origin': validOrigin,
            'x-csrf-token': token,
            'cookie': `session-id=${validSessionId}`
          }
        })

        const start = process.hrtime.bigint()
        validateCSRFMiddleware(request)
        const end = process.hrtime.bigint()
        
        timings.push(Number(end - start))
      }

      // Calculate timing variance
      const avgTiming = timings.reduce((a, b) => a + b, 0) / timings.length
      const variance = timings.reduce((acc, timing) => {
        return acc + Math.pow(timing - avgTiming, 2)
      }, 0) / timings.length

      const standardDeviation = Math.sqrt(variance)
      const coefficientOfVariation = standardDeviation / avgTiming

      // Timing should be consistent (low coefficient of variation)
      expect(coefficientOfVariation).toBeLessThan(0.1) // Less than 10% variation
    })
  })

  describe('Double-Submit Cookie Bypass Attempts', () => {
    it('should block cookie injection attacks', () => {
      const tokenInfo = csrfProtectionService.generateCSRFToken(validSessionId)
      
      // Attacker tries to inject their own CSRF cookie
      const request = new NextRequest('http://localhost:3000/api/admin/promote', {
        method: 'POST',
        headers: {
          'origin': attackerOrigin,
          'x-csrf-token': 'attacker-token',
          'cookie': `session-id=${validSessionId}; csrf-token=attacker-token`
        }
      })

      const response = validateCSRFMiddleware(request)
      expect(response).not.toBeNull()
      expect(response?.status).toBe(403)
    })

    it('should block mismatched header and cookie tokens', () => {
      const tokenInfo = csrfProtectionService.generateCSRFToken(validSessionId)
      
      const request = new NextRequest('http://localhost:3000/api/change-email', {
        method: 'PUT',
        headers: {
          'origin': validOrigin,
          'x-csrf-token': tokenInfo.token,
          'cookie': `session-id=${validSessionId}; csrf-token=different-token`
        }
      })

      const response = validateCSRFMiddleware(request)
      expect(response).not.toBeNull()
      expect(response?.status).toBe(403)
    })
  })

  describe('Edge Cases and Error Conditions', () => {
    it('should handle malformed requests gracefully', () => {
      const request = new NextRequest('http://localhost:3000/api/test', {
        method: 'POST',
        headers: {
          'origin': 'invalid-url-format',
          'x-csrf-token': 'some-token',
          'cookie': `session-id=${validSessionId}`
        }
      })

      const response = validateCSRFMiddleware(request)
      expect(response).not.toBeNull()
      expect(response?.status).toBe(403)
    })

    it('should handle extremely long tokens', () => {
      const longToken = 'a'.repeat(10000) // 10KB token
      
      const request = new NextRequest('http://localhost:3000/api/test', {
        method: 'POST',
        headers: {
          'origin': validOrigin,
          'x-csrf-token': longToken,
          'cookie': `session-id=${validSessionId}`
        }
      })

      const response = validateCSRFMiddleware(request)
      expect(response).not.toBeNull()
      expect(response?.status).toBe(403)
    })

    it('should handle special characters in tokens', () => {
      const specialToken = '../../etc/passwd'
      
      const request = new NextRequest('http://localhost:3000/api/test', {
        method: 'POST',
        headers: {
          'origin': validOrigin,
          'x-csrf-token': specialToken,
          'cookie': `session-id=${validSessionId}`
        }
      })

      const response = validateCSRFMiddleware(request)
      expect(response).not.toBeNull()
      expect(response?.status).toBe(403)
    })
  })

  describe('Legitimate Requests', () => {
    it('should allow valid requests with proper CSRF protection', () => {
      const tokenInfo = csrfProtectionService.generateCSRFToken(validSessionId)
      
      const request = new NextRequest('http://localhost:3000/api/user/update', {
        method: 'PUT',
        headers: {
          'origin': validOrigin,
          'x-csrf-token': tokenInfo.token,
          'cookie': `session-id=${validSessionId}; csrf-token=${tokenInfo.token}`
        }
      })

      const response = validateCSRFMiddleware(request)
      expect(response).toBeNull() // No blocking response means request is allowed
    })

    it('should allow GET requests without CSRF tokens', () => {
      const request = new NextRequest('http://localhost:3000/api/user/profile', {
        method: 'GET',
        headers: {
          'origin': validOrigin,
          'cookie': `session-id=${validSessionId}`
        }
      })

      const response = validateCSRFMiddleware(request)
      expect(response).toBeNull() // GET requests don't need CSRF protection
    })
  })
})
